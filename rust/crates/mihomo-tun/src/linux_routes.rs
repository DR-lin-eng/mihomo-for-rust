use super::*;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// This protocol identifies our policy rules and routes. Priority and table
// collisions are rejected before any global routing change is made.
const OWNED_PROTOCOL: &str = "242";
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    namespace: u64,
    table: i32,
    device: String,
    undo: Vec<Vec<String>>,
}

/// A lock and write-ahead journal for the routes installed by one TUN.
/// SIGKILL releases the lock but leaves enough information for its successor
/// to recover. Normal drop rolls back only protocol-tagged owned objects.
pub struct LinuxTunRouteGuard {
    _lock: File,
    path: std::path::PathBuf,
    journal: Journal,
}

fn output(args: &[&str]) -> io::Result<serde_json::Value> {
    for binary in ["/sbin/ip", "/usr/sbin/ip", "ip"] {
        match Command::new(binary).args(args).output() {
            Ok(result) if result.status.success() => {
                return serde_json::from_slice(&result.stdout).map_err(io::Error::other);
            }
            Ok(result) => {
                let error = String::from_utf8_lossy(&result.stderr);
                if error.contains("FIB table does not exist") {
                    return Ok(serde_json::json!([]));
                }
                return Err(io::Error::other(error.into_owned()));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "ip utility unavailable",
    ))
}

fn command_kind(command: &[String]) -> Option<(usize, &str)> {
    let offset = usize::from(command.first().is_some_and(|value| value == "-6"));
    match command.get(offset).map(String::as_str) {
        Some("route") => Some((offset, "route")),
        Some("rule") => Some((offset, "rule")),
        _ => None,
    }
}

impl LinuxTunRouteGuard {
    pub(super) fn acquire(spec: &TunRuntimeSpec, device: &str) -> io::Result<Self> {
        let namespace = std::fs::metadata("/proc/self/ns/net")?.ino();
        let table = iproute2_table_index(spec);
        let path = format!("/tmp/mihomo-tun-routes-{namespace}-{table}.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe TUN route journal",
            ));
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("TUN routing table {table} is already owned by another active core"),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let path =
            std::path::PathBuf::from(format!("/tmp/mihomo-tun-routes-{namespace}-{table}.json"));
        let mut bytes = Vec::new();
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(mut file) => {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o077 != 0
                    || metadata.len() > MAX_JOURNAL_BYTES
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsafe TUN route ownership journal",
                    ));
                }
                file.read_to_end(&mut bytes)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let journal = if bytes.is_empty() {
            Journal {
                version: 1,
                namespace,
                table,
                device: device.into(),
                undo: Vec::new(),
            }
        } else {
            let journal: Journal = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if journal.version != 1
                || journal.namespace != namespace
                || journal.table != table
                || journal.undo.iter().any(|command| {
                    let Some((offset, kind)) = command_kind(command) else {
                        return true;
                    };
                    command.get(offset + 1).map(String::as_str) != Some("del")
                        || !command
                            .windows(2)
                            .any(|pair| pair[0] == "protocol" && pair[1] == OWNED_PROTOCOL)
                        || !matches!(kind, "route" | "rule")
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid TUN route ownership journal",
                ));
            }
            journal
        };
        let mut owner = Self {
            _lock: lock,
            path,
            journal,
        };
        owner.cleanup()?;
        owner.journal.device = device.into();
        owner.reject_foreign_conflicts(spec, device)?;
        Ok(owner)
    }

    fn save(&mut self) -> io::Result<()> {
        let bytes = serde_json::to_vec(&self.journal).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN routing configuration is too large",
            ));
        }
        // Replace the journal atomically. Overwriting a shorter JSON document
        // in place could leave an unreadable tail if SIGKILL arrives before
        // truncation, precisely when recovery is needed.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = self
            .path
            .with_extension(format!("tmp-{}-{unique}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_data()?;
            std::fs::rename(&temporary, &self.path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn reject_foreign_conflicts(&self, spec: &TunRuntimeSpec, device: &str) -> io::Result<()> {
        let planned = linux_tun_auto_route_commands(spec, device);
        for ipv6 in [false, true] {
            let commands: Vec<_> = planned
                .iter()
                .filter(|command| command.first().is_some_and(|value| value == "-6") == ipv6)
                .collect();
            if commands.is_empty() {
                continue;
            }
            let priorities: BTreeSet<_> = commands
                .iter()
                .filter_map(|command| {
                    command
                        .windows(2)
                        .find(|pair| pair[0] == "priority")
                        .and_then(|pair| pair[1].parse::<u64>().ok())
                })
                .collect();
            let args: Vec<_> = if ipv6 {
                vec!["-6", "-j", "rule", "show"]
            } else {
                vec!["-j", "rule", "show"]
            };
            let existing = output(&args)?;
            if existing.as_array().is_some_and(|rules| {
                rules.iter().any(|rule| {
                    rule.get("priority")
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|priority| priorities.contains(&priority))
                })
            }) {
                return Err(io::Error::new(io::ErrorKind::AddrInUse,
                    "TUN rule priorities conflict with existing unowned rules; choose a different iproute2-rule-index"));
            }
            let table = self.journal.table.to_string();
            let args = if ipv6 {
                vec!["-6", "-j", "route", "show", "table", table.as_str()]
            } else {
                vec!["-j", "route", "show", "table", table.as_str()]
            };
            let existing = output(&args)?;
            for command in commands {
                if let Some((offset, "route")) = command_kind(command) {
                    let prefix = &command[offset + 2];
                    let destination = if prefix == "0.0.0.0/0" || prefix == "::/0" {
                        "default"
                    } else {
                        prefix
                    };
                    if existing.as_array().is_some_and(|routes| {
                        routes.iter().any(|route| {
                            route.get("dst").and_then(serde_json::Value::as_str)
                                == Some(destination)
                        })
                    }) {
                        return Err(io::Error::new(io::ErrorKind::AddrInUse,
                            format!("TUN route {prefix} conflicts with an unowned route in table {table}")));
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn configure(&mut self, mut command: Vec<String>) -> io::Result<()> {
        let Some((offset, _)) = command_kind(&command) else {
            return self.run_owned_command(&command);
        };
        // `add` cannot overwrite a route owned by another application.
        command[offset + 1] = "add".into();
        command.extend(["protocol".into(), OWNED_PROTOCOL.into()]);
        let mut undo = command.clone();
        undo[offset + 1] = "del".into();
        self.journal.undo.push(undo);
        self.save()?;
        self.run_owned_command(&command)
    }

    pub(super) fn set_device(&mut self, device: &str) {
        self.journal.device = device.into();
    }

    fn run_owned_command(&self, args: &[String]) -> io::Result<()> {
        for binary in ["/sbin/ip", "/usr/sbin/ip", "ip"] {
            let mut command = Command::new(binary);
            command.args(args);
            let lock_fd = self._lock.as_raw_fd();
            // Keep the lease in the ip child too. Otherwise SIGKILL between
            // spawn and netlink completion could let a late child modify
            // routing after the successor has already replayed the journal.
            // dup is async-signal-safe; only this child inherits the duplicate.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup(lock_fd) < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            match command.output() {
                Ok(result) if result.status.success() => return Ok(()),
                Ok(result) => {
                    return Err(io::Error::other(format!(
                        "TUN owned ip command {}: {}",
                        args.join(" "),
                        String::from_utf8_lossy(&result.stderr).trim()
                    )))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ip utility unavailable",
        ))
    }

    fn cleanup(&mut self) -> io::Result<()> {
        while let Some(command) = self.journal.undo.last() {
            let cleanup = if command_kind(command).is_some_and(|(_, kind)| kind == "rule") {
                // Priorities were exclusively reserved before installation.
                // Delete one owned rule per journal entry, even when a nop
                // rule shares a priority with a long include/exclude list.
                // Detached iif names after SIGKILL need no name resolution.
                let priority = command
                    .windows(2)
                    .find(|pair| pair[0] == "priority")
                    .ok_or_else(|| io::Error::other("owned rule has no priority"))?;
                let mut cleanup = if command[0] == "-6" {
                    vec!["-6".into()]
                } else {
                    Vec::new()
                };
                cleanup.extend([
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    priority[1].clone(),
                    "protocol".into(),
                    OWNED_PROTOCOL.into(),
                ]);
                cleanup
            } else {
                command.clone()
            };
            if let Err(error) = self.run_owned_command(&cleanup) {
                let message = error.to_string();
                if !message.contains("Cannot find device")
                    && !message.contains("No such process")
                    && !message.contains("No such file or directory")
                {
                    return Err(error);
                }
            }
            self.journal.undo.pop();
            self.save()?;
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for LinuxTunRouteGuard {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            mihomo_core::push_log(
                mihomo_core::LogLevel::Warn,
                format!("TUN owned route cleanup: {error}"),
            );
        }
    }
}
