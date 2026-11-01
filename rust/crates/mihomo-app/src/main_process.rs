use std::path::Path;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use mihomo_core::{push_log, LogLevel};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunLoopExit {
    Shutdown,
    Restart,
}

pub(crate) struct PostDownGuard {
    command: Option<String>,
}

impl PostDownGuard {
    pub(crate) fn new(command: Option<String>) -> Self {
        Self { command }
    }
}

impl Drop for PostDownGuard {
    fn drop(&mut self) {
        if let Some(command) = self.command.take() {
            if let Err(err) = exec_shell(&command) {
                let message = format!("post-down script error: {err}");
                eprintln!("{message}");
                push_log(LogLevel::Error, message);
            }
        }
    }
}

pub(crate) fn exec_shell(command: &str) -> Result<(), String> {
    #[cfg(unix)]
    let output = ProcessCommand::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|err| err.to_string())?;

    #[cfg(windows)]
    let output = ProcessCommand::new("cmd")
        .arg("/C")
        .arg(command)
        .output()
        .map_err(|err| err.to_string())?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    if detail.is_empty() {
        Err(format!("command exited with status {}", output.status))
    } else {
        Err(format!("{detail} (status: {})", output.status))
    }
}

#[cfg(unix)]
pub(crate) fn run_app_until_signal(
    mut app: mihomo_app::RunningApp,
    options: &mihomo_config::BootOptions,
    cwd: &Path,
    environment: &mihomo_config::BootEnvironment,
) -> Result<RunLoopExit, String> {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP]).map_err(|err| err.to_string())?;
    loop {
        for signal in signals.pending() {
            match signal {
                SIGINT | SIGTERM => {
                    app.shutdown();
                    return Ok(RunLoopExit::Shutdown);
                }
                SIGHUP => match app.reload(options, cwd, environment) {
                    Ok(()) => println!("{}", app.summary()),
                    Err(err) => {
                        let message = format!("reload error: {err}");
                        eprintln!("{message}");
                        push_log(LogLevel::Error, message);
                    }
                },
                _ => {}
            }
        }
        if process_control_command(&mut app, options) {
            return Ok(RunLoopExit::Restart);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(not(unix))]
pub(crate) fn run_app_until_signal(
    mut app: mihomo_app::RunningApp,
    _options: &mihomo_config::BootOptions,
    _cwd: &Path,
    _environment: &mihomo_config::BootEnvironment,
) -> Result<RunLoopExit, String> {
    loop {
        if process_control_command(&mut app, _options) {
            return Ok(RunLoopExit::Restart);
        }
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

fn process_control_command(
    app: &mut mihomo_app::RunningApp,
    options: &mihomo_config::BootOptions,
) -> bool {
    match app.poll_control_command() {
        Some(mihomo_api::ApiControlCommand::Restart) => {
            app.shutdown();
            true
        }
        Some(mihomo_api::ApiControlCommand::ApplyConfig { state, reply }) => {
            let result = app
                .apply_config(options, *state)
                .map_err(|err| err.to_string());
            let _ = reply.send(result);
            false
        }
        None => false,
    }
}

#[cfg(unix)]
pub(crate) fn restart_current_process() -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    let err = ProcessCommand::new(&exe)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(err.to_string())
}

#[cfg(windows)]
pub(crate) fn restart_current_process() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    ProcessCommand::new(&exe)
        .args(std::env::args_os().skip(1))
        .spawn()
        .map_err(|err| err.to_string())?;
    std::process::exit(0);
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn restart_current_process() -> Result<(), String> {
    Err("restart is not supported on this platform".to_owned())
}
