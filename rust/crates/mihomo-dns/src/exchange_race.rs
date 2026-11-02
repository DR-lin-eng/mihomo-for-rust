use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use crate::{DnsError, DnsPacketTransport};

const WORKERS_PER_QUERY: usize = 4;
const MAX_WORKERS: usize = 64;
static WORKERS: AtomicUsize = AtomicUsize::new(0);

struct WorkerPermit;
impl WorkerPermit {
    fn acquire() -> Option<Self> {
        WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_WORKERS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for WorkerPermit {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn exchange_one(
    transport: &mut (impl DnsPacketTransport + ?Sized),
    server: &str,
    packet: &[u8],
) -> Result<Vec<u8>, DnsError> {
    let response = transport.exchange(server, packet)?;
    crate::packet::validate_dns_reply(packet, &response)?;
    // Match Go: retry SERVFAIL/REFUSED, but preserve NXDOMAIN and intentional
    // rcode:// policies instead of fabricating a successful empty response.
    if !server.starts_with("rcode://") && matches!(response[3] & 15, 2 | 5) {
        return Err(DnsError::DnsProtocol(format!(
            "DNS upstream returned rcode {}",
            response[3] & 15
        )));
    }
    Ok(response)
}

pub(super) fn exchange(
    transport: &mut impl DnsPacketTransport,
    servers: &[String],
    packet: &[u8],
) -> Result<Vec<u8>, DnsError> {
    if let Some(policy) = servers.iter().find(|server| server.starts_with("rcode://")) {
        return exchange_one(transport, policy, packet);
    }
    let mut forks = Vec::new();
    if servers.len() > 1 {
        for _ in 0..servers.len().min(WORKERS_PER_QUERY) {
            let Some(fork) = transport.fork() else { break };
            let Some(permit) = WorkerPermit::acquire() else {
                break;
            };
            forks.push((fork, permit));
        }
    }
    if forks.is_empty() {
        let mut error = DnsError::ResolveFailed("no DNS upstream servers configured".into());
        for server in servers {
            match exchange_one(transport, server, packet) {
                Ok(response) => return Ok(response),
                Err(err) => error = err,
            }
        }
        return Err(error);
    }
    let queue = Arc::new(Mutex::new(VecDeque::from(servers.to_vec())));
    let stopped = Arc::new(AtomicBool::new(false));
    let _stop = Stop(stopped.clone());
    let (tx, rx) = mpsc::channel();
    let mut spawn_error = None;
    for (mut fork, permit) in forks {
        let queue = queue.clone();
        let stopped = stopped.clone();
        let tx = tx.clone();
        let packet = packet.to_vec();
        if let Err(err) = std::thread::Builder::new()
            .name("dns-upstream".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let _permit = permit;
                while !stopped.load(Ordering::Acquire) {
                    let Some(server) = queue.lock().unwrap().pop_front() else {
                        break;
                    };
                    let result = exchange_one(&mut *fork, &server, &packet);
                    let done = result.is_ok();
                    if tx.send(result).is_err() || done {
                        break;
                    }
                }
            })
        {
            spawn_error = Some(DnsError::Io(err.to_string()));
        }
    }
    drop(tx);
    let mut error =
        spawn_error.unwrap_or_else(|| DnsError::ResolveFailed("all DNS upstreams failed".into()));
    for response in rx {
        match response {
            Ok(response) => return Ok(response),
            Err(err) => error = err,
        }
    }
    Err(error)
}
