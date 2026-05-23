use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

const MAX_RECENT_LOGS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    pub fn includes(self, level: Self) -> bool {
        rank(level) >= rank(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub timestamp_unix_ms: u64,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            timestamp_unix_ms: now_unix_ms(),
        }
    }
}

#[derive(Default)]
struct LogBus {
    recent: VecDeque<LogEntry>,
    subscribers: Vec<mpsc::Sender<LogEntry>>,
}

impl LogBus {
    fn push(&mut self, entry: LogEntry) {
        if self.recent.len() == MAX_RECENT_LOGS {
            self.recent.pop_front();
        }
        self.recent.push_back(entry.clone());
        self.subscribers.retain(|subscriber| subscriber.send(entry.clone()).is_ok());
    }
}

fn global_log_bus() -> &'static Mutex<LogBus> {
    static BUS: OnceLock<Mutex<LogBus>> = OnceLock::new();
    BUS.get_or_init(|| Mutex::new(LogBus::default()))
}

pub fn push_log(level: LogLevel, message: impl Into<String>) {
    global_log_bus()
        .lock()
        .unwrap()
        .push(LogEntry::new(level, message));
}

pub fn recent_logs(min_level: LogLevel) -> Vec<LogEntry> {
    global_log_bus()
        .lock()
        .unwrap()
        .recent
        .iter()
        .filter(|entry| min_level.includes(entry.level))
        .cloned()
        .collect()
}

pub fn subscribe_logs() -> mpsc::Receiver<LogEntry> {
    let (tx, rx) = mpsc::channel();
    global_log_bus().lock().unwrap().subscribers.push(tx);
    rx
}

fn rank(level: LogLevel) -> u8 {
    match level {
        LogLevel::Debug => 0,
        LogLevel::Info => 1,
        LogLevel::Warn => 2,
        LogLevel::Error => 3,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{push_log, recent_logs, subscribe_logs, LogLevel};

    #[test]
    fn log_bus_keeps_recent_entries_and_filters_by_level() {
        push_log(LogLevel::Info, "info-entry");
        push_log(LogLevel::Error, "error-entry");

        let info = recent_logs(LogLevel::Info);
        assert!(info.iter().any(|entry| entry.message == "info-entry"));
        assert!(info.iter().any(|entry| entry.message == "error-entry"));

        let error = recent_logs(LogLevel::Error);
        assert!(!error.iter().any(|entry| entry.message == "info-entry"));
        assert!(error.iter().any(|entry| entry.message == "error-entry"));
    }

    #[test]
    fn log_bus_streams_new_entries_to_subscribers() {
        let rx = subscribe_logs();
        push_log(LogLevel::Warn, "stream-entry");
        let entry = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(entry.level, LogLevel::Warn);
        assert_eq!(entry.message, "stream-entry");
    }
}
