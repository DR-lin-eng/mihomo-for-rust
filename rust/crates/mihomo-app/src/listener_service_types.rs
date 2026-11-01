use std::net::SocketAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundTcpListener {
    pub name: String,
    pub kind: String,
    pub configured_addr: String,
    pub local_addr: SocketAddr,
}

#[derive(Debug)]
pub enum ListenerServiceError {
    Rule(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ListenerServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rule(message) => write!(f, "{message}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ListenerServiceError {}

impl From<std::io::Error> for ListenerServiceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
