mod extras;
mod server_streams;

pub(crate) use extras::*;
pub(crate) use server_streams::*;

use std::fs;
use std::io;

pub(crate) fn normalize_client_auth_type(raw: &str) -> Result<Option<ClientAuthMode>, String> {
    match raw.trim() {
        "" => Ok(None),
        "request" => Ok(Some(ClientAuthMode::Request)),
        "require-any" => Ok(Some(ClientAuthMode::RequireAny)),
        "verify-if-given" | "verify" => Ok(Some(ClientAuthMode::VerifyIfGiven)),
        "require-and-verify" | "require" => Ok(Some(ClientAuthMode::RequireAndVerify)),
        other => Err(other.to_owned()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientAuthMode {
    Request,
    RequireAny,
    VerifyIfGiven,
    RequireAndVerify,
}

pub(crate) fn resolve_pem_source(raw: &str) -> io::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains("-----BEGIN ") {
        return Ok(raw.to_owned());
    }
    fs::read_to_string(trimmed)
}
