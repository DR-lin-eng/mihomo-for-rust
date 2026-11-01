use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, Condvar, Mutex};

use mihomo_core::BoxedTcpStream;
use mihomo_runtime::ListenerRuntimeError;
use mihomo_transport::XHttpOptions;

use super::meta::{
    collect_xhttp_uplink_prefix, normalize_xhttp_path, normalized_xhttp_mode,
    normalized_xhttp_seq_key, normalized_xhttp_seq_placement, normalized_xhttp_session_key,
    normalized_xhttp_session_placement, parse_cookie_header, parse_query_string, split_request_path,
    take_xhttp_meta_from_request, validate_expected_headers, xhttp_download_authority,
    xhttp_download_headers, xhttp_download_path, xhttp_uses_path_seq, xhttp_uses_path_session,
};
use super::session::{
    PacketUpSequenceInner, PacketUpSequenceReader, PacketUpSequenceState, PendingXhttpSession,
    SharedReadHalf, SharedWriteHalf, SplitTcpStream,
};

pub(in crate::listener_service) struct AcceptedXhttpRequest {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
}

pub(in crate::listener_service) fn accept_inbound_xhttp_stream(
    protocol: &str,
    options: &XHttpOptions,
    sessions: &Mutex<HashMap<String, PendingXhttpSession>>,
    request: AcceptedXhttpRequest,
    stream: BoxedTcpStream,
) -> Result<Option<BoxedTcpStream>, ListenerRuntimeError> {
    let mode = normalized_xhttp_mode(options);
    if !matches!(mode, "stream-one" | "stream-up" | "packet-up") {
        return Err(ListenerRuntimeError::Io(io::Error::other(format!(
            "{protocol} inbound xhttp mode is not implemented yet: {mode}",
        ))));
    }

    let expected_path = normalize_xhttp_path(&options.path);
    let download_expected_path = xhttp_download_path(options);
    let upload_authority = options.host.trim();
    let download_authority = xhttp_download_authority(options).trim();
    let request_path = request.path.clone();
    let (request_path_only, request_query) = split_request_path(&request_path);
    let request_query = parse_query_string(request_query);

    if mode == "stream-one" {
        if request.method != "POST" {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected {protocol} xhttp request method: {}", request.method),
            )));
        }
        if request_path_only != expected_path {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp request path: expected={}, got={}",
                    expected_path, request.path
                ),
            )));
        }
        if !upload_authority.is_empty() && request.authority != upload_authority {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp authority: expected={}, got={}",
                    upload_authority, request.authority
                ),
            )));
        }
        return Ok(Some(stream));
    }

    if mode == "stream-up" {
        return accept_stream_up_request(
            protocol,
            options,
            sessions,
            request,
            stream,
            request_path_only,
            request_query,
            &expected_path,
            &download_expected_path,
            upload_authority,
            download_authority,
        );
    }

    accept_packet_up_request(
        protocol,
        options,
        sessions,
        request,
        stream,
        request_path_only,
        request_query,
        &expected_path,
        &download_expected_path,
        upload_authority,
        download_authority,
    )
}

fn accept_stream_up_request(
    protocol: &str,
    options: &XHttpOptions,
    sessions: &Mutex<HashMap<String, PendingXhttpSession>>,
    request: AcceptedXhttpRequest,
    stream: BoxedTcpStream,
    request_path_only: &str,
    request_query: BTreeMap<String, String>,
    expected_path: &str,
    download_expected_path: &str,
    upload_authority: &str,
    download_authority: &str,
) -> Result<Option<BoxedTcpStream>, ListenerRuntimeError> {
    if request.method != "GET" && request.method != "POST" {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected {protocol} xhttp stream-up request method: {}",
                request.method
            ),
        )));
    }
    let cookies = parse_cookie_header(&request.headers);
    let (base_path, authority, expected_headers) = if request.method == "GET" {
        (
            download_expected_path,
            download_authority,
            xhttp_download_headers(options),
        )
    } else {
        (expected_path, upload_authority, options.headers.clone())
    };
    if !authority.is_empty() && request.authority != authority {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected {protocol} xhttp {} authority: expected={}, got={}",
                request.method.to_ascii_lowercase(),
                authority,
                request.authority
            ),
        )));
    }
    validate_expected_headers(
        &request.headers,
        &expected_headers,
        if request.method == "GET" { "download" } else { "upload" },
    )?;
    if !request_path_only.starts_with(base_path)
        || (request_path_only.len() <= base_path.len() && xhttp_uses_path_session(options))
    {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected {protocol} xhttp stream-up request path: base={}, got={}",
                base_path, request.path
            ),
        )));
    }
    let mut path_segments = request_path_only[base_path.len()..]
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let session_id = take_xhttp_meta_from_request(
        &request.headers,
        &request_query,
        &cookies,
        &mut path_segments,
        normalized_xhttp_session_placement(options),
        &normalized_xhttp_session_key(options),
        "session id",
    )?;
    if !path_segments.is_empty() {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected {protocol} xhttp stream-up extra path segments: {}",
                path_segments.join("/")
            ),
        )));
    }

    let mut session_map = sessions.lock().map_err(|_| {
        ListenerRuntimeError::Io(io::Error::other(format!(
            "{protocol} inbound xhttp session map poisoned",
        )))
    })?;
    let session = session_map.entry(session_id.clone()).or_default();
    let slot = if request.method == "GET" {
        &mut session.download_stream
    } else {
        &mut session.upload_stream
    };
    if slot.is_some() {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "duplicate {protocol} xhttp {} stream for session {}",
                request.method, session_id
            ),
        )));
    }
    *slot = Some(stream);
    if session.download_stream.is_some() && session.upload_stream.is_some() {
        let download = session.download_stream.take().unwrap();
        let upload = session.upload_stream.take().unwrap();
        session_map.remove(&session_id);
        Ok(Some(split_stream(upload, download)))
    } else {
        Ok(None)
    }
}

fn accept_packet_up_request(
    protocol: &str,
    options: &XHttpOptions,
    sessions: &Mutex<HashMap<String, PendingXhttpSession>>,
    request: AcceptedXhttpRequest,
    stream: BoxedTcpStream,
    request_path_only: &str,
    request_query: BTreeMap<String, String>,
    expected_path: &str,
    download_expected_path: &str,
    upload_authority: &str,
    download_authority: &str,
) -> Result<Option<BoxedTcpStream>, ListenerRuntimeError> {
    if request.method != "GET" && request.method != "POST" {
        return Err(ListenerRuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected {protocol} xhttp packet-up request method: {}",
                request.method
            ),
        )));
    }

    let cookies = parse_cookie_header(&request.headers);
    if request.method == "GET" {
        if !download_authority.is_empty() && request.authority != download_authority {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp packet-up download authority: expected={}, got={}",
                    download_authority, request.authority
                ),
            )));
        }
        validate_expected_headers(
            &request.headers,
            &xhttp_download_headers(options),
            "download",
        )?;
        if !request_path_only.starts_with(download_expected_path)
            || (request_path_only.len() <= download_expected_path.len()
                && xhttp_uses_path_session(options))
        {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp packet-up download path: base={}, got={}",
                    download_expected_path, request.path
                ),
            )));
        }
        let mut path_segments = request_path_only[download_expected_path.len()..]
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let session_id = take_xhttp_meta_from_request(
            &request.headers,
            &request_query,
            &cookies,
            &mut path_segments,
            normalized_xhttp_session_placement(options),
            &normalized_xhttp_session_key(options),
            "session id",
        )?;
        if !path_segments.is_empty() {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp packet-up download extra path segments: {}",
                    path_segments.join("/")
                ),
            )));
        }

        let mut session_map = sessions.lock().map_err(|_| {
            ListenerRuntimeError::Io(io::Error::other(format!(
                "{protocol} inbound xhttp session map poisoned",
            )))
        })?;
        let session = session_map.entry(session_id.clone()).or_default();
        if session.download_stream.is_some() {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "duplicate {protocol} xhttp packet-up download stream for session {}",
                    session_id
                ),
            )));
        }
        session.download_stream = Some(stream);
        let packet_up = Arc::clone(session.packet_up.get_or_insert_with(|| {
            Arc::new(PacketUpSequenceState {
                inner: Mutex::new(PacketUpSequenceInner::default()),
                ready: Condvar::new(),
            })
        }));
        let has_seq0 = packet_up
            .inner
            .lock()
            .map_err(|_| {
                ListenerRuntimeError::Io(io::Error::other(format!(
                    "{protocol} inbound xhttp packet-up sequence mutex poisoned",
                )))
            })?
            .streams
            .contains_key(&0);
        if has_seq0 {
            let download = session.download_stream.take().unwrap();
            session.packet_up = None;
            session_map.remove(&session_id);
            Ok(Some(split_packet_up_stream(packet_up, download)))
        } else {
            Ok(None)
        }
    } else {
        if !upload_authority.is_empty() && request.authority != upload_authority {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp packet-up upload authority: expected={}, got={}",
                    upload_authority, request.authority
                ),
            )));
        }
        validate_expected_headers(&request.headers, &options.headers, "upload")?;
        if !request_path_only.starts_with(expected_path)
            || (request_path_only.len() <= expected_path.len()
                && (xhttp_uses_path_session(options) || xhttp_uses_path_seq(options)))
        {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp packet-up upload path: base={}, got={}",
                    expected_path, request.path
                ),
            )));
        }
        let mut path_segments = request_path_only[expected_path.len()..]
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        let session_id = take_xhttp_meta_from_request(
            &request.headers,
            &request_query,
            &cookies,
            &mut path_segments,
            normalized_xhttp_session_placement(options),
            &normalized_xhttp_session_key(options),
            "session id",
        )?;
        let seq = take_xhttp_meta_from_request(
            &request.headers,
            &request_query,
            &cookies,
            &mut path_segments,
            normalized_xhttp_seq_placement(options),
            &normalized_xhttp_seq_key(options),
            "seq",
        )?;
        if !path_segments.is_empty() {
            return Err(ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected {protocol} xhttp packet-up upload extra path segments: {}",
                    path_segments.join("/")
                ),
            )));
        }

        let prefix = collect_xhttp_uplink_prefix(&request.headers, &cookies, options)?;
        let stream = super::meta::maybe_prefix_xhttp_stream(stream, prefix);
        let mut session_map = sessions.lock().map_err(|_| {
            ListenerRuntimeError::Io(io::Error::other(format!(
                "{protocol} inbound xhttp session map poisoned",
            )))
        })?;
        let session = session_map.entry(session_id.to_owned()).or_default();
        let seq = seq.parse::<u64>().map_err(|err| {
            ListenerRuntimeError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {protocol} xhttp packet-up seq {seq}: {err}"),
            ))
        })?;
        let packet_up = Arc::clone(session.packet_up.get_or_insert_with(|| {
            Arc::new(PacketUpSequenceState {
                inner: Mutex::new(PacketUpSequenceInner::default()),
                ready: Condvar::new(),
            })
        }));
        {
            let mut packet_guard = packet_up.inner.lock().map_err(|_| {
                ListenerRuntimeError::Io(io::Error::other(format!(
                    "{protocol} inbound xhttp packet-up sequence mutex poisoned",
                )))
            })?;
            if packet_guard.streams.contains_key(&seq) {
                return Err(ListenerRuntimeError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "duplicate {protocol} xhttp packet-up upload stream for session {} seq {}",
                        session_id, seq
                    ),
                )));
            }
            packet_guard.streams.insert(seq, stream);
        }
        packet_up.ready.notify_all();
        if seq == 0 && session.download_stream.is_some() {
            let download = session.download_stream.take().unwrap();
            session.packet_up = None;
            session_map.remove(&session_id);
            Ok(Some(split_packet_up_stream(packet_up, download)))
        } else {
            Ok(None)
        }
    }
}

fn split_stream(upload: BoxedTcpStream, download: BoxedTcpStream) -> BoxedTcpStream {
    Box::new(SplitTcpStream {
        reader: SharedReadHalf(Arc::new(Mutex::new(upload))),
        writer: SharedWriteHalf(Arc::new(Mutex::new(download))),
        packet_up_close_state: None,
    })
}

fn split_packet_up_stream(
    packet_up: Arc<PacketUpSequenceState>,
    download: BoxedTcpStream,
) -> BoxedTcpStream {
    Box::new(SplitTcpStream {
        reader: SharedReadHalf(Arc::new(Mutex::new(Box::new(
            PacketUpSequenceReader::new(packet_up.clone()),
        )))),
        writer: SharedWriteHalf(Arc::new(Mutex::new(download))),
        packet_up_close_state: Some(packet_up),
    })
}
