//! The mlab-agent ↔ tool local protocol, v1 (mlab-agent `docs/tool-protocol.md`).
//!
//! Implemented here from the spec rather than through `mlab-agent-tool-sdk`:
//! virtsec is public (Apache-2.0) and the SDK is not; adapted from k3sec. The wire is small: a
//! big-endian `u32` length, then one CBOR map internally tagged by `t`.
//! Interop with the real agent is checked end to end (see the wiki's Tool-API page).

use std::io::{self, Read};

use serde::{Deserialize, Serialize};

/// Version of the local protocol this tool speaks.
pub const TOOL_PROTOCOL_VERSION: u16 = 1;

/// Frames above this are refused (the agent's limit).
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Agent → tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HostMsg {
    Init {
        protocol: u16,
        /// `[tools.virtsec.settings]` of the agent's local policy.
        settings: ciborium::Value,
        work_dir: String,
    },
    Call {
        id: u64,
        op: String,
        #[serde(with = "serde_bytes")]
        args: Vec<u8>,
        /// mlab sent an upload target: the answer may be a file.
        blob_ok: bool,
    },
    Shutdown,
}

/// Tool → agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToolMsg {
    Ready {
        name: String,
        version: String,
        ops: Vec<String>,
    },
    InitFailed {
        message: String,
    },
    Result {
        id: u64,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
        /// A file under the work dir, encrypted and uploaded by the agent.
        blob_path: Option<String>,
    },
    Failure {
        id: u64,
        error: ErrorBody,
    },
    Event {
        name: String,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
}

/// The agent protocol's error codes (mlab-agent `docs/protocol.md` §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Disabled,
    PolicyDenied,
    UnknownTool,
    UnknownOp,
    ToolUnavailable,
    NotFound,
    TooLarge,
    ReadFailed,
    BadRequest,
    Unsupported,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Encode one frame (length prefix + CBOR).
pub fn encode<T: Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body).map_err(|e| io::Error::other(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::other(format!(
            "frame of {} bytes over the limit",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend((body.len() as u32).to_be_bytes());
    out.extend(body);
    Ok(out)
}

/// Read one frame; `None` on a clean end of stream.
pub fn read<T: for<'de> Deserialize<'de>>(input: &mut dyn Read) -> io::Result<Option<T>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other(format!(
            "frame of {len} bytes over the limit"
        )));
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    ciborium::from_reader(body.as_slice())
        .map(Some)
        .map_err(|e| io::Error::other(format!("bad frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_tags_match_the_spec() {
        let msg = ToolMsg::Event {
            name: "batch".into(),
            body: vec![1, 2, 3],
        };
        let bytes = encode(&msg).unwrap();
        assert_eq!(
            u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        let back: ToolMsg = read(&mut bytes.as_slice()).unwrap().unwrap();
        assert_eq!(back, msg);

        // Internally tagged: {"t": "event", "name": ..., "body": bytes}.
        let v: ciborium::Value = ciborium::from_reader(&bytes[4..]).unwrap();
        let map = v.as_map().unwrap();
        assert!(map
            .iter()
            .any(|(k, v)| k.as_text() == Some("t") && v.as_text() == Some("event")));
        assert!(map
            .iter()
            .any(|(k, v)| k.as_text() == Some("body") && v.is_bytes()));

        let fail = encode(&ToolMsg::Failure {
            id: 3,
            error: ErrorBody::new(ErrorCode::BadRequest, "x"),
        })
        .unwrap();
        let v: ciborium::Value = ciborium::from_reader(&fail[4..]).unwrap();
        let text = format!("{v:?}");
        assert!(
            text.contains("bad_request") && text.contains("failure"),
            "{text}"
        );
    }

    #[test]
    fn end_of_stream_and_oversized_frames() {
        assert!(read::<HostMsg>(&mut [].as_slice()).unwrap().is_none());
        let huge = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert!(read::<HostMsg>(&mut huge.as_slice()).is_err());
    }
}
