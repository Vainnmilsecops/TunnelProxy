use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    decode_versioned_snapshot, encode_versioned_snapshot, SnapshotVersion,
    VersionedAuthorizationSnapshot, MAX_SNAPSHOT_BYTES,
};

const MAGIC: [u8; 4] = *b"TPS1";
const HEADER_SIZE: usize = 12;
pub const SNAPSHOT_PROTOCOL_VERSION: u8 = 1;
pub const SNAPSHOT_PROTOCOL_ALPN: &[u8] = b"tunnelproxy-snapshot/1";

const SUBSCRIBE: u8 = 1;
const SNAPSHOT: u8 = 2;
const UP_TO_DATE: u8 = 3;
const ERROR: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotMessage {
    /// Version zero means a fresh Edge with no cached snapshot.
    Subscribe {
        last_applied_version: u64,
    },
    Snapshot(VersionedAuthorizationSnapshot),
    UpToDate(SnapshotVersion),
    Error(SnapshotServiceErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnapshotServiceErrorCode {
    InvalidRequest = 1,
    RepositoryUninitialized = 2,
    ClientAhead = 3,
}

impl SnapshotServiceErrorCode {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::InvalidRequest),
            2 => Some(Self::RepositoryUninitialized),
            3 => Some(Self::ClientAhead),
            _ => None,
        }
    }
}

pub fn encode_snapshot_message(
    message: &SnapshotMessage,
) -> Result<Vec<u8>, SnapshotProtocolError> {
    let (message_type, payload) = match message {
        SnapshotMessage::Subscribe {
            last_applied_version,
        } => (SUBSCRIBE, last_applied_version.to_be_bytes().to_vec()),
        SnapshotMessage::Snapshot(snapshot) => (
            SNAPSHOT,
            encode_versioned_snapshot(snapshot).map_err(SnapshotProtocolError::Snapshot)?,
        ),
        SnapshotMessage::UpToDate(version) => (UP_TO_DATE, version.get().to_be_bytes().to_vec()),
        SnapshotMessage::Error(code) => (ERROR, (*code as u16).to_be_bytes().to_vec()),
    };
    if payload.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotProtocolError::PayloadTooLarge(payload.len()));
    }
    let mut output = Vec::with_capacity(HEADER_SIZE + payload.len());
    output.extend_from_slice(&MAGIC);
    output.push(SNAPSHOT_PROTOCOL_VERSION);
    output.push(message_type);
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn decode_snapshot_message(bytes: &[u8]) -> Result<SnapshotMessage, SnapshotProtocolError> {
    let header: [u8; HEADER_SIZE] = bytes
        .get(..HEADER_SIZE)
        .ok_or(SnapshotProtocolError::Truncated)?
        .try_into()
        .expect("header size checked");
    if header[..4] != MAGIC {
        return Err(SnapshotProtocolError::InvalidMagic);
    }
    if header[4] != SNAPSHOT_PROTOCOL_VERSION {
        return Err(SnapshotProtocolError::UnsupportedVersion(header[4]));
    }
    if u16::from_be_bytes([header[6], header[7]]) != 0 {
        return Err(SnapshotProtocolError::UnsupportedFlags);
    }
    let payload_len = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if payload_len > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotProtocolError::PayloadTooLarge(payload_len));
    }
    if bytes.len() != HEADER_SIZE + payload_len {
        return Err(if bytes.len() < HEADER_SIZE + payload_len {
            SnapshotProtocolError::Truncated
        } else {
            SnapshotProtocolError::TrailingBytes
        });
    }
    let payload = &bytes[HEADER_SIZE..];
    match header[5] {
        SUBSCRIBE if payload.len() == 8 => Ok(SnapshotMessage::Subscribe {
            last_applied_version: u64::from_be_bytes(payload.try_into().expect("length checked")),
        }),
        SNAPSHOT => decode_versioned_snapshot(payload)
            .map(SnapshotMessage::Snapshot)
            .map_err(SnapshotProtocolError::Snapshot),
        UP_TO_DATE if payload.len() == 8 => {
            let raw = u64::from_be_bytes(payload.try_into().expect("length checked"));
            SnapshotVersion::new(raw)
                .map(SnapshotMessage::UpToDate)
                .ok_or(SnapshotProtocolError::InvalidPayload)
        }
        ERROR if payload.len() == 2 => {
            let raw = u16::from_be_bytes(payload.try_into().expect("length checked"));
            SnapshotServiceErrorCode::from_raw(raw)
                .map(SnapshotMessage::Error)
                .ok_or(SnapshotProtocolError::InvalidPayload)
        }
        SUBSCRIBE | UP_TO_DATE | ERROR => Err(SnapshotProtocolError::InvalidPayload),
        other => Err(SnapshotProtocolError::UnknownMessageType(other)),
    }
}

pub async fn read_snapshot_message<R>(
    reader: &mut R,
) -> Result<SnapshotMessage, SnapshotProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HEADER_SIZE];
    reader
        .read_exact(&mut header)
        .await
        .map_err(SnapshotProtocolError::Io)?;
    let payload_len = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if payload_len > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotProtocolError::PayloadTooLarge(payload_len));
    }
    let mut frame = Vec::with_capacity(HEADER_SIZE + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_SIZE + payload_len, 0);
    reader
        .read_exact(&mut frame[HEADER_SIZE..])
        .await
        .map_err(SnapshotProtocolError::Io)?;
    decode_snapshot_message(&frame)
}

pub async fn write_snapshot_message<W>(
    writer: &mut W,
    message: &SnapshotMessage,
) -> Result<(), SnapshotProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_snapshot_message(message)?;
    writer
        .write_all(&encoded)
        .await
        .map_err(SnapshotProtocolError::Io)?;
    writer.flush().await.map_err(SnapshotProtocolError::Io)
}

#[derive(Debug)]
pub enum SnapshotProtocolError {
    Io(std::io::Error),
    Snapshot(crate::SnapshotCodecError),
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedFlags,
    UnknownMessageType(u8),
    InvalidPayload,
    PayloadTooLarge(usize),
    Truncated,
    TrailingBytes,
}

impl std::fmt::Display for SnapshotProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(_) => f.write_str("snapshot protocol I/O failed"),
            Self::Snapshot(error) => write!(f, "invalid snapshot payload: {error}"),
            Self::InvalidMagic => f.write_str("invalid snapshot protocol magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported snapshot protocol version {version}")
            }
            Self::UnsupportedFlags => f.write_str("snapshot protocol flags are unsupported"),
            Self::UnknownMessageType(kind) => {
                write!(f, "unknown snapshot message type {kind}")
            }
            Self::InvalidPayload => f.write_str("snapshot message payload is invalid"),
            Self::PayloadTooLarge(size) => {
                write!(f, "snapshot protocol payload is too large: {size} bytes")
            }
            Self::Truncated => f.write_str("snapshot protocol frame is truncated"),
            Self::TrailingBytes => f.write_str("snapshot protocol frame has trailing bytes"),
        }
    }
}

impl std::error::Error for SnapshotProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizationSnapshot, SnapshotVersion, VersionedAuthorizationSnapshot};

    #[test]
    fn protocol_messages_have_stable_roundtrips() {
        let messages = [
            SnapshotMessage::Subscribe {
                last_applied_version: 0,
            },
            SnapshotMessage::Snapshot(VersionedAuthorizationSnapshot::new(
                SnapshotVersion::FIRST,
                AuthorizationSnapshot::default(),
            )),
            SnapshotMessage::UpToDate(SnapshotVersion::new(8).unwrap()),
            SnapshotMessage::Error(SnapshotServiceErrorCode::ClientAhead),
        ];
        for message in messages {
            let encoded = encode_snapshot_message(&message).unwrap();
            assert_eq!(decode_snapshot_message(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn malformed_header_version_flags_and_length_fail_closed() {
        let valid = encode_snapshot_message(&SnapshotMessage::Subscribe {
            last_applied_version: 3,
        })
        .unwrap();
        let mut invalid_magic = valid.clone();
        invalid_magic[0] = b'X';
        assert!(matches!(
            decode_snapshot_message(&invalid_magic),
            Err(SnapshotProtocolError::InvalidMagic)
        ));
        let mut invalid_version = valid.clone();
        invalid_version[4] = 2;
        assert!(matches!(
            decode_snapshot_message(&invalid_version),
            Err(SnapshotProtocolError::UnsupportedVersion(2))
        ));
        let mut invalid_flags = valid.clone();
        invalid_flags[7] = 1;
        assert!(matches!(
            decode_snapshot_message(&invalid_flags),
            Err(SnapshotProtocolError::UnsupportedFlags)
        ));
        assert!(matches!(
            decode_snapshot_message(&valid[..valid.len() - 1]),
            Err(SnapshotProtocolError::Truncated)
        ));
    }
}
