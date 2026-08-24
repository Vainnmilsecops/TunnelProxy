//! Bounded certificate-enrollment protocol shared by Agent and Control Plane.

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tunnelproxy_common::{AgentId, TunnelId};

pub const ENROLLMENT_PROTOCOL_ALPN: &[u8] = b"tunnelproxy-enroll/1";
pub const ENROLLMENT_PROTOCOL_MAGIC: [u8; 4] = *b"TPE1";
pub const ENROLLMENT_PROTOCOL_VERSION: u8 = 1;
pub const MAX_ENROLLMENT_MESSAGE_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 12;
const TOKEN_BYTES: usize = 32;
const REQUEST_ID_BYTES: usize = 16;
const FINGERPRINT_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnrollmentToken([u8; TOKEN_BYTES]);

impl EnrollmentToken {
    pub const fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentToken([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnrollmentRequestId([u8; REQUEST_ID_BYTES]);

impl EnrollmentRequestId {
    pub const fn from_bytes(bytes: [u8; REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; REQUEST_ID_BYTES] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EnrollmentErrorCode {
    InvalidRequest = 1,
    Unauthorized = 2,
    TokenExpired = 3,
    IdentityMismatch = 4,
    InvalidCsr = 5,
    Conflict = 6,
    Internal = 7,
}

impl EnrollmentErrorCode {
    fn from_raw(value: u16) -> Result<Self, EnrollmentProtocolError> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::TokenExpired),
            4 => Ok(Self::IdentityMismatch),
            5 => Ok(Self::InvalidCsr),
            6 => Ok(Self::Conflict),
            7 => Ok(Self::Internal),
            _ => Err(EnrollmentProtocolError::InvalidPayload),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum EnrollmentMessage {
    Enroll {
        request_id: EnrollmentRequestId,
        token: EnrollmentToken,
        next_renewal_token: EnrollmentToken,
        agent_id: AgentId,
        tunnel_id: TunnelId,
        csr_der: Vec<u8>,
    },
    Issued {
        request_id: EnrollmentRequestId,
        generation: u64,
        not_after_unix: u64,
        certificate_pem: Vec<u8>,
        server_ca_pem: Vec<u8>,
        fingerprint: [u8; FINGERPRINT_BYTES],
    },
    Activate {
        request_id: EnrollmentRequestId,
        renewal_token: EnrollmentToken,
        fingerprint: [u8; FINGERPRINT_BYTES],
    },
    Activated {
        snapshot_version: u64,
    },
    Error {
        code: EnrollmentErrorCode,
    },
}

impl fmt::Debug for EnrollmentMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enroll {
                request_id,
                next_renewal_token: _,
                agent_id,
                tunnel_id,
                csr_der,
                ..
            } => f
                .debug_struct("Enroll")
                .field("request_id", request_id)
                .field("agent_id", agent_id)
                .field("tunnel_id", tunnel_id)
                .field("csr_bytes", &csr_der.len())
                .finish(),
            Self::Issued {
                request_id,
                generation,
                not_after_unix,
                certificate_pem,
                server_ca_pem,
                fingerprint,
                ..
            } => f
                .debug_struct("Issued")
                .field("request_id", request_id)
                .field("generation", generation)
                .field("not_after_unix", not_after_unix)
                .field("certificate_bytes", &certificate_pem.len())
                .field("server_ca_bytes", &server_ca_pem.len())
                .field("fingerprint", &HexFingerprint(fingerprint))
                .finish(),
            Self::Activate {
                request_id,
                fingerprint,
                ..
            } => f
                .debug_struct("Activate")
                .field("request_id", request_id)
                .field("fingerprint", &HexFingerprint(fingerprint))
                .finish(),
            Self::Activated { snapshot_version } => f
                .debug_struct("Activated")
                .field("snapshot_version", snapshot_version)
                .finish(),
            Self::Error { code } => f.debug_struct("Error").field("code", code).finish(),
        }
    }
}

struct HexFingerprint<'a>(&'a [u8; FINGERPRINT_BYTES]);

impl fmt::Debug for HexFingerprint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub async fn write_enrollment_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &EnrollmentMessage,
) -> Result<(), EnrollmentProtocolError> {
    let (message_type, payload) = encode_payload(message)?;
    if payload.len() > MAX_ENROLLMENT_MESSAGE_BYTES {
        return Err(EnrollmentProtocolError::MessageTooLarge);
    }
    let mut header = [0_u8; HEADER_BYTES];
    header[..4].copy_from_slice(&ENROLLMENT_PROTOCOL_MAGIC);
    header[4] = ENROLLMENT_PROTOCOL_VERSION;
    header[5] = message_type;
    header[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer
        .write_all(&header)
        .await
        .map_err(EnrollmentProtocolError::Io)?;
    writer
        .write_all(&payload)
        .await
        .map_err(EnrollmentProtocolError::Io)?;
    writer.flush().await.map_err(EnrollmentProtocolError::Io)
}

pub async fn read_enrollment_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<EnrollmentMessage>, EnrollmentProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    match reader.read(&mut header[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(error) => return Err(EnrollmentProtocolError::Io(error)),
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(EnrollmentProtocolError::Io)?;
    if header[..4] != ENROLLMENT_PROTOCOL_MAGIC
        || header[4] != ENROLLMENT_PROTOCOL_VERSION
        || header[6] != 0
        || header[7] != 0
    {
        return Err(EnrollmentProtocolError::InvalidHeader);
    }
    let payload_len = u32::from_be_bytes(header[8..12].try_into().expect("four bytes")) as usize;
    if payload_len > MAX_ENROLLMENT_MESSAGE_BYTES {
        return Err(EnrollmentProtocolError::MessageTooLarge);
    }
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(EnrollmentProtocolError::Io)?;
    decode_payload(header[5], &payload).map(Some)
}

fn encode_payload(message: &EnrollmentMessage) -> Result<(u8, Vec<u8>), EnrollmentProtocolError> {
    let mut output = Vec::new();
    let message_type = match message {
        EnrollmentMessage::Enroll {
            request_id,
            token,
            next_renewal_token,
            agent_id,
            tunnel_id,
            csr_der,
        } => {
            output.extend_from_slice(request_id.as_bytes());
            output.extend_from_slice(token.as_bytes());
            output.extend_from_slice(next_renewal_token.as_bytes());
            push_id(&mut output, agent_id.as_str())?;
            push_id(&mut output, tunnel_id.as_str())?;
            push_bytes(&mut output, csr_der)?;
            1
        }
        EnrollmentMessage::Issued {
            request_id,
            generation,
            not_after_unix,
            certificate_pem,
            server_ca_pem,
            fingerprint,
        } => {
            output.extend_from_slice(request_id.as_bytes());
            output.extend_from_slice(&generation.to_be_bytes());
            output.extend_from_slice(&not_after_unix.to_be_bytes());
            push_bytes(&mut output, certificate_pem)?;
            push_bytes(&mut output, server_ca_pem)?;
            output.extend_from_slice(fingerprint);
            2
        }
        EnrollmentMessage::Activate {
            request_id,
            renewal_token,
            fingerprint,
        } => {
            output.extend_from_slice(request_id.as_bytes());
            output.extend_from_slice(renewal_token.as_bytes());
            output.extend_from_slice(fingerprint);
            3
        }
        EnrollmentMessage::Activated { snapshot_version } => {
            output.extend_from_slice(&snapshot_version.to_be_bytes());
            4
        }
        EnrollmentMessage::Error { code } => {
            output.extend_from_slice(&(*code as u16).to_be_bytes());
            5
        }
    };
    Ok((message_type, output))
}

fn decode_payload(
    message_type: u8,
    payload: &[u8],
) -> Result<EnrollmentMessage, EnrollmentProtocolError> {
    let mut cursor = Cursor::new(payload);
    let message = match message_type {
        1 => EnrollmentMessage::Enroll {
            request_id: EnrollmentRequestId::from_bytes(cursor.array()?),
            token: EnrollmentToken::from_bytes(cursor.array()?),
            next_renewal_token: EnrollmentToken::from_bytes(cursor.array()?),
            agent_id: AgentId::new(cursor.string()?)
                .map_err(|_| EnrollmentProtocolError::InvalidPayload)?,
            tunnel_id: TunnelId::new(cursor.string()?)
                .map_err(|_| EnrollmentProtocolError::InvalidPayload)?,
            csr_der: cursor.bytes()?,
        },
        2 => EnrollmentMessage::Issued {
            request_id: EnrollmentRequestId::from_bytes(cursor.array()?),
            generation: cursor.u64()?,
            not_after_unix: cursor.u64()?,
            certificate_pem: cursor.bytes()?,
            server_ca_pem: cursor.bytes()?,
            fingerprint: cursor.array()?,
        },
        3 => EnrollmentMessage::Activate {
            request_id: EnrollmentRequestId::from_bytes(cursor.array()?),
            renewal_token: EnrollmentToken::from_bytes(cursor.array()?),
            fingerprint: cursor.array()?,
        },
        4 => EnrollmentMessage::Activated {
            snapshot_version: cursor.u64()?,
        },
        5 => EnrollmentMessage::Error {
            code: EnrollmentErrorCode::from_raw(cursor.u16()?)?,
        },
        _ => return Err(EnrollmentProtocolError::InvalidMessageType),
    };
    if !cursor.is_empty() {
        return Err(EnrollmentProtocolError::InvalidPayload);
    }
    Ok(message)
}

fn push_id(output: &mut Vec<u8>, value: &str) -> Result<(), EnrollmentProtocolError> {
    let length = u8::try_from(value.len()).map_err(|_| EnrollmentProtocolError::InvalidPayload)?;
    output.push(length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EnrollmentProtocolError> {
    let length =
        u32::try_from(value.len()).map_err(|_| EnrollmentProtocolError::MessageTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], EnrollmentProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EnrollmentProtocolError::InvalidPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EnrollmentProtocolError::InvalidPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EnrollmentProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| EnrollmentProtocolError::InvalidPayload)
    }

    fn u16(&mut self) -> Result<u16, EnrollmentProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, EnrollmentProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn string(&mut self) -> Result<String, EnrollmentProtocolError> {
        let length = usize::from(*self.take(1)?.first().expect("one byte"));
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| EnrollmentProtocolError::InvalidPayload)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, EnrollmentProtocolError> {
        let length = u32::from_be_bytes(self.array()?) as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Debug)]
pub enum EnrollmentProtocolError {
    Io(std::io::Error),
    InvalidHeader,
    InvalidMessageType,
    InvalidPayload,
    MessageTooLarge,
}

impl fmt::Display for EnrollmentProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io(_) => "enrollment protocol I/O failed",
            Self::InvalidHeader => "enrollment protocol header is invalid",
            Self::InvalidMessageType => "enrollment message type is invalid",
            Self::InvalidPayload => "enrollment message payload is invalid",
            Self::MessageTooLarge => "enrollment message exceeds its size limit",
        };
        f.write_str(message)
    }
}

impl std::error::Error for EnrollmentProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment() -> EnrollmentMessage {
        EnrollmentMessage::Enroll {
            request_id: EnrollmentRequestId::from_bytes([1; 16]),
            token: EnrollmentToken::from_bytes([2; 32]),
            next_renewal_token: EnrollmentToken::from_bytes([12; 32]),
            agent_id: AgentId::new("agent-one").unwrap(),
            tunnel_id: TunnelId::new("tunnel-one").unwrap(),
            csr_der: vec![3; 128],
        }
    }

    #[tokio::test]
    async fn messages_round_trip_and_debug_redacts_tokens() {
        let messages = vec![
            enrollment(),
            EnrollmentMessage::Issued {
                request_id: EnrollmentRequestId::from_bytes([4; 16]),
                generation: 7,
                not_after_unix: 1234,
                certificate_pem: b"certificate".to_vec(),
                server_ca_pem: b"authority".to_vec(),
                fingerprint: [6; 32],
            },
            EnrollmentMessage::Activate {
                request_id: EnrollmentRequestId::from_bytes([7; 16]),
                renewal_token: EnrollmentToken::from_bytes([8; 32]),
                fingerprint: [9; 32],
            },
            EnrollmentMessage::Activated {
                snapshot_version: 11,
            },
            EnrollmentMessage::Error {
                code: EnrollmentErrorCode::Unauthorized,
            },
        ];
        for message in messages {
            let mut bytes = Vec::new();
            write_enrollment_message(&mut bytes, &message)
                .await
                .unwrap();
            let decoded = read_enrollment_message(&mut bytes.as_slice())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(decoded, message);
            let debug = format!("{decoded:?}");
            assert!(!debug.contains(&"02".repeat(32)));
            assert!(!debug.contains(&"0c".repeat(32)));
        }
    }

    #[tokio::test]
    async fn invalid_header_and_oversized_payload_fail_closed() {
        let mut bytes = Vec::new();
        write_enrollment_message(&mut bytes, &enrollment())
            .await
            .unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            read_enrollment_message(&mut bytes.as_slice()).await,
            Err(EnrollmentProtocolError::InvalidHeader)
        ));

        let mut header = [0_u8; HEADER_BYTES];
        header[..4].copy_from_slice(&ENROLLMENT_PROTOCOL_MAGIC);
        header[4] = ENROLLMENT_PROTOCOL_VERSION;
        header[5] = 1;
        header[8..12].copy_from_slice(&((MAX_ENROLLMENT_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        assert!(matches!(
            read_enrollment_message(&mut header.as_slice()).await,
            Err(EnrollmentProtocolError::MessageTooLarge)
        ));
    }

    #[test]
    fn invalid_payload_and_unknown_error_codes_are_rejected() {
        assert!(matches!(
            decode_payload(1, &[0; 8]),
            Err(EnrollmentProtocolError::InvalidPayload)
        ));
        assert!(matches!(
            decode_payload(5, &[0xff, 0xff]),
            Err(EnrollmentProtocolError::InvalidPayload)
        ));
    }
}
