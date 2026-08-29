//! Bounded authenticated managed-hostname lifecycle protocol.

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tunnelproxy_common::{AgentId, PublicHostname, TunnelId};

pub const HOSTNAME_PROTOCOL_ALPN: &[u8] = b"tunnelproxy-hostname/1";
pub const HOSTNAME_PROTOCOL_MAGIC: [u8; 4] = *b"TPH1";
pub const HOSTNAME_PROTOCOL_VERSION: u8 = 1;
pub const MAX_HOSTNAME_MESSAGE_BYTES: usize = 1_024;

const HEADER_BYTES: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HostnameErrorCode {
    InvalidRequest = 1,
    Unauthorized = 2,
    Conflict = 3,
    Capacity = 4,
    Internal = 5,
}

impl HostnameErrorCode {
    fn from_raw(value: u16) -> Result<Self, HostnameProtocolError> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::Conflict),
            4 => Ok(Self::Capacity),
            5 => Ok(Self::Internal),
            _ => Err(HostnameProtocolError::InvalidPayload),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameMessage {
    Allocate {
        agent_id: AgentId,
        tunnel_id: TunnelId,
    },
    Release {
        agent_id: AgentId,
        tunnel_id: TunnelId,
    },
    Allocated {
        hostname: PublicHostname,
        catalog_version: u64,
        changed: bool,
    },
    Released {
        hostname: Option<PublicHostname>,
        catalog_version: u64,
        changed: bool,
    },
    Error {
        code: HostnameErrorCode,
    },
}

pub async fn write_hostname_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &HostnameMessage,
) -> Result<(), HostnameProtocolError> {
    let (message_type, payload) = encode_payload(message)?;
    if payload.len() > MAX_HOSTNAME_MESSAGE_BYTES {
        return Err(HostnameProtocolError::MessageTooLarge);
    }
    let mut header = [0_u8; HEADER_BYTES];
    header[..4].copy_from_slice(&HOSTNAME_PROTOCOL_MAGIC);
    header[4] = HOSTNAME_PROTOCOL_VERSION;
    header[5] = message_type;
    header[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer
        .write_all(&header)
        .await
        .map_err(HostnameProtocolError::Io)?;
    writer
        .write_all(&payload)
        .await
        .map_err(HostnameProtocolError::Io)?;
    writer.flush().await.map_err(HostnameProtocolError::Io)
}

pub async fn read_hostname_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<HostnameMessage>, HostnameProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    match reader.read(&mut header[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(error) => return Err(HostnameProtocolError::Io(error)),
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(HostnameProtocolError::Io)?;
    if header[..4] != HOSTNAME_PROTOCOL_MAGIC
        || header[4] != HOSTNAME_PROTOCOL_VERSION
        || header[6] != 0
        || header[7] != 0
    {
        return Err(HostnameProtocolError::InvalidHeader);
    }
    let payload_len = u32::from_be_bytes(header[8..12].try_into().expect("four bytes")) as usize;
    if payload_len > MAX_HOSTNAME_MESSAGE_BYTES {
        return Err(HostnameProtocolError::MessageTooLarge);
    }
    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(HostnameProtocolError::Io)?;
    decode_payload(header[5], &payload).map(Some)
}

fn encode_payload(message: &HostnameMessage) -> Result<(u8, Vec<u8>), HostnameProtocolError> {
    let mut output = Vec::new();
    let message_type = match message {
        HostnameMessage::Allocate {
            agent_id,
            tunnel_id,
        } => {
            push_string(&mut output, agent_id.as_str())?;
            push_string(&mut output, tunnel_id.as_str())?;
            1
        }
        HostnameMessage::Release {
            agent_id,
            tunnel_id,
        } => {
            push_string(&mut output, agent_id.as_str())?;
            push_string(&mut output, tunnel_id.as_str())?;
            2
        }
        HostnameMessage::Allocated {
            hostname,
            catalog_version,
            changed,
        } => {
            nonzero_version(*catalog_version)?;
            push_string(&mut output, hostname.as_str())?;
            output.extend_from_slice(&catalog_version.to_be_bytes());
            output.push(u8::from(*changed));
            3
        }
        HostnameMessage::Released {
            hostname,
            catalog_version,
            changed,
        } => {
            nonzero_version(*catalog_version)?;
            if *changed != hostname.is_some() {
                return Err(HostnameProtocolError::InvalidPayload);
            }
            match hostname {
                Some(hostname) => {
                    output.push(1);
                    push_string(&mut output, hostname.as_str())?;
                }
                None => output.push(0),
            }
            output.extend_from_slice(&catalog_version.to_be_bytes());
            output.push(u8::from(*changed));
            4
        }
        HostnameMessage::Error { code } => {
            output.extend_from_slice(&(*code as u16).to_be_bytes());
            5
        }
    };
    Ok((message_type, output))
}

fn decode_payload(
    message_type: u8,
    payload: &[u8],
) -> Result<HostnameMessage, HostnameProtocolError> {
    let mut cursor = Cursor::new(payload);
    let message = match message_type {
        1 => HostnameMessage::Allocate {
            agent_id: AgentId::new(cursor.string()?)
                .map_err(|_| HostnameProtocolError::InvalidPayload)?,
            tunnel_id: TunnelId::new(cursor.string()?)
                .map_err(|_| HostnameProtocolError::InvalidPayload)?,
        },
        2 => HostnameMessage::Release {
            agent_id: AgentId::new(cursor.string()?)
                .map_err(|_| HostnameProtocolError::InvalidPayload)?,
            tunnel_id: TunnelId::new(cursor.string()?)
                .map_err(|_| HostnameProtocolError::InvalidPayload)?,
        },
        3 => {
            let raw_hostname = cursor.string()?;
            let hostname = PublicHostname::new(&raw_hostname)
                .map_err(|_| HostnameProtocolError::InvalidPayload)?;
            if hostname.as_str() != raw_hostname {
                return Err(HostnameProtocolError::InvalidPayload);
            }
            HostnameMessage::Allocated {
                hostname,
                catalog_version: nonzero_version(cursor.u64()?)?,
                changed: cursor.boolean()?,
            }
        }
        4 => {
            let hostname = match cursor.u8()? {
                0 => None,
                1 => {
                    let raw_hostname = cursor.string()?;
                    let hostname = PublicHostname::new(&raw_hostname)
                        .map_err(|_| HostnameProtocolError::InvalidPayload)?;
                    if hostname.as_str() != raw_hostname {
                        return Err(HostnameProtocolError::InvalidPayload);
                    }
                    Some(hostname)
                }
                _ => return Err(HostnameProtocolError::InvalidPayload),
            };
            let catalog_version = nonzero_version(cursor.u64()?)?;
            let changed = cursor.boolean()?;
            if changed != hostname.is_some() {
                return Err(HostnameProtocolError::InvalidPayload);
            }
            HostnameMessage::Released {
                hostname,
                catalog_version,
                changed,
            }
        }
        5 => HostnameMessage::Error {
            code: HostnameErrorCode::from_raw(cursor.u16()?)?,
        },
        _ => return Err(HostnameProtocolError::InvalidMessageType),
    };
    if !cursor.is_empty() {
        return Err(HostnameProtocolError::InvalidPayload);
    }
    Ok(message)
}

fn nonzero_version(value: u64) -> Result<u64, HostnameProtocolError> {
    if value == 0 {
        Err(HostnameProtocolError::InvalidPayload)
    } else {
        Ok(value)
    }
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), HostnameProtocolError> {
    let length = u16::try_from(value.len()).map_err(|_| HostnameProtocolError::InvalidPayload)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], HostnameProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HostnameProtocolError::InvalidPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(HostnameProtocolError::InvalidPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], HostnameProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| HostnameProtocolError::InvalidPayload)
    }

    fn u8(&mut self) -> Result<u8, HostnameProtocolError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, HostnameProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, HostnameProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn boolean(&mut self) -> Result<bool, HostnameProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HostnameProtocolError::InvalidPayload),
        }
    }

    fn string(&mut self) -> Result<String, HostnameProtocolError> {
        let length = usize::from(self.u16()?);
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| HostnameProtocolError::InvalidPayload)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Debug)]
pub enum HostnameProtocolError {
    Io(std::io::Error),
    InvalidHeader,
    InvalidMessageType,
    InvalidPayload,
    MessageTooLarge,
}

impl fmt::Display for HostnameProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "hostname protocol I/O failed",
            Self::InvalidHeader => "hostname protocol header is invalid",
            Self::InvalidMessageType => "hostname message type is invalid",
            Self::InvalidPayload => "hostname message payload is invalid",
            Self::MessageTooLarge => "hostname message exceeds its size limit",
        })
    }
}

impl std::error::Error for HostnameProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> (AgentId, TunnelId) {
        (
            AgentId::new("agent-one").unwrap(),
            TunnelId::new("tunnel-one").unwrap(),
        )
    }

    #[tokio::test]
    async fn every_message_round_trips() {
        let (agent_id, tunnel_id) = identity();
        let messages = [
            HostnameMessage::Allocate {
                agent_id: agent_id.clone(),
                tunnel_id: tunnel_id.clone(),
            },
            HostnameMessage::Release {
                agent_id,
                tunnel_id,
            },
            HostnameMessage::Allocated {
                hostname: PublicHostname::new("tp-0123456789abcdef.example.test").unwrap(),
                catalog_version: 7,
                changed: true,
            },
            HostnameMessage::Released {
                hostname: Some(PublicHostname::new("tp-0123456789abcdef.example.test").unwrap()),
                catalog_version: 8,
                changed: true,
            },
            HostnameMessage::Released {
                hostname: None,
                catalog_version: 8,
                changed: false,
            },
            HostnameMessage::Error {
                code: HostnameErrorCode::Unauthorized,
            },
        ];
        for message in messages {
            let mut bytes = Vec::new();
            write_hostname_message(&mut bytes, &message).await.unwrap();
            assert_eq!(
                read_hostname_message(&mut bytes.as_slice()).await.unwrap(),
                Some(message)
            );
        }
    }

    #[tokio::test]
    async fn invalid_header_and_oversized_payload_fail_closed() {
        let mut bytes = Vec::new();
        let (agent_id, tunnel_id) = identity();
        write_hostname_message(
            &mut bytes,
            &HostnameMessage::Allocate {
                agent_id,
                tunnel_id,
            },
        )
        .await
        .unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            read_hostname_message(&mut bytes.as_slice()).await,
            Err(HostnameProtocolError::InvalidHeader)
        ));

        let mut header = [0_u8; HEADER_BYTES];
        header[..4].copy_from_slice(&HOSTNAME_PROTOCOL_MAGIC);
        header[4] = HOSTNAME_PROTOCOL_VERSION;
        header[5] = 1;
        header[8..12].copy_from_slice(&((MAX_HOSTNAME_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        assert!(matches!(
            read_hostname_message(&mut header.as_slice()).await,
            Err(HostnameProtocolError::MessageTooLarge)
        ));
    }

    #[test]
    fn malformed_noncanonical_and_unknown_values_are_rejected() {
        assert!(matches!(
            decode_payload(3, &[0; 8]),
            Err(HostnameProtocolError::InvalidPayload)
        ));
        let mut noncanonical = Vec::new();
        push_string(&mut noncanonical, "Demo.Example.test.").unwrap();
        noncanonical.extend_from_slice(&1_u64.to_be_bytes());
        noncanonical.push(1);
        assert!(matches!(
            decode_payload(3, &noncanonical),
            Err(HostnameProtocolError::InvalidPayload)
        ));
        assert!(matches!(
            decode_payload(5, &[0xff, 0xff]),
            Err(HostnameProtocolError::InvalidPayload)
        ));
        assert!(matches!(
            decode_payload(4, &[0, 0, 0, 0, 0, 0, 0, 1, 1]),
            Err(HostnameProtocolError::InvalidPayload)
        ));
        assert!(matches!(
            encode_payload(&HostnameMessage::Released {
                hostname: None,
                catalog_version: 1,
                changed: true,
            }),
            Err(HostnameProtocolError::InvalidPayload)
        ));
        assert!(matches!(
            encode_payload(&HostnameMessage::Allocated {
                hostname: PublicHostname::new("demo.example.test").unwrap(),
                catalog_version: 0,
                changed: false,
            }),
            Err(HostnameProtocolError::InvalidPayload)
        ));
    }
}
