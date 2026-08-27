//! Bounded Route Catalog Protocol v1 used only between Control Plane and Edge.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    decode_https_route_catalog, encode_https_route_catalog, HttpsRouteCatalog,
    HttpsRouteCatalogVersion, HttpsRouteCodecError, MAX_HTTPS_ROUTE_CATALOG_BYTES,
};

const MAGIC: [u8; 4] = *b"TPR1";
const HEADER_BYTES: usize = 12;
const SUBSCRIBE: u8 = 1;
const CATALOG: u8 = 2;
const UP_TO_DATE: u8 = 3;
const ERROR: u8 = 4;

pub const HTTPS_ROUTE_PROTOCOL_VERSION: u8 = 1;
pub const HTTPS_ROUTE_PROTOCOL_ALPN: &[u8] = b"tunnelproxy-https-routes/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsRouteMessage {
    Subscribe { last_applied_version: u64 },
    Catalog(HttpsRouteCatalog),
    UpToDate(HttpsRouteCatalogVersion),
    Error(HttpsRouteServiceErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HttpsRouteServiceErrorCode {
    InvalidRequest = 1,
    ClientAhead = 2,
}

impl HttpsRouteServiceErrorCode {
    const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::InvalidRequest),
            2 => Some(Self::ClientAhead),
            _ => None,
        }
    }
}

pub fn encode_https_route_message(
    message: &HttpsRouteMessage,
) -> Result<Vec<u8>, HttpsRouteProtocolError> {
    let (kind, payload) = match message {
        HttpsRouteMessage::Subscribe {
            last_applied_version,
        } => (SUBSCRIBE, last_applied_version.to_be_bytes().to_vec()),
        HttpsRouteMessage::Catalog(catalog) => (
            CATALOG,
            encode_https_route_catalog(catalog).map_err(HttpsRouteProtocolError::Catalog)?,
        ),
        HttpsRouteMessage::UpToDate(version) => (UP_TO_DATE, version.get().to_be_bytes().to_vec()),
        HttpsRouteMessage::Error(code) => (ERROR, (*code as u16).to_be_bytes().to_vec()),
    };
    if payload.len() > MAX_HTTPS_ROUTE_CATALOG_BYTES {
        return Err(HttpsRouteProtocolError::PayloadTooLarge);
    }
    let mut output = Vec::with_capacity(HEADER_BYTES + payload.len());
    output.extend_from_slice(&MAGIC);
    output.push(HTTPS_ROUTE_PROTOCOL_VERSION);
    output.push(kind);
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn decode_https_route_message(
    bytes: &[u8],
) -> Result<HttpsRouteMessage, HttpsRouteProtocolError> {
    let header: [u8; HEADER_BYTES] = bytes
        .get(..HEADER_BYTES)
        .ok_or(HttpsRouteProtocolError::Truncated)?
        .try_into()
        .expect("header length checked");
    if header[..4] != MAGIC {
        return Err(HttpsRouteProtocolError::InvalidMagic);
    }
    if header[4] != HTTPS_ROUTE_PROTOCOL_VERSION {
        return Err(HttpsRouteProtocolError::UnsupportedVersion(header[4]));
    }
    if u16::from_be_bytes([header[6], header[7]]) != 0 {
        return Err(HttpsRouteProtocolError::UnsupportedFlags);
    }
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if length > MAX_HTTPS_ROUTE_CATALOG_BYTES {
        return Err(HttpsRouteProtocolError::PayloadTooLarge);
    }
    let expected = HEADER_BYTES
        .checked_add(length)
        .ok_or(HttpsRouteProtocolError::PayloadTooLarge)?;
    if bytes.len() != expected {
        return Err(if bytes.len() < expected {
            HttpsRouteProtocolError::Truncated
        } else {
            HttpsRouteProtocolError::TrailingBytes
        });
    }
    let payload = &bytes[HEADER_BYTES..];
    match header[5] {
        SUBSCRIBE if payload.len() == 8 => Ok(HttpsRouteMessage::Subscribe {
            last_applied_version: u64::from_be_bytes(payload.try_into().expect("length checked")),
        }),
        CATALOG => decode_https_route_catalog(payload)
            .map(HttpsRouteMessage::Catalog)
            .map_err(HttpsRouteProtocolError::Catalog),
        UP_TO_DATE if payload.len() == 8 => HttpsRouteCatalogVersion::new(u64::from_be_bytes(
            payload.try_into().expect("length checked"),
        ))
        .map(HttpsRouteMessage::UpToDate)
        .ok_or(HttpsRouteProtocolError::InvalidPayload),
        ERROR if payload.len() == 2 => HttpsRouteServiceErrorCode::from_raw(u16::from_be_bytes(
            payload.try_into().expect("length checked"),
        ))
        .map(HttpsRouteMessage::Error)
        .ok_or(HttpsRouteProtocolError::InvalidPayload),
        SUBSCRIBE | UP_TO_DATE | ERROR => Err(HttpsRouteProtocolError::InvalidPayload),
        other => Err(HttpsRouteProtocolError::UnknownMessageType(other)),
    }
}

pub async fn read_https_route_message<R>(
    reader: &mut R,
) -> Result<HttpsRouteMessage, HttpsRouteProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(HttpsRouteProtocolError::Io)?;
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed header")) as usize;
    if length > MAX_HTTPS_ROUTE_CATALOG_BYTES {
        return Err(HttpsRouteProtocolError::PayloadTooLarge);
    }
    let mut frame = Vec::with_capacity(HEADER_BYTES + length);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_BYTES + length, 0);
    reader
        .read_exact(&mut frame[HEADER_BYTES..])
        .await
        .map_err(HttpsRouteProtocolError::Io)?;
    decode_https_route_message(&frame)
}

pub async fn write_https_route_message<W>(
    writer: &mut W,
    message: &HttpsRouteMessage,
) -> Result<(), HttpsRouteProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode_https_route_message(message)?;
    writer
        .write_all(&bytes)
        .await
        .map_err(HttpsRouteProtocolError::Io)?;
    writer.flush().await.map_err(HttpsRouteProtocolError::Io)
}

#[derive(Debug)]
pub enum HttpsRouteProtocolError {
    Io(std::io::Error),
    Catalog(HttpsRouteCodecError),
    InvalidMagic,
    UnsupportedVersion(u8),
    UnsupportedFlags,
    UnknownMessageType(u8),
    InvalidPayload,
    PayloadTooLarge,
    Truncated,
    TrailingBytes,
}

impl std::fmt::Display for HttpsRouteProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("HTTPS route protocol I/O failed"),
            Self::Catalog(error) => write!(formatter, "HTTPS route catalog is invalid: {error}"),
            Self::InvalidMagic => formatter.write_str("HTTPS route protocol magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "HTTPS route protocol version {version} is unsupported"
                )
            }
            Self::UnsupportedFlags => {
                formatter.write_str("HTTPS route protocol flags are unsupported")
            }
            Self::UnknownMessageType(kind) => {
                write!(
                    formatter,
                    "HTTPS route protocol message type {kind} is unknown"
                )
            }
            Self::InvalidPayload => formatter.write_str("HTTPS route protocol payload is invalid"),
            Self::PayloadTooLarge => {
                formatter.write_str("HTTPS route protocol payload is too large")
            }
            Self::Truncated => formatter.write_str("HTTPS route protocol frame is truncated"),
            Self::TrailingBytes => {
                formatter.write_str("HTTPS route protocol frame has trailing bytes")
            }
        }
    }
}

impl std::error::Error for HttpsRouteProtocolError {}

#[cfg(test)]
mod tests {
    use tunnelproxy_common::{PublicHostname, TunnelId};

    use super::*;
    use crate::{HttpsRouteRecord, HttpsRouteStatus};

    fn catalog() -> HttpsRouteCatalog {
        HttpsRouteCatalog::new(
            HttpsRouteCatalogVersion::new(2).unwrap(),
            vec![HttpsRouteRecord::new(
                PublicHostname::new("demo.example.test").unwrap(),
                TunnelId::new("tunnel-demo").unwrap(),
                HttpsRouteStatus::Enabled,
            )],
        )
        .unwrap()
    }

    #[test]
    fn every_message_round_trips() {
        let messages = [
            HttpsRouteMessage::Subscribe {
                last_applied_version: 0,
            },
            HttpsRouteMessage::Catalog(catalog()),
            HttpsRouteMessage::UpToDate(HttpsRouteCatalogVersion::new(2).unwrap()),
            HttpsRouteMessage::Error(HttpsRouteServiceErrorCode::ClientAhead),
        ];
        for message in messages {
            let encoded = encode_https_route_message(&message).unwrap();
            assert_eq!(decode_https_route_message(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn invalid_headers_and_lengths_fail_closed() {
        let encoded = encode_https_route_message(&HttpsRouteMessage::Catalog(catalog())).unwrap();
        let mut invalid = encoded.clone();
        invalid[0] = b'X';
        assert!(matches!(
            decode_https_route_message(&invalid),
            Err(HttpsRouteProtocolError::InvalidMagic)
        ));
        assert_eq!(
            decode_https_route_message(&encoded[..encoded.len() - 1])
                .unwrap_err()
                .to_string(),
            HttpsRouteProtocolError::Truncated.to_string()
        );
    }
}
