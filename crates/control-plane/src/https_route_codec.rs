//! Canonical bounded encoding for complete HTTPS route catalogs.

use tunnelproxy_common::{PublicHostname, TunnelId};

use crate::{
    HttpsRouteCatalog, HttpsRouteCatalogVersion, HttpsRouteRecord, HttpsRouteStatus,
    MAX_HTTPS_ROUTE_RECORDS,
};

pub const MAX_HTTPS_ROUTE_CATALOG_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 10;

pub fn encode_https_route_catalog(
    catalog: &HttpsRouteCatalog,
) -> Result<Vec<u8>, HttpsRouteCodecError> {
    let count =
        u16::try_from(catalog.routes().len()).map_err(|_| HttpsRouteCodecError::TooManyRoutes)?;
    let mut output = Vec::with_capacity(HEADER_BYTES + catalog.routes().len() * 64);
    output.extend_from_slice(&catalog.version().get().to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for route in catalog.routes() {
        put_string(&mut output, route.hostname.as_str())?;
        put_string(&mut output, route.tunnel_id.as_str())?;
        output.push(match route.status {
            HttpsRouteStatus::Enabled => 1,
            HttpsRouteStatus::Disabled => 2,
        });
    }
    if output.len() > MAX_HTTPS_ROUTE_CATALOG_BYTES {
        return Err(HttpsRouteCodecError::TooLarge);
    }
    Ok(output)
}

pub fn decode_https_route_catalog(bytes: &[u8]) -> Result<HttpsRouteCatalog, HttpsRouteCodecError> {
    if bytes.len() > MAX_HTTPS_ROUTE_CATALOG_BYTES {
        return Err(HttpsRouteCodecError::TooLarge);
    }
    let mut input = Input::new(bytes);
    let version =
        HttpsRouteCatalogVersion::new(input.u64()?).ok_or(HttpsRouteCodecError::InvalidVersion)?;
    let count = usize::from(input.u16()?);
    if count > MAX_HTTPS_ROUTE_RECORDS {
        return Err(HttpsRouteCodecError::TooManyRoutes);
    }
    let mut routes = Vec::with_capacity(count);
    let mut previous: Option<PublicHostname> = None;
    for _ in 0..count {
        let raw_hostname = input.string()?;
        let hostname = PublicHostname::new(&raw_hostname)
            .map_err(|_| HttpsRouteCodecError::InvalidHostname)?;
        if hostname.as_str() != raw_hostname {
            return Err(HttpsRouteCodecError::NonCanonical);
        }
        if previous.as_ref().is_some_and(|value| value >= &hostname) {
            return Err(HttpsRouteCodecError::NonCanonical);
        }
        previous = Some(hostname.clone());
        let tunnel_id =
            TunnelId::new(input.string()?).map_err(|_| HttpsRouteCodecError::InvalidTunnelId)?;
        let status = match input.u8()? {
            1 => HttpsRouteStatus::Enabled,
            2 => HttpsRouteStatus::Disabled,
            _ => return Err(HttpsRouteCodecError::InvalidStatus),
        };
        routes.push(HttpsRouteRecord::new(hostname, tunnel_id, status));
    }
    if !input.is_empty() {
        return Err(HttpsRouteCodecError::TrailingBytes);
    }
    HttpsRouteCatalog::new(version, routes).map_err(|_| HttpsRouteCodecError::NonCanonical)
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), HttpsRouteCodecError> {
    let length = u16::try_from(value.len()).map_err(|_| HttpsRouteCodecError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], HttpsRouteCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(HttpsRouteCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(HttpsRouteCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, HttpsRouteCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, HttpsRouteCodecError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("length checked"),
        ))
    }

    fn u64(&mut self) -> Result<u64, HttpsRouteCodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("length checked"),
        ))
    }

    fn string(&mut self) -> Result<String, HttpsRouteCodecError> {
        let length = usize::from(self.u16()?);
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| HttpsRouteCodecError::InvalidUtf8)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsRouteCodecError {
    TooLarge,
    TooManyRoutes,
    Truncated,
    TrailingBytes,
    InvalidUtf8,
    InvalidVersion,
    InvalidHostname,
    InvalidTunnelId,
    InvalidStatus,
    NonCanonical,
}

impl std::fmt::Display for HttpsRouteCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "HTTPS route catalog payload is too large",
            Self::TooManyRoutes => "HTTPS route catalog contains too many routes",
            Self::Truncated => "HTTPS route catalog payload is truncated",
            Self::TrailingBytes => "HTTPS route catalog payload has trailing bytes",
            Self::InvalidUtf8 => "HTTPS route catalog contains invalid UTF-8",
            Self::InvalidVersion => "HTTPS route catalog version is invalid",
            Self::InvalidHostname => "HTTPS route catalog hostname is invalid",
            Self::InvalidTunnelId => "HTTPS route catalog TunnelId is invalid",
            Self::InvalidStatus => "HTTPS route catalog status is invalid",
            Self::NonCanonical => "HTTPS route catalog payload is not canonical",
        })
    }
}

impl std::error::Error for HttpsRouteCodecError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> HttpsRouteCatalog {
        HttpsRouteCatalog::new(
            HttpsRouteCatalogVersion::new(7).unwrap(),
            vec![
                HttpsRouteRecord::new(
                    PublicHostname::new("b.example.test").unwrap(),
                    TunnelId::new("tunnel-b").unwrap(),
                    HttpsRouteStatus::Disabled,
                ),
                HttpsRouteRecord::new(
                    PublicHostname::new("a.example.test").unwrap(),
                    TunnelId::new("tunnel-a").unwrap(),
                    HttpsRouteStatus::Enabled,
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn catalog_round_trips_in_canonical_order() {
        let catalog = catalog();
        let encoded = encode_https_route_catalog(&catalog).unwrap();
        assert_eq!(decode_https_route_catalog(&encoded).unwrap(), catalog);
        assert_eq!(catalog.routes()[0].hostname.as_str(), "a.example.test");
    }

    #[test]
    fn malformed_and_noncanonical_payloads_fail_closed() {
        let encoded = encode_https_route_catalog(&catalog()).unwrap();
        assert_eq!(
            decode_https_route_catalog(&encoded[..encoded.len() - 1]),
            Err(HttpsRouteCodecError::Truncated)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_https_route_catalog(&trailing),
            Err(HttpsRouteCodecError::TrailingBytes)
        );
        let mut zero_version = encoded;
        zero_version[..8].fill(0);
        assert_eq!(
            decode_https_route_catalog(&zero_version),
            Err(HttpsRouteCodecError::InvalidVersion)
        );
    }
}
