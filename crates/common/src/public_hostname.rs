//! Canonical public DNS hostname shared by Control Plane and Edge.

use std::net::IpAddr;

pub const MAX_PUBLIC_HOSTNAME_BYTES: usize = 253;
pub const MAX_DNS_LABEL_BYTES: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicHostname(String);

impl PublicHostname {
    pub fn new(value: impl AsRef<str>) -> Result<Self, PublicHostnameError> {
        normalize_dns_hostname(value.as_ref()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PublicHostname {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicHostnameError {
    Empty,
    TooLong,
    InvalidLabel,
    IpAddress,
    PortNotAllowed,
}

impl std::fmt::Display for PublicHostnameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "public hostname must not be empty",
            Self::TooLong => "public hostname exceeds 253 bytes",
            Self::InvalidLabel => "public hostname contains an invalid DNS label",
            Self::IpAddress => "public hostname must be a DNS name, not an IP address",
            Self::PortNotAllowed => "public hostname must not contain a port",
        })
    }
}

impl std::error::Error for PublicHostnameError {}

fn normalize_dns_hostname(value: &str) -> Result<String, PublicHostnameError> {
    if value.is_empty() {
        return Err(PublicHostnameError::Empty);
    }
    let normalized = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PublicHostnameError::Empty);
    }
    if normalized.parse::<IpAddr>().is_ok() {
        return Err(PublicHostnameError::IpAddress);
    }
    if normalized.contains(':') {
        return Err(PublicHostnameError::PortNotAllowed);
    }
    if normalized.len() > MAX_PUBLIC_HOSTNAME_BYTES {
        return Err(PublicHostnameError::TooLong);
    }
    if normalized.split('.').any(|label| {
        label.is_empty()
            || label.len() > MAX_DNS_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(PublicHostnameError::InvalidLabel);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_canonical_and_exact() {
        assert_eq!(
            PublicHostname::new("Demo.Example.COM.").unwrap().as_str(),
            "demo.example.com"
        );
        assert_ne!(
            PublicHostname::new("demo.example.com").unwrap(),
            PublicHostname::new("other.example.com").unwrap()
        );
    }

    #[test]
    fn hostname_rejects_non_dns_and_unsafe_forms() {
        for (value, expected) in [
            ("", PublicHostnameError::Empty),
            (".", PublicHostnameError::Empty),
            ("127.0.0.1", PublicHostnameError::IpAddress),
            ("127.0.0.1.", PublicHostnameError::IpAddress),
            ("example.com:443", PublicHostnameError::PortNotAllowed),
            ("*.example.com", PublicHostnameError::InvalidLabel),
            ("bad_label.example", PublicHostnameError::InvalidLabel),
            ("-bad.example", PublicHostnameError::InvalidLabel),
            ("bad-.example", PublicHostnameError::InvalidLabel),
            ("café.example", PublicHostnameError::InvalidLabel),
        ] {
            assert_eq!(PublicHostname::new(value), Err(expected));
        }
    }

    #[test]
    fn hostname_bounds_labels_and_total_length() {
        let label = "a".repeat(MAX_DNS_LABEL_BYTES);
        assert!(PublicHostname::new(format!("{label}.example")).is_ok());
        assert_eq!(
            PublicHostname::new(format!("{}a.example", label)),
            Err(PublicHostnameError::InvalidLabel)
        );
        assert_eq!(
            PublicHostname::new(format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(63)
            )),
            Err(PublicHostnameError::TooLong)
        );
    }
}
