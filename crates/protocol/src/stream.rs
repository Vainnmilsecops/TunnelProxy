//! Stream-lifecycle payload types for Tunnel Protocol v1.

use std::fmt;

/// Error codes carried by a `RESET_STREAM` payload.
///
/// The payload is exactly one big-endian `u16`. Codes intentionally describe
/// categories rather than operating-system details so peers do not leak local
/// paths, addresses, or platform-specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StreamResetCode {
    /// Agent could not connect to its configured local service.
    LocalConnectFailed = 1,
    /// Agent's local-service connection deadline expired.
    LocalConnectTimeout = 2,
    /// An I/O failure interrupted an active stream.
    IoFailure = 3,
    /// A peer violated the stream lifecycle or payload contract.
    ProtocolViolation = 4,
    /// A second stream was requested while one was already active.
    StreamBusy = 5,
    /// Edge did not receive the stream-open acknowledgment in time.
    OpenTimeout = 6,
    /// Neither data direction made progress before the stream idle deadline.
    IdleTimeout = 7,
}

impl StreamResetCode {
    /// Encodes the reset code as two big-endian bytes.
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    /// Decodes a reset code, returning `None` for unknown values.
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Option<Self> {
        match u16::from_be_bytes(bytes) {
            1 => Some(Self::LocalConnectFailed),
            2 => Some(Self::LocalConnectTimeout),
            3 => Some(Self::IoFailure),
            4 => Some(Self::ProtocolViolation),
            5 => Some(Self::StreamBusy),
            6 => Some(Self::OpenTimeout),
            7 => Some(Self::IdleTimeout),
            _ => None,
        }
    }

    /// Returns the stable wire value.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for StreamResetCode {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_be_bytes(value.to_be_bytes()).ok_or(())
    }
}

impl fmt::Display for StreamResetCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::LocalConnectFailed => "local_connect_failed",
            Self::LocalConnectTimeout => "local_connect_timeout",
            Self::IoFailure => "io_failure",
            Self::ProtocolViolation => "protocol_violation",
            Self::StreamBusy => "stream_busy",
            Self::OpenTimeout => "open_timeout",
            Self::IdleTimeout => "idle_timeout",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_reset_codes_roundtrip() {
        for code in [
            StreamResetCode::LocalConnectFailed,
            StreamResetCode::LocalConnectTimeout,
            StreamResetCode::IoFailure,
            StreamResetCode::ProtocolViolation,
            StreamResetCode::StreamBusy,
            StreamResetCode::OpenTimeout,
            StreamResetCode::IdleTimeout,
        ] {
            assert_eq!(
                StreamResetCode::from_be_bytes(code.to_be_bytes()),
                Some(code)
            );
            assert_eq!(StreamResetCode::try_from(code.as_u16()), Ok(code));
        }
    }

    #[test]
    fn unknown_stream_reset_code_is_rejected() {
        assert_eq!(StreamResetCode::from_be_bytes([0, 0]), None);
        assert_eq!(StreamResetCode::try_from(99), Err(()));
    }
}
