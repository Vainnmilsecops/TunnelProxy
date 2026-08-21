//! Handshake-level types for Tunnel Protocol v1.
//!
//! These types define the binary structure of handshake frame payloads
//! (HELLO, REGISTERED, ERROR) without encoding any domain-specific
//! semantics.

use std::fmt;

/// Byte assigned to the AGENT role in a HELLO frame payload.
pub const ROLE_AGENT: u8 = 0x01;

/// The role advertised in a HELLO frame payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloRole {
    /// The HELLO is sent by a TunnelProxy Agent.
    Agent,
}

impl HelloRole {
    /// Decodes a role byte from a HELLO frame payload.
    ///
    /// Returns `None` if the byte is not a defined role.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            ROLE_AGENT => Some(Self::Agent),
            _ => None,
        }
    }

    /// Returns the wire byte value for this role.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Agent => ROLE_AGENT,
        }
    }
}

impl TryFrom<u8> for HelloRole {
    type Error = ();
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_byte(byte).ok_or(())
    }
}

// ---------------------------------------------------------------------------
// TransportSessionId
// ---------------------------------------------------------------------------

/// A process-local, ephemeral session identifier allocated by Edge
/// upon successful completion of the protocol handshake.
///
/// `TransportSessionId` is **not** a `TunnelId`, `AgentId`, or any
/// durable identity. It is a lightweight handle for tracking an
/// established Agent ↔ Edge transport session within the Edge process
/// for the duration of that TCP connection.
///
/// Properties:
/// - Zero is reserved / invalid.
/// - IDs are monotonically increasing (via `AtomicU64` on Edge).
/// - Edge allocates IDs with checked atomic addition and returns `None` on
///   exhaustion rather than wrapping or silently reusing an ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportSessionId(u64);

impl TransportSessionId {
    /// The zero / invalid session ID. No valid session has this value.
    pub const INVALID: Self = Self(0);

    /// Attempts to construct a `TransportSessionId` from a raw `u64`.
    ///
    /// Returns `None` if the value is zero.
    #[inline]
    pub fn new(id: u64) -> Option<Self> {
        if id == 0 {
            None
        } else {
            Some(Self(id))
        }
    }

    /// Returns `true` if this is the invalid / zero session ID.
    #[inline]
    pub const fn is_invalid(&self) -> bool {
        self.0 == 0
    }

    /// Returns the raw `u64` value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Encodes the session ID as 8 big-endian bytes, suitable for the
    /// REGISTERED frame payload.
    #[inline]
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Decodes an 8-byte big-endian REGISTERED payload into a
    /// `TransportSessionId`.
    ///
    /// Returns `None` if the bytes decode to zero.
    pub fn from_be_bytes(bytes: [u8; 8]) -> Option<Self> {
        let id = u64::from_be_bytes(bytes);
        Self::new(id)
    }
}

impl From<u64> for TransportSessionId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<TransportSessionId> for u64 {
    fn from(id: TransportSessionId) -> Self {
        id.0
    }
}

impl fmt::Display for TransportSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Handshake error codes
// ---------------------------------------------------------------------------

/// Error codes transmitted in ERROR frame payloads during handshake
/// violations.
///
/// The error code is a 2-byte big-endian unsigned integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HandshakeErrorCode {
    /// The received frame was not expected at this point in the
    /// handshake sequence.
    UnexpectedFrame = 1,
    /// The HELLO frame had an invalid payload (wrong size or unknown role).
    InvalidHello = 2,
    /// The REGISTER frame had an invalid payload (non-empty in v1).
    InvalidRegister = 3,
    /// A general protocol violation detected during the handshake.
    ProtocolViolation = 4,
}

impl HandshakeErrorCode {
    /// Encodes the error code as 2 big-endian bytes.
    #[inline]
    pub fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    /// Decodes a 2-byte big-endian ERROR payload into a
    /// `HandshakeErrorCode`.
    ///
    /// Returns `None` if the code is not a defined variant.
    pub fn from_be_bytes(bytes: [u8; 2]) -> Option<Self> {
        let code = u16::from_be_bytes(bytes);
        match code {
            1 => Some(Self::UnexpectedFrame),
            2 => Some(Self::InvalidHello),
            3 => Some(Self::InvalidRegister),
            4 => Some(Self::ProtocolViolation),
            _ => None,
        }
    }

    /// Returns the raw `u16` value.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for HandshakeErrorCode {
    type Error = ();
    fn try_from(code: u16) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(Self::UnexpectedFrame),
            2 => Ok(Self::InvalidHello),
            3 => Ok(Self::InvalidRegister),
            4 => Ok(Self::ProtocolViolation),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// HeartbeatSequence
// ---------------------------------------------------------------------------

/// A strictly positive sequence number used in PING/PONG heartbeat frames.
///
/// `HeartbeatSequence` is encoded as an 8-byte big-endian unsigned integer
/// in the PING and PONG frame payloads.
///
/// Properties:
/// - Zero is reserved / invalid.
/// - [`checked_next`](Self::checked_next) returns `None` rather than wrapping
///   to zero after `u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeartbeatSequence(u64);

impl HeartbeatSequence {
    /// The zero / invalid sequence. No valid heartbeat has this value.
    pub const INVALID: Self = Self(0);

    /// The first valid sequence number.
    pub const FIRST: Self = Self(1);

    /// Attempts to construct a `HeartbeatSequence` from a raw `u64`.
    ///
    /// Returns `None` if the value is zero.
    #[inline]
    pub fn new(seq: u64) -> Option<Self> {
        if seq == 0 {
            None
        } else {
            Some(Self(seq))
        }
    }

    /// Returns `true` if this is the invalid / zero sequence.
    #[inline]
    pub const fn is_invalid(&self) -> bool {
        self.0 == 0
    }

    /// Returns the raw `u64` value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Encodes the sequence as 8 big-endian bytes.
    #[inline]
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Decodes 8 big-endian bytes into a `HeartbeatSequence`.
    ///
    /// Returns `None` if the bytes decode to zero.
    #[inline]
    pub fn from_be_bytes(bytes: [u8; 8]) -> Option<Self> {
        let seq = u64::from_be_bytes(bytes);
        Self::new(seq)
    }

    /// Returns the next sequence, or `None` instead of wrapping at `u64::MAX`.
    #[inline]
    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).and_then(Self::new)
    }
}

impl fmt::Display for HeartbeatSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Heartbeat error codes
// ---------------------------------------------------------------------------

/// Error codes transmitted in ERROR frame payloads during established-session
/// heartbeat violations.
///
/// Distinct from `HandshakeErrorCode` — these apply after REGISTERED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HeartbeatErrorCode {
    /// No PONG was received before the heartbeat deadline expired.
    HeartbeatTimeout = 1,
    /// Received a PONG with a sequence that does not match the outstanding PING.
    HeartbeatSequenceMismatch = 2,
    /// Received a PONG when no PING was outstanding.
    UnsolicitedPong = 3,
    /// Received a PING from the Agent (not supported in Session 07).
    AgentPingNotSupported = 4,
    /// PING or PONG payload was not exactly one non-zero 8-byte sequence.
    InvalidHeartbeatPayload = 5,
    /// A frame was received in a control-session state where it is not allowed.
    UnexpectedFrame = 6,
}

impl HeartbeatErrorCode {
    /// Encodes the error code as 2 big-endian bytes.
    #[inline]
    pub fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    /// Decodes a 2-byte big-endian ERROR payload into a `HeartbeatErrorCode`.
    ///
    /// Returns `None` if the code is not a defined variant.
    pub fn from_be_bytes(bytes: [u8; 2]) -> Option<Self> {
        let code = u16::from_be_bytes(bytes);
        match code {
            1 => Some(Self::HeartbeatTimeout),
            2 => Some(Self::HeartbeatSequenceMismatch),
            3 => Some(Self::UnsolicitedPong),
            4 => Some(Self::AgentPingNotSupported),
            5 => Some(Self::InvalidHeartbeatPayload),
            6 => Some(Self::UnexpectedFrame),
            _ => None,
        }
    }

    /// Returns the raw `u16` value.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for HeartbeatErrorCode {
    type Error = ();
    fn try_from(code: u16) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(Self::HeartbeatTimeout),
            2 => Ok(Self::HeartbeatSequenceMismatch),
            3 => Ok(Self::UnsolicitedPong),
            4 => Ok(Self::AgentPingNotSupported),
            5 => Ok(Self::InvalidHeartbeatPayload),
            6 => Ok(Self::UnexpectedFrame),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_role_roundtrip() {
        assert_eq!(HelloRole::from_byte(ROLE_AGENT), Some(HelloRole::Agent));
        assert_eq!(HelloRole::from_byte(0x99), None);
        assert_eq!(HelloRole::Agent.as_u8(), ROLE_AGENT);
    }

    #[test]
    fn transport_session_id_validity() {
        assert!(TransportSessionId::INVALID.is_invalid());
        assert_eq!(TransportSessionId::INVALID.get(), 0);

        let sid = TransportSessionId::new(42).unwrap();
        assert!(!sid.is_invalid());
        assert_eq!(sid.get(), 42);

        assert!(TransportSessionId::new(0).is_none());
    }

    #[test]
    fn transport_session_id_be_bytes() {
        // Test a known value.
        let sid = TransportSessionId::new(0x01_02_03_04_05_06_07_08).unwrap();
        let expected: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(sid.to_be_bytes(), expected);
        let sid2 = TransportSessionId::from_be_bytes(sid.to_be_bytes()).unwrap();
        assert_eq!(sid, sid2);

        // Zero roundtrips to None.
        assert!(TransportSessionId::from_be_bytes([0u8; 8]).is_none());
    }

    #[test]
    fn handshake_error_code_roundtrip() {
        for code in [
            HandshakeErrorCode::UnexpectedFrame,
            HandshakeErrorCode::InvalidHello,
            HandshakeErrorCode::InvalidRegister,
            HandshakeErrorCode::ProtocolViolation,
        ] {
            let bytes = code.to_be_bytes();
            assert_eq!(HandshakeErrorCode::from_be_bytes(bytes), Some(code));
        }

        // Unknown code.
        assert!(HandshakeErrorCode::from_be_bytes([0x00, 0x99]).is_none());
    }

    #[test]
    fn heartbeat_sequence_rejects_zero() {
        assert!(HeartbeatSequence::INVALID.is_invalid());
        assert!(HeartbeatSequence::new(0).is_none());
        assert!(HeartbeatSequence::from_be_bytes([0; 8]).is_none());
        assert_eq!(HeartbeatSequence::FIRST.get(), 1);
    }

    #[test]
    fn heartbeat_sequence_roundtrips_big_endian() {
        let sequence = HeartbeatSequence::new(0x01_02_03_04_05_06_07_08).unwrap();
        assert_eq!(
            sequence.to_be_bytes(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            HeartbeatSequence::from_be_bytes(sequence.to_be_bytes()),
            Some(sequence)
        );
        assert_eq!(sequence.to_string(), "seq#72623859790382856");
    }

    #[test]
    fn heartbeat_sequence_checked_next_does_not_wrap() {
        assert_eq!(
            HeartbeatSequence::FIRST.checked_next(),
            HeartbeatSequence::new(2)
        );
        assert!(HeartbeatSequence::new(u64::MAX)
            .unwrap()
            .checked_next()
            .is_none());
    }

    #[test]
    fn heartbeat_error_code_roundtrip() {
        for code in [
            HeartbeatErrorCode::HeartbeatTimeout,
            HeartbeatErrorCode::HeartbeatSequenceMismatch,
            HeartbeatErrorCode::UnsolicitedPong,
            HeartbeatErrorCode::AgentPingNotSupported,
            HeartbeatErrorCode::InvalidHeartbeatPayload,
            HeartbeatErrorCode::UnexpectedFrame,
        ] {
            assert_eq!(
                HeartbeatErrorCode::from_be_bytes(code.to_be_bytes()),
                Some(code)
            );
            assert_eq!(HeartbeatErrorCode::try_from(code.as_u16()), Ok(code));
        }
        assert!(HeartbeatErrorCode::from_be_bytes([0x00, 0x99]).is_none());
    }
}
