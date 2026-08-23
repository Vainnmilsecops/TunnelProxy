//! Protocol frame types, stream identifiers, and frame construction.
//!
//! # Stream scope
//!
//! - [`Scope::Control`] — frames used for connection setup, control, and
//!   errors. `stream_id` must be 0.
//! - [`Scope::Stream`] — frames that carry application data on a logical
//!   stream. `stream_id` must be > 0.
//!
//! The scope of a [`FrameType`] is fixed; attempting to construct a frame
//! with an inconsistent `stream_id` is a protocol error.

use crate::wire::{HEADER_SIZE, MAX_FRAME_PAYLOAD};

/// Stable numeric values for all defined frame types.
///
/// Each variant is documented with its required stream scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum FrameType {
    // --- Connection setup (control, stream_id == 0) ---
    /// Initial handshake frame sent by either side.
    ///
    /// Scope: control (`stream_id == 0`).
    #[default]
    Hello = 0x01,

    /// Agent requests tunnel registration with the edge.
    ///
    /// Scope: control (`stream_id == 0`).
    Register = 0x02,

    /// Edge confirms tunnel registration.
    ///
    /// Scope: control (`stream_id == 0`).
    Registered = 0x03,

    // --- Stream lifecycle (stream, stream_id > 0) ---
    /// Opens or acknowledges a logical stream on an established connection.
    ///
    /// Scope: stream (`stream_id > 0`).
    OpenStream = 0x10,

    /// Carries bidirectional data on an open stream.
    ///
    /// Scope: stream (`stream_id > 0`).
    Data = 0x11,

    /// Graceful directional end; the sender will emit no more DATA.
    ///
    /// Scope: stream (`stream_id > 0`).
    EndStream = 0x12,

    /// Abrupt stream termination (analogous to RST_STREAM).
    ///
    /// Scope: stream (`stream_id > 0`).
    ResetStream = 0x13,

    // --- Keepalive (control, stream_id == 0) ---
    /// Ping frame; receiver must respond with a [`FrameType::Pong`].
    ///
    /// Scope: control (`stream_id == 0`).
    Ping = 0x20,

    /// Response to a [`FrameType::Ping`] frame.
    ///
    /// Scope: control (`stream_id == 0`).
    Pong = 0x21,

    // --- Error (control, stream_id == 0) ---
    /// Conveys a protocol-level error to the peer.
    ///
    /// Scope: control (`stream_id == 0`).
    Error = 0xFF,
}

impl FrameType {
    /// Returns the required stream scope for this frame type.
    pub const fn scope(self) -> Scope {
        match self {
            // Control frames: stream_id == 0
            Self::Hello
            | Self::Register
            | Self::Registered
            | Self::Ping
            | Self::Pong
            | Self::Error => Scope::Control,

            // Stream frames: stream_id > 0
            Self::OpenStream | Self::Data | Self::EndStream | Self::ResetStream => Scope::Stream,
        }
    }

    /// Converts a raw byte to a `FrameType`.
    ///
    /// Returns `None` if the byte does not correspond to any defined variant.
    pub fn from_raw(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Register),
            0x03 => Some(Self::Registered),
            0x10 => Some(Self::OpenStream),
            0x11 => Some(Self::Data),
            0x12 => Some(Self::EndStream),
            0x13 => Some(Self::ResetStream),
            0x20 => Some(Self::Ping),
            0x21 => Some(Self::Pong),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }

    /// Returns the raw byte value for this frame type.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The required stream scope of a [`FrameType`].
///
/// Controls whether a frame must carry `stream_id == 0` (control) or
/// `stream_id > 0` (stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Control frames; `stream_id` must be 0.
    Control,
    /// Stream frames; `stream_id` must be > 0.
    Stream,
}

/// A strongly-typed stream identifier.
///
/// `StreamId(0)` represents the absence of a logical stream (control
/// frames). `StreamId(N)` where `N > 0` represents a logical stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct StreamId(pub(crate) u32);

impl StreamId {
    /// Stream ID zero — used for control-scoped frames.
    pub const CONTROL: Self = Self(0);

    /// Creates a new stream ID.
    ///
    /// Returns `None` if `id == 0`; use [`StreamId::CONTROL`] for that case.
    #[inline]
    pub const fn new(id: u32) -> Option<Self> {
        if id == 0 {
            None
        } else {
            Some(Self(id))
        }
    }

    /// Returns `true` for `stream_id == 0` (control scope).
    #[inline]
    pub const fn is_control(&self) -> bool {
        self.0 == 0
    }

    /// Returns the raw `u32` value.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for StreamId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<StreamId> for u32 {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

/// A complete, validated protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Which kind of frame this is.
    pub frame_type: FrameType,
    /// Flags for this frame. Must be zero in protocol v2.
    pub flags: u16,
    /// Stream identifier (0 = control, >0 = stream).
    pub stream_id: StreamId,
    /// Arbitrary binary payload. May be empty.
    pub payload: Vec<u8>,
}

impl Frame {
    /// The fixed wire header size in bytes.
    pub const WIRE_HEADER_SIZE: u32 = HEADER_SIZE;

    /// The maximum wire frame size (header + max payload).
    pub const MAX_WIRE_SIZE: u32 = HEADER_SIZE + MAX_FRAME_PAYLOAD;

    /// Constructs a new frame after validating the payload size and
    /// stream scope.
    ///
    /// Returns `Err` if:
    /// - `payload.len() > MAX_FRAME_PAYLOAD`
    /// - `stream_id` is inconsistent with `frame_type.scope()`
    /// - `flags != 0` (v1 has no defined flags)
    pub fn new(
        frame_type: FrameType,
        flags: u16,
        stream_id: StreamId,
        payload: Vec<u8>,
    ) -> Result<Self, crate::ProtocolError> {
        // Validate flags.
        if flags != 0 {
            return Err(crate::ProtocolError::UnsupportedFlags(flags));
        }

        // Validate payload size.
        let len = u32::try_from(payload.len())
            .map_err(|_| crate::ProtocolError::EncodeFrameTooLarge(u32::MAX))?;
        if len > MAX_FRAME_PAYLOAD {
            return Err(crate::ProtocolError::EncodeFrameTooLarge(len));
        }

        // Validate stream scope.
        Self::validate_scope(frame_type, stream_id)?;

        Ok(Self {
            frame_type,
            flags,
            stream_id,
            payload,
        })
    }

    /// Convenience: constructs a control frame (`stream_id == 0`).
    pub fn control(frame_type: FrameType, payload: Vec<u8>) -> Result<Self, crate::ProtocolError> {
        Self::new(frame_type, 0, StreamId::CONTROL, payload)
    }

    /// Convenience: constructs a stream frame (`stream_id > 0`).
    pub fn stream(
        stream_id: StreamId,
        frame_type: FrameType,
        payload: Vec<u8>,
    ) -> Result<Self, crate::ProtocolError> {
        Self::new(frame_type, 0, stream_id, payload)
    }

    /// Returns `true` if this frame is control-scoped.
    #[inline]
    pub fn is_control(&self) -> bool {
        self.stream_id.is_control()
    }

    /// Returns `true` if this frame is stream-scoped.
    #[inline]
    pub fn is_stream(&self) -> bool {
        !self.stream_id.is_control()
    }

    fn validate_scope(
        frame_type: FrameType,
        stream_id: StreamId,
    ) -> Result<(), crate::ProtocolError> {
        match frame_type.scope() {
            Scope::Control => {
                if !stream_id.is_control() {
                    return Err(crate::ProtocolError::InvalidStreamScope {
                        frame_type,
                        required: "0 (control)",
                        got: stream_id.get(),
                    });
                }
            }
            Scope::Stream => {
                if stream_id.is_control() {
                    return Err(crate::ProtocolError::InvalidStreamScope {
                        frame_type,
                        required: "> 0 (stream)",
                        got: stream_id.get(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_is_control() {
        let control = StreamId::CONTROL;
        assert!(control.is_control());
        assert_eq!(control.get(), 0);

        let stream = StreamId::new(42).unwrap();
        assert!(!stream.is_control());
        assert_eq!(stream.get(), 42);

        assert!(StreamId::new(0).is_none());
    }

    #[test]
    fn frame_type_scope() {
        assert_eq!(FrameType::Hello.scope(), Scope::Control);
        assert_eq!(FrameType::Register.scope(), Scope::Control);
        assert_eq!(FrameType::Registered.scope(), Scope::Control);
        assert_eq!(FrameType::Ping.scope(), Scope::Control);
        assert_eq!(FrameType::Pong.scope(), Scope::Control);
        assert_eq!(FrameType::Error.scope(), Scope::Control);

        assert_eq!(FrameType::OpenStream.scope(), Scope::Stream);
        assert_eq!(FrameType::Data.scope(), Scope::Stream);
        assert_eq!(FrameType::EndStream.scope(), Scope::Stream);
        assert_eq!(FrameType::ResetStream.scope(), Scope::Stream);
    }

    #[test]
    fn frame_type_from_raw() {
        assert_eq!(FrameType::from_raw(0x01), Some(FrameType::Hello));
        assert_eq!(FrameType::from_raw(0x02), Some(FrameType::Register));
        assert_eq!(FrameType::from_raw(0x03), Some(FrameType::Registered));
        assert_eq!(FrameType::from_raw(0x10), Some(FrameType::OpenStream));
        assert_eq!(FrameType::from_raw(0x11), Some(FrameType::Data));
        assert_eq!(FrameType::from_raw(0x12), Some(FrameType::EndStream));
        assert_eq!(FrameType::from_raw(0x13), Some(FrameType::ResetStream));
        assert_eq!(FrameType::from_raw(0x20), Some(FrameType::Ping));
        assert_eq!(FrameType::from_raw(0x21), Some(FrameType::Pong));
        assert_eq!(FrameType::from_raw(0xFF), Some(FrameType::Error));

        assert_eq!(FrameType::from_raw(0x00), None);
        assert_eq!(FrameType::from_raw(0x99), None);
        assert_eq!(FrameType::from_raw(0xFE), None);
    }

    #[test]
    fn frame_control_scope_validation() {
        // Control frames accept stream_id == 0.
        assert!(Frame::control(FrameType::Hello, vec![]).is_ok());
        assert!(Frame::control(FrameType::Ping, b"ping".to_vec()).is_ok());
        assert!(Frame::control(FrameType::Error, vec![]).is_ok());

        // Control frames reject stream_id > 0.
        let stream_id = StreamId::new(1).unwrap();
        assert!(Frame::new(FrameType::Hello, 0, stream_id, vec![]).is_err());
        assert!(Frame::new(FrameType::Ping, 0, stream_id, vec![]).is_err());
    }

    #[test]
    fn frame_stream_scope_validation() {
        let stream_id = StreamId::new(1).unwrap();

        // Stream frames accept stream_id > 0.
        assert!(Frame::stream(stream_id, FrameType::OpenStream, vec![]).is_ok());
        assert!(Frame::stream(stream_id, FrameType::Data, b"hello".to_vec()).is_ok());
        assert!(Frame::stream(stream_id, FrameType::EndStream, vec![]).is_ok());

        // Stream frames reject stream_id == 0.
        assert!(Frame::stream(StreamId::CONTROL, FrameType::Data, vec![]).is_err());
        assert!(Frame::stream(StreamId::CONTROL, FrameType::OpenStream, vec![]).is_err());
    }

    #[test]
    fn frame_rejects_non_zero_flags() {
        let stream_id = StreamId::new(1).unwrap();
        assert!(Frame::new(FrameType::Data, 0x0001, stream_id, vec![]).is_err());
        assert!(Frame::new(FrameType::Data, 0x8000, stream_id, vec![]).is_err());
    }

    #[test]
    fn frame_rejects_oversized_payload() {
        let stream_id = StreamId::new(1).unwrap();
        let oversized = vec![0u8; (MAX_FRAME_PAYLOAD + 1) as usize];
        assert!(Frame::new(FrameType::Data, 0, stream_id, oversized).is_err());
    }

    #[test]
    fn frame_max_payload_is_exactly_64kib() {
        let stream_id = StreamId::new(1).unwrap();
        let exactly_64k: Vec<u8> = vec![0u8; MAX_FRAME_PAYLOAD as usize];
        assert!(Frame::new(FrameType::Data, 0, stream_id, exactly_64k).is_ok());
    }
}
