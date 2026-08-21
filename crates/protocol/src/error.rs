//! Typed protocol error taxonomy.
//!
//! Every variant is distinct so callers and tests can match on the exact
//! failure class without ambiguity.

use thiserror::Error;

/// Protocol-level errors that can occur while encoding or decoding frames.
///
/// These are distinct from I/O errors (e.g. connection reset) which are
/// reported separately by the underlying `AsyncRead`/`AsyncWrite`.
#[derive(Debug, Error)]
pub enum ProtocolError {
    // --- I/O ---
    /// The underlying stream returned an I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // --- Wire format ---
    /// Frame header magic bytes do not match `MAGIC`.
    #[error("invalid magic: expected TPX1, got {0:?}")]
    InvalidMagic([u8; 4]),

    /// Protocol version byte is not supported.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// Frame type byte does not match any defined variant.
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u8),

    /// Non-zero flags value on a v1 frame.
    #[error("unsupported flags: 0x{0:04x}")]
    UnsupportedFlags(u16),

    // --- Frame structure ---
    /// `stream_id == 0` on a stream-scoped frame, or `stream_id > 0`
    /// on a control-scoped frame.
    #[error(
        "invalid stream scope: frame type {frame_type:?} requires stream_id {required}, got {got}"
    )]
    InvalidStreamScope {
        frame_type: super::FrameType,
        required: &'static str,
        got: u32,
    },

    /// Announced payload length exceeds [`MAX_FRAME_PAYLOAD`][super::wire::MAX_FRAME_PAYLOAD].
    #[error("frame too large: payload length {0} exceeds maximum {max} bytes", max = super::wire::MAX_FRAME_PAYLOAD)]
    FrameTooLarge(u32),

    /// Received fewer than [`HEADER_SIZE`][super::wire::HEADER_SIZE] bytes
    /// before EOF — a truncated header.
    #[error("truncated header: got {got} bytes, expected {expected}", expected = super::wire::HEADER_SIZE)]
    TruncatedHeader { got: usize },

    /// Received a complete header but fewer payload bytes than announced
    /// before EOF.
    #[error("truncated payload: got {got} bytes, expected {expected}")]
    TruncatedPayload { got: usize, expected: usize },

    // --- Encoding ---
    /// Attempted to encode a frame whose payload exceeds [`MAX_FRAME_PAYLOAD`][super::wire::MAX_FRAME_PAYLOAD].
    #[error("frame too large for encoding: payload {0} bytes exceeds maximum {max} bytes", max = super::wire::MAX_FRAME_PAYLOAD)]
    EncodeFrameTooLarge(u32),

    /// Attempted to encode a frame with an invalid stream scope combination.
    #[error("encode validation failed: {0}")]
    EncodeValidation(String),
}
