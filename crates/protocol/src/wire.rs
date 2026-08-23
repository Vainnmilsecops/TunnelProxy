//! Fixed wire-format constants for Tunnel Protocol v2.

/// Magic bytes that must appear at the start of every valid frame.
///
/// Encoded as `0x54 0x50 0x58 0x31` — the ASCII string `"TPX1"`.
pub const MAGIC: [u8; 4] = [0x54, 0x50, 0x58, 0x31];

/// Fixed header size in bytes.
pub const HEADER_SIZE: u32 = 16;

/// Supported protocol version.
pub const PROTOCOL_VERSION: u8 = 2;

/// Backwards-compatible constant name used by the codec.
pub const VERSION: u8 = PROTOCOL_VERSION;

/// Maximum allowed payload size in bytes (64 KiB).
pub const MAX_FRAME_PAYLOAD: u32 = 64 * 1024;

// ---------------------------------------------------------------------------
// Handshake payload sizes
// ---------------------------------------------------------------------------

/// Exact byte length of a [`FrameType::Hello`] payload (1 byte: role).
pub const HELLO_PAYLOAD_SIZE: u32 = 1;

/// Exact byte length of a [`FrameType::Registered`] payload (8 bytes: session ID).
pub const REGISTERED_PAYLOAD_SIZE: u32 = 8;

/// Exact byte length of an ERROR frame payload (2 bytes: error code).
pub const ERROR_PAYLOAD_SIZE: u32 = 2;

/// Exact byte length of a PING or PONG payload (8 bytes: heartbeat sequence).
pub const HEARTBEAT_PAYLOAD_SIZE: u32 = 8;

/// Exact byte length of OPEN_STREAM and END_STREAM payloads.
pub const EMPTY_STREAM_PAYLOAD_SIZE: u32 = 0;

/// Exact byte length of a RESET_STREAM payload (2 bytes: reset code).
pub const STREAM_RESET_PAYLOAD_SIZE: u32 = 2;
