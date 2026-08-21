//! Fixed wire-format constants for Tunnel Protocol v1.

/// Magic bytes that must appear at the start of every valid frame.
///
/// Encoded as `0x54 0x50 0x58 0x31` — the ASCII string `"TPX1"`.
pub const MAGIC: [u8; 4] = [0x54, 0x50, 0x58, 0x31];

/// Fixed header size in bytes.
pub const HEADER_SIZE: u32 = 16;

/// Supported protocol version.
pub const VERSION: u8 = 1;

/// Maximum allowed payload size in bytes (64 KiB).
pub const MAX_FRAME_PAYLOAD: u32 = 64 * 1024;
