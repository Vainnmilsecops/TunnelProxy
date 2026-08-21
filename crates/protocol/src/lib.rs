//! `tunnelproxy-protocol`
//!
//! Wire protocol types and codecs spoken between
//! [`tunnelproxy-edge`] and [`tunnelproxy-agent`].
//!
//! # Wire Format
//!
//! Every frame begins with a fixed 16-byte header followed by a bounded
//! payload (max 64 KiB):
//!
//! ```text
//! Offset  Size  Field           Type
//! 0       4     Magic           [0x54, 0x50, 0x58, 0x31] ("TPX1")
//! 4       1     Version         u8  (1)
//! 5       1     Frame Type      u8
//! 6       2     Flags           u16 (big-endian)
//! 8       4     Stream ID       u32 (big-endian)
//! 12      4     Payload Length  u32 (big-endian)
//! 16      N     Payload         [u8; N]
//! ```
//!
//! All multi-byte integers use big-endian / network byte order.

#![deny(unsafe_code)]

mod codec;
mod error;
mod frame;
mod wire;

pub use codec::{FrameDecoder, FrameEncoder};
pub use error::ProtocolError;
pub use frame::{Frame, FrameType, Scope, StreamId};
pub use wire::{HEADER_SIZE, MAGIC, MAX_FRAME_PAYLOAD, VERSION};
