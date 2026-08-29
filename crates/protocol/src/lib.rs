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

mod codec;
mod enrollment;
mod error;
mod frame;
mod handshake;
mod hostname;
mod stream;
mod wire;

pub use codec::{FrameDecoder, FrameEncoder};
pub use enrollment::{
    read_enrollment_message, write_enrollment_message, EnrollmentErrorCode, EnrollmentMessage,
    EnrollmentProtocolError, EnrollmentRequestId, EnrollmentToken, ENROLLMENT_PROTOCOL_ALPN,
    ENROLLMENT_PROTOCOL_MAGIC, ENROLLMENT_PROTOCOL_VERSION, MAX_ENROLLMENT_MESSAGE_BYTES,
};
pub use error::ProtocolError;
pub use frame::{Frame, FrameType, Scope, StreamId};
pub use handshake::{
    HandshakeErrorCode, HeartbeatErrorCode, HeartbeatSequence, HelloRole, RegistrationPayloadError,
    RegistrationRequest, TransportSessionId, REGISTER_MAX_PAYLOAD_SIZE, REGISTER_PREFIX_SIZE,
    ROLE_AGENT,
};
pub use hostname::{
    read_hostname_message, write_hostname_message, HostnameErrorCode, HostnameMessage,
    HostnameProtocolError, HOSTNAME_PROTOCOL_ALPN, HOSTNAME_PROTOCOL_MAGIC,
    HOSTNAME_PROTOCOL_VERSION, MAX_HOSTNAME_MESSAGE_BYTES,
};
pub use stream::StreamResetCode;
pub use wire::{
    EMPTY_STREAM_PAYLOAD_SIZE, ERROR_PAYLOAD_SIZE, HEADER_SIZE, HEARTBEAT_PAYLOAD_SIZE,
    HELLO_PAYLOAD_SIZE, MAGIC, MAX_FRAME_PAYLOAD, PROTOCOL_VERSION, REGISTERED_PAYLOAD_SIZE,
    STREAM_RESET_PAYLOAD_SIZE, VERSION,
};
