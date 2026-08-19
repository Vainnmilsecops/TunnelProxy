//! `tunnelproxy-protocol`
//!
//! Placeholder for the future wire protocol spoken between
//! [`tunnelproxy-edge`] and [`tunnelproxy-agent`].
//!
//! Nothing here is implemented yet on purpose. Once work begins, this crate
//! will own the protocol versioning, framing, message types, and codec.
//! Until then, exposing anything beyond a version constant would be a lie.

#![deny(unsafe_code)]

/// Protocol version negotiated between Edge and Agent.
///
/// Bumping this number is the explicit signal that a wire-format change
/// happened (see INV-004 in `docs/ai/INVARIANTS.md`).
pub const PROTOCOL_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        // Pinning the initial version prevents accidental "0.0.0" placeholders.
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
