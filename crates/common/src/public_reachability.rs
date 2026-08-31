use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

const CHALLENGE_BYTES: usize = 16;
const PROOF_CONTEXT: &[u8] = b"TunnelProxy public reachability v1\0";

pub const PUBLIC_REACHABILITY_PATH: &str = "/.well-known/tunnelproxy/reachability";
pub const PUBLIC_REACHABILITY_CHALLENGE_HEADER: &str = "tunnelproxy-probe";
pub const PUBLIC_REACHABILITY_PROOF_HEADER: &str = "tunnelproxy-probe-proof";
pub const PUBLIC_REACHABILITY_CHALLENGE_LENGTH: usize = 22;
pub const PUBLIC_REACHABILITY_PROOF_LENGTH: usize = 43;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicReachabilityChallenge([u8; CHALLENGE_BYTES]);

impl std::fmt::Debug for PublicReachabilityChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicReachabilityChallenge([REDACTED])")
    }
}

impl PublicReachabilityChallenge {
    pub fn generate() -> Result<Self, PublicReachabilityError> {
        let mut bytes = [0_u8; CHALLENGE_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|_| PublicReachabilityError::Random)?;
        Ok(Self(bytes))
    }

    pub fn parse(value: &str) -> Result<Self, PublicReachabilityError> {
        if value.len() != PUBLIC_REACHABILITY_CHALLENGE_LENGTH {
            return Err(PublicReachabilityError::InvalidChallenge);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| PublicReachabilityError::InvalidChallenge)?;
        let bytes: [u8; CHALLENGE_BYTES] = decoded
            .try_into()
            .map_err(|_| PublicReachabilityError::InvalidChallenge)?;
        let challenge = Self(bytes);
        if challenge.encoded() != value {
            return Err(PublicReachabilityError::InvalidChallenge);
        }
        Ok(challenge)
    }

    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn proof(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(PROOF_CONTEXT);
        digest.update(self.0);
        URL_SAFE_NO_PAD.encode(digest.finalize())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicReachabilityError {
    Random,
    InvalidChallenge,
}

impl std::fmt::Display for PublicReachabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Random => "could not generate public reachability challenge",
            Self::InvalidChallenge => "public reachability challenge is invalid",
        })
    }
}

impl std::error::Error for PublicReachabilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_canonical_bounded_and_debug_redacted() {
        let challenge = PublicReachabilityChallenge::generate().unwrap();
        let encoded = challenge.encoded();
        assert_eq!(encoded.len(), PUBLIC_REACHABILITY_CHALLENGE_LENGTH);
        assert_eq!(
            PublicReachabilityChallenge::parse(&encoded).unwrap(),
            challenge
        );
        assert_eq!(challenge.proof().len(), PUBLIC_REACHABILITY_PROOF_LENGTH);
        assert!(!format!("{challenge:?}").contains(&encoded));
        assert_eq!(
            PublicReachabilityChallenge::parse(&(encoded + "=")),
            Err(PublicReachabilityError::InvalidChallenge)
        );
    }
}
