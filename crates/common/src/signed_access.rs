//! Bounded, offline-issued access tokens for public HTTPS ingress.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::PublicHostname;

const TOKEN_MAGIC: &[u8; 4] = b"TPS1";
const SIGNATURE_BYTES: usize = 64;
const PRIVATE_KEY_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;
const KEY_FILE_VERSION: u8 = 1;

pub const SIGNED_ACCESS_QUERY_PARAMETER: &str = "tp_access";
pub const MAX_SIGNED_ACCESS_TOKEN_BYTES: usize = 512;
pub const MAX_SIGNED_ACCESS_KEYS: usize = 8;
pub const MAX_SIGNED_ACCESS_KEY_FILE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAccessClaims {
    pub key_id: u32,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub hostname: PublicHostname,
}

#[derive(Clone)]
pub struct SignedAccessSigner {
    key_id: u32,
    key: SigningKey,
}

impl std::fmt::Debug for SignedAccessSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedAccessSigner")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl SignedAccessSigner {
    pub fn from_private_key(
        key_id: u32,
        private_key: [u8; PRIVATE_KEY_BYTES],
    ) -> Result<Self, SignedAccessError> {
        validate_key_id(key_id)?;
        Ok(Self {
            key_id,
            key: SigningKey::from_bytes(&private_key),
        })
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn public_key_ring(&self) -> SignedAccessKeyRing {
        SignedAccessKeyRing {
            keys: BTreeMap::from([(self.key_id, self.key.verifying_key())]),
        }
    }

    pub fn sign(
        &self,
        hostname: &PublicHostname,
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<String, SignedAccessError> {
        if issued_at_unix >= expires_at_unix {
            return Err(SignedAccessError::InvalidLifetime);
        }
        let payload = encode_payload(self.key_id, issued_at_unix, expires_at_unix, hostname);
        let signature = self.key.sign(&payload);
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

#[derive(Clone)]
pub struct SignedAccessKeyRing {
    keys: BTreeMap<u32, VerifyingKey>,
}

impl std::fmt::Debug for SignedAccessKeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedAccessKeyRing")
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SignedAccessKeyRing {
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn verify(
        &self,
        token: &str,
        expected_hostname: &PublicHostname,
        now_unix: u64,
        maximum_ttl_seconds: u64,
        clock_skew_seconds: u64,
    ) -> Result<SignedAccessClaims, SignedAccessError> {
        if token.is_empty() || token.len() > MAX_SIGNED_ACCESS_TOKEN_BYTES {
            return Err(SignedAccessError::MalformedToken);
        }
        let (payload_text, signature_text) = token
            .split_once('.')
            .filter(|(_, signature)| !signature.contains('.'))
            .ok_or(SignedAccessError::MalformedToken)?;
        let payload = decode_canonical(payload_text)?;
        let signature_bytes = decode_canonical(signature_text)?;
        let signature_bytes: [u8; SIGNATURE_BYTES] = signature_bytes
            .try_into()
            .map_err(|_| SignedAccessError::MalformedToken)?;
        let claims = decode_payload(&payload)?;
        let key = self
            .keys
            .get(&claims.key_id)
            .ok_or(SignedAccessError::UnknownKey)?;
        key.verify(&payload, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| SignedAccessError::InvalidSignature)?;

        if &claims.hostname != expected_hostname {
            return Err(SignedAccessError::WrongHostname);
        }
        let ttl = claims
            .expires_at_unix
            .checked_sub(claims.issued_at_unix)
            .ok_or(SignedAccessError::InvalidLifetime)?;
        if ttl == 0 || ttl > maximum_ttl_seconds {
            return Err(SignedAccessError::LifetimeTooLong);
        }
        if now_unix.saturating_add(clock_skew_seconds) < claims.issued_at_unix {
            return Err(SignedAccessError::NotYetValid);
        }
        if now_unix > claims.expires_at_unix.saturating_add(clock_skew_seconds) {
            return Err(SignedAccessError::Expired);
        }
        Ok(claims)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedAccessError {
    InvalidKeyId,
    KeyGeneration,
    KeyFileTooLarge,
    InvalidKeyFile,
    UnsupportedKeyFileVersion,
    EmptyKeyRing,
    TooManyKeys,
    DuplicateKeyId,
    MalformedToken,
    UnknownKey,
    InvalidSignature,
    WrongHostname,
    InvalidLifetime,
    LifetimeTooLong,
    NotYetValid,
    Expired,
}

impl std::fmt::Display for SignedAccessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyId => "signed-access key ID must be non-zero",
            Self::KeyGeneration => "could not generate signed-access key material",
            Self::KeyFileTooLarge => "signed-access key file exceeds the size limit",
            Self::InvalidKeyFile => "signed-access key file is invalid",
            Self::UnsupportedKeyFileVersion => "signed-access key file version is unsupported",
            Self::EmptyKeyRing => "signed-access public-key ring must not be empty",
            Self::TooManyKeys => "signed-access public-key ring contains too many keys",
            Self::DuplicateKeyId => "signed-access public-key ring contains a duplicate key ID",
            Self::MalformedToken => "signed-access token is malformed",
            Self::UnknownKey => "signed-access token refers to an unknown key",
            Self::InvalidSignature => "signed-access token signature is invalid",
            Self::WrongHostname => "signed-access token is for another hostname",
            Self::InvalidLifetime => "signed-access token lifetime is invalid",
            Self::LifetimeTooLong => "signed-access token lifetime exceeds policy",
            Self::NotYetValid => "signed-access token is not yet valid",
            Self::Expired => "signed-access token has expired",
        })
    }
}

impl std::error::Error for SignedAccessError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyFile {
    version: u8,
    key_id: u32,
    private_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRingFile {
    version: u8,
    keys: Vec<PublicKeyFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyFile {
    key_id: u32,
    public_key: String,
}

pub fn generate_signed_access_keypair(
    key_id: u32,
) -> Result<(Vec<u8>, Vec<u8>), SignedAccessError> {
    validate_key_id(key_id)?;
    let mut private_key = [0_u8; PRIVATE_KEY_BYTES];
    getrandom::getrandom(&mut private_key).map_err(|_| SignedAccessError::KeyGeneration)?;
    let signer = SignedAccessSigner::from_private_key(key_id, private_key)?;
    let private_file = PrivateKeyFile {
        version: KEY_FILE_VERSION,
        key_id,
        private_key: URL_SAFE_NO_PAD.encode(private_key),
    };
    let public_file = PublicKeyRingFile {
        version: KEY_FILE_VERSION,
        keys: vec![PublicKeyFile {
            key_id,
            public_key: URL_SAFE_NO_PAD.encode(signer.key.verifying_key().to_bytes()),
        }],
    };
    Ok((
        serde_json::to_vec_pretty(&private_file).map_err(|_| SignedAccessError::InvalidKeyFile)?,
        serde_json::to_vec_pretty(&public_file).map_err(|_| SignedAccessError::InvalidKeyFile)?,
    ))
}

pub fn load_signed_access_signer(bytes: &[u8]) -> Result<SignedAccessSigner, SignedAccessError> {
    check_file_size(bytes)?;
    let file: PrivateKeyFile =
        serde_json::from_slice(bytes).map_err(|_| SignedAccessError::InvalidKeyFile)?;
    if file.version != KEY_FILE_VERSION {
        return Err(SignedAccessError::UnsupportedKeyFileVersion);
    }
    validate_key_id(file.key_id)?;
    let key = decode_canonical(&file.private_key).map_err(|_| SignedAccessError::InvalidKeyFile)?;
    let key: [u8; PRIVATE_KEY_BYTES] = key
        .try_into()
        .map_err(|_| SignedAccessError::InvalidKeyFile)?;
    SignedAccessSigner::from_private_key(file.key_id, key)
}

pub fn load_signed_access_key_ring(bytes: &[u8]) -> Result<SignedAccessKeyRing, SignedAccessError> {
    check_file_size(bytes)?;
    let file: PublicKeyRingFile =
        serde_json::from_slice(bytes).map_err(|_| SignedAccessError::InvalidKeyFile)?;
    if file.version != KEY_FILE_VERSION {
        return Err(SignedAccessError::UnsupportedKeyFileVersion);
    }
    if file.keys.is_empty() {
        return Err(SignedAccessError::EmptyKeyRing);
    }
    if file.keys.len() > MAX_SIGNED_ACCESS_KEYS {
        return Err(SignedAccessError::TooManyKeys);
    }
    let mut keys = BTreeMap::new();
    for entry in file.keys {
        validate_key_id(entry.key_id)?;
        let bytes =
            decode_canonical(&entry.public_key).map_err(|_| SignedAccessError::InvalidKeyFile)?;
        let bytes: [u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| SignedAccessError::InvalidKeyFile)?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| SignedAccessError::InvalidKeyFile)?;
        if keys.insert(entry.key_id, key).is_some() {
            return Err(SignedAccessError::DuplicateKeyId);
        }
    }
    Ok(SignedAccessKeyRing { keys })
}

fn validate_key_id(key_id: u32) -> Result<(), SignedAccessError> {
    if key_id == 0 {
        Err(SignedAccessError::InvalidKeyId)
    } else {
        Ok(())
    }
}

fn check_file_size(bytes: &[u8]) -> Result<(), SignedAccessError> {
    if bytes.is_empty() {
        Err(SignedAccessError::InvalidKeyFile)
    } else if bytes.len() > MAX_SIGNED_ACCESS_KEY_FILE_BYTES {
        Err(SignedAccessError::KeyFileTooLarge)
    } else {
        Ok(())
    }
}

fn decode_canonical(value: &str) -> Result<Vec<u8>, SignedAccessError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SignedAccessError::MalformedToken)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(SignedAccessError::MalformedToken);
    }
    Ok(decoded)
}

fn encode_payload(
    key_id: u32,
    issued_at_unix: u64,
    expires_at_unix: u64,
    hostname: &PublicHostname,
) -> Vec<u8> {
    let hostname = hostname.as_str().as_bytes();
    let mut payload = Vec::with_capacity(26 + hostname.len());
    payload.extend_from_slice(TOKEN_MAGIC);
    payload.extend_from_slice(&key_id.to_be_bytes());
    payload.extend_from_slice(&issued_at_unix.to_be_bytes());
    payload.extend_from_slice(&expires_at_unix.to_be_bytes());
    payload.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    payload.extend_from_slice(hostname);
    payload
}

fn decode_payload(payload: &[u8]) -> Result<SignedAccessClaims, SignedAccessError> {
    const HEADER_BYTES: usize = 4 + 4 + 8 + 8 + 2;
    if payload.len() < HEADER_BYTES || &payload[..4] != TOKEN_MAGIC {
        return Err(SignedAccessError::MalformedToken);
    }
    let key_id = u32::from_be_bytes(payload[4..8].try_into().expect("fixed slice"));
    validate_key_id(key_id).map_err(|_| SignedAccessError::MalformedToken)?;
    let issued_at_unix = u64::from_be_bytes(payload[8..16].try_into().expect("fixed slice"));
    let expires_at_unix = u64::from_be_bytes(payload[16..24].try_into().expect("fixed slice"));
    let hostname_len =
        u16::from_be_bytes(payload[24..26].try_into().expect("fixed slice")) as usize;
    if payload.len() != HEADER_BYTES + hostname_len {
        return Err(SignedAccessError::MalformedToken);
    }
    let hostname = std::str::from_utf8(&payload[HEADER_BYTES..])
        .map_err(|_| SignedAccessError::MalformedToken)?;
    let hostname = PublicHostname::new(hostname).map_err(|_| SignedAccessError::MalformedToken)?;
    if hostname.as_str().as_bytes() != &payload[HEADER_BYTES..] {
        return Err(SignedAccessError::MalformedToken);
    }
    Ok(SignedAccessClaims {
        key_id,
        issued_at_unix,
        expires_at_unix,
        hostname,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SignedAccessSigner, SignedAccessKeyRing, PublicHostname) {
        let signer = SignedAccessSigner::from_private_key(7, [42; PRIVATE_KEY_BYTES]).unwrap();
        let ring = signer.public_key_ring();
        let hostname = PublicHostname::new("Demo.Example.COM.").unwrap();
        (signer, ring, hostname)
    }

    #[test]
    fn token_roundtrip_binds_hostname_and_lifetime() {
        let (signer, ring, hostname) = fixture();
        let token = signer.sign(&hostname, 1_000, 1_060).unwrap();
        let claims = ring.verify(&token, &hostname, 1_030, 60, 0).unwrap();
        assert_eq!(claims.key_id, 7);
        assert_eq!(claims.hostname.as_str(), "demo.example.com");
        assert_eq!(claims.expires_at_unix, 1_060);
    }

    #[test]
    fn token_rejects_tampering_wrong_host_and_unknown_key() {
        let (signer, ring, hostname) = fixture();
        let token = signer.sign(&hostname, 1_000, 1_060).unwrap();
        let mut tampered = token.into_bytes();
        tampered[10] = if tampered[10] == b'A' { b'B' } else { b'A' };
        assert!(matches!(
            ring.verify(
                std::str::from_utf8(&tampered).unwrap(),
                &hostname,
                1_030,
                60,
                0
            ),
            Err(SignedAccessError::InvalidSignature | SignedAccessError::MalformedToken)
        ));

        let token = signer.sign(&hostname, 1_000, 1_060).unwrap();
        assert_eq!(
            ring.verify(
                &token,
                &PublicHostname::new("other.example.com").unwrap(),
                1_030,
                60,
                0
            ),
            Err(SignedAccessError::WrongHostname)
        );

        let other_ring = SignedAccessSigner::from_private_key(8, [11; 32])
            .unwrap()
            .public_key_ring();
        assert_eq!(
            other_ring.verify(&token, &hostname, 1_030, 60, 0),
            Err(SignedAccessError::UnknownKey)
        );
    }

    #[test]
    fn policy_enforces_expiry_start_time_and_maximum_ttl() {
        let (signer, ring, hostname) = fixture();
        let token = signer.sign(&hostname, 1_000, 1_100).unwrap();
        assert_eq!(
            ring.verify(&token, &hostname, 1_101, 100, 0),
            Err(SignedAccessError::Expired)
        );
        assert_eq!(
            ring.verify(&token, &hostname, 999, 100, 0),
            Err(SignedAccessError::NotYetValid)
        );
        assert_eq!(
            ring.verify(&token, &hostname, 1_050, 99, 0),
            Err(SignedAccessError::LifetimeTooLong)
        );
        assert!(ring.verify(&token, &hostname, 999, 100, 1).is_ok());
        assert!(ring.verify(&token, &hostname, 1_101, 100, 1).is_ok());
    }

    #[test]
    fn generated_key_files_roundtrip_without_debug_secret_leakage() {
        let (private_file, public_file) = generate_signed_access_keypair(19).unwrap();
        let signer = load_signed_access_signer(&private_file).unwrap();
        let ring = load_signed_access_key_ring(&public_file).unwrap();
        let hostname = PublicHostname::new("private.example").unwrap();
        let token = signer.sign(&hostname, 10, 20).unwrap();
        assert!(ring.verify(&token, &hostname, 15, 10, 0).is_ok());
        let debug = format!("{signer:?}");
        let private_json = std::str::from_utf8(&private_file).unwrap();
        let secret = serde_json::from_str::<serde_json::Value>(private_json).unwrap()
            ["private_key"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(!debug.contains(&secret));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn key_files_are_strict_and_bounded() {
        assert!(matches!(
            load_signed_access_key_ring(br#"{"version":1,"keys":[]}"#),
            Err(SignedAccessError::EmptyKeyRing)
        ));
        assert!(matches!(
            load_signed_access_signer(br#"{"version":1,"key_id":1,"private_key":"AA","extra":1}"#),
            Err(SignedAccessError::InvalidKeyFile)
        ));
        assert!(matches!(
            load_signed_access_key_ring(&vec![b'x'; MAX_SIGNED_ACCESS_KEY_FILE_BYTES + 1]),
            Err(SignedAccessError::KeyFileTooLarge)
        ));
        let (_, public_file) = generate_signed_access_keypair(5).unwrap();
        let mut ring: serde_json::Value = serde_json::from_slice(&public_file).unwrap();
        let key = ring["keys"][0].clone();
        ring["keys"].as_array_mut().unwrap().push(key);
        assert!(matches!(
            load_signed_access_key_ring(&serde_json::to_vec(&ring).unwrap()),
            Err(SignedAccessError::DuplicateKeyId)
        ));
        let mut ring: serde_json::Value = serde_json::from_slice(&public_file).unwrap();
        let key = ring["keys"][0].clone();
        ring["keys"] = serde_json::Value::Array(vec![key; MAX_SIGNED_ACCESS_KEYS + 1]);
        assert!(matches!(
            load_signed_access_key_ring(&serde_json::to_vec(&ring).unwrap()),
            Err(SignedAccessError::TooManyKeys)
        ));
    }
}
