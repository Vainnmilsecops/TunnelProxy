use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SerialNumber,
};
use rustls::pki_types::CertificateSigningRequestDer;
use time::OffsetDateTime;
use tunnelproxy_common::{AgentId, TunnelId};
use tunnelproxy_protocol::EnrollmentRequestId;
use x509_parser::parse_x509_certificate;

use crate::CertificateFingerprint;

#[derive(Clone)]
pub struct AgentCertificateIssuer {
    inner: Arc<IssuerInner>,
}

struct IssuerInner {
    certificate: Certificate,
    key_pair: KeyPair,
    validity: Duration,
}

impl AgentCertificateIssuer {
    pub fn validity(&self) -> Duration {
        self.inner.validity
    }

    pub fn from_pem(
        issuer_certificate_pem: &[u8],
        issuer_private_key_pem: &[u8],
        validity: Duration,
    ) -> Result<Self, CertificateIssuerError> {
        if validity.as_secs() == 0 || validity > Duration::from_secs(30 * 24 * 60 * 60) {
            return Err(CertificateIssuerError::InvalidValidity);
        }
        let certificate_text = std::str::from_utf8(issuer_certificate_pem)
            .map_err(|_| CertificateIssuerError::InvalidCertificate)?;
        let private_key_text = std::str::from_utf8(issuer_private_key_pem)
            .map_err(|_| CertificateIssuerError::InvalidPrivateKey)?;
        let params = CertificateParams::from_ca_cert_pem(certificate_text)
            .map_err(|_| CertificateIssuerError::InvalidCertificate)?;
        if !matches!(
            params.is_ca,
            IsCa::Ca(BasicConstraints::Unconstrained) | IsCa::Ca(_)
        ) {
            return Err(CertificateIssuerError::NotCertificateAuthority);
        }
        let key_pair = KeyPair::from_pem(private_key_text)
            .map_err(|_| CertificateIssuerError::InvalidPrivateKey)?;
        verify_ca_key_pair(issuer_certificate_pem, &key_pair)?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|_| CertificateIssuerError::InvalidIdentity)?;
        Ok(Self {
            inner: Arc::new(IssuerInner {
                certificate,
                key_pair,
                validity,
            }),
        })
    }

    pub fn issue(
        &self,
        request_id: EnrollmentRequestId,
        agent_id: &AgentId,
        tunnel_id: &TunnelId,
        csr_der: &[u8],
    ) -> Result<IssuedCertificate, CertificateIssuerError> {
        if csr_der.is_empty() || csr_der.len() > 48 * 1024 {
            return Err(CertificateIssuerError::InvalidCsr);
        }
        let csr_der = CertificateSigningRequestDer::from(csr_der.to_vec());
        let mut request = CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|_| CertificateIssuerError::InvalidCsr)?;
        let now = OffsetDateTime::now_utc();
        let validity_seconds = i64::try_from(self.inner.validity.as_secs())
            .map_err(|_| CertificateIssuerError::InvalidValidity)?;
        let not_after = now
            .checked_add(time::Duration::seconds(validity_seconds))
            .ok_or(CertificateIssuerError::InvalidValidity)?;
        request.params.not_before = now - time::Duration::minutes(1);
        request.params.not_after = not_after;
        request.params.is_ca = IsCa::NoCa;
        request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        request.params.subject_alt_names.clear();
        request.params.serial_number = Some(SerialNumber::from(request_id.as_bytes().to_vec()));
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, agent_id.as_str());
        distinguished_name.push(DnType::OrganizationalUnitName, tunnel_id.as_str());
        request.params.distinguished_name = distinguished_name;
        let certificate = request
            .signed_by(&self.inner.certificate, &self.inner.key_pair)
            .map_err(|_| CertificateIssuerError::Signing)?;
        let fingerprint = CertificateFingerprint::from_certificate_der(certificate.der().as_ref());
        Ok(IssuedCertificate {
            certificate_pem: certificate.pem().into_bytes(),
            fingerprint,
            not_after_unix: u64::try_from(not_after.unix_timestamp())
                .map_err(|_| CertificateIssuerError::InvalidValidity)?,
        })
    }
}

fn verify_ca_key_pair(
    certificate_pem: &[u8],
    key_pair: &KeyPair,
) -> Result<(), CertificateIssuerError> {
    let mut reader = std::io::BufReader::new(certificate_pem);
    let certificate = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .map_err(|_| CertificateIssuerError::InvalidCertificate)?
        .ok_or(CertificateIssuerError::InvalidCertificate)?;
    let (_, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| CertificateIssuerError::InvalidCertificate)?;
    let public_key_der = key_pair.public_key_der();
    if parsed.public_key().raw != public_key_der.as_slice() {
        return Err(CertificateIssuerError::InvalidIdentity);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub certificate_pem: Vec<u8>,
    pub fingerprint: CertificateFingerprint,
    pub not_after_unix: u64,
}

impl std::fmt::Debug for AgentCertificateIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCertificateIssuer")
            .field("validity", &self.inner.validity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateIssuerError {
    InvalidValidity,
    InvalidCertificate,
    InvalidPrivateKey,
    NotCertificateAuthority,
    InvalidIdentity,
    InvalidCsr,
    Signing,
}

impl std::fmt::Display for CertificateIssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidValidity => "certificate validity policy is invalid",
            Self::InvalidCertificate => "issuer certificate is invalid",
            Self::InvalidPrivateKey => "issuer private key is invalid",
            Self::NotCertificateAuthority => "issuer certificate is not a CA",
            Self::InvalidIdentity => "issuer certificate and private key do not match",
            Self::InvalidCsr => "certificate signing request is invalid",
            Self::Signing => "certificate signing failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CertificateIssuerError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca() -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate, key)
    }

    #[test]
    fn issuer_enforces_ca_identity_policy_and_client_auth_leaf_profile() {
        let (ca, ca_key) = test_ca();
        assert_eq!(
            AgentCertificateIssuer::from_pem(
                ca.pem().as_bytes(),
                ca_key.serialize_pem().as_bytes(),
                Duration::from_millis(999),
            )
            .unwrap_err(),
            CertificateIssuerError::InvalidValidity
        );
        assert_eq!(
            AgentCertificateIssuer::from_pem(
                ca.pem().as_bytes(),
                ca_key.serialize_pem().as_bytes(),
                Duration::from_secs(31 * 24 * 60 * 60),
            )
            .unwrap_err(),
            CertificateIssuerError::InvalidValidity
        );
        let wrong_key = KeyPair::generate().unwrap();
        assert_eq!(
            AgentCertificateIssuer::from_pem(
                ca.pem().as_bytes(),
                wrong_key.serialize_pem().as_bytes(),
                Duration::from_secs(60),
            )
            .unwrap_err(),
            CertificateIssuerError::InvalidIdentity
        );

        let issuer = AgentCertificateIssuer::from_pem(
            ca.pem().as_bytes(),
            ca_key.serialize_pem().as_bytes(),
            Duration::from_secs(60),
        )
        .unwrap();
        let agent_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&agent_key)
            .unwrap();
        let issued = issuer
            .issue(
                EnrollmentRequestId::from_bytes([8; 16]),
                &AgentId::new("agent-issuer-test").unwrap(),
                &TunnelId::new("tunnel-issuer-test").unwrap(),
                csr.der().as_ref(),
            )
            .unwrap();
        let mut reader = std::io::BufReader::new(issued.certificate_pem.as_slice());
        let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        assert_eq!(
            issued.fingerprint,
            CertificateFingerprint::from_certificate_der(der.as_ref())
        );
        let (_, parsed) = parse_x509_certificate(der.as_ref()).unwrap();
        assert!(!parsed.tbs_certificate.is_ca());
        let usage = parsed.extended_key_usage().unwrap().unwrap();
        assert!(usage.value.client_auth);
        assert!(!usage.value.server_auth);
        assert_eq!(
            parsed.subject().iter_common_name().next().unwrap().as_str(),
            Ok("agent-issuer-test")
        );
    }
}
