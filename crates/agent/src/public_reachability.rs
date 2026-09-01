use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::header::{CACHE_CONTROL, CONNECTION, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tunnelproxy_common::{
    PublicHostname, PublicReachabilityChallenge, ShutdownSignal,
    PUBLIC_REACHABILITY_CHALLENGE_HEADER, PUBLIC_REACHABILITY_PATH,
    PUBLIC_REACHABILITY_PROOF_HEADER,
};

pub const DEFAULT_PUBLIC_REACHABILITY_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_PUBLIC_REACHABILITY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_PUBLIC_REACHABILITY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
pub const MAX_PUBLIC_REACHABILITY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const MIN_PUBLIC_REACHABILITY_MONITOR_INTERVAL: Duration = Duration::from_secs(10);
pub const MAX_PUBLIC_REACHABILITY_MONITOR_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_PUBLIC_REACHABILITY_FAILURE_THRESHOLD: u64 = 3;
pub const MAX_PUBLIC_REACHABILITY_FAILURE_THRESHOLD: u64 = 10;
const MAX_RESOLVED_ADDRESSES: usize = 8;
const MAX_RESPONSE_BODY_BYTES: usize = 1024;

#[derive(Debug, Clone)]
pub struct PublicReachabilityConfig {
    pub hostname: PublicHostname,
    pub ca_pem: Option<Vec<u8>>,
    pub total_timeout: Duration,
    pub attempt_timeout: Duration,
    pub retry_interval: Duration,
    pub server_addr_override: Option<SocketAddr>,
}

impl PublicReachabilityConfig {
    pub fn validate(&self) -> Result<(), PublicReachabilityError> {
        if self.total_timeout.is_zero()
            || self.total_timeout > MAX_PUBLIC_REACHABILITY_TIMEOUT
            || self.attempt_timeout.is_zero()
            || self.attempt_timeout > self.total_timeout
            || self.retry_interval.is_zero()
            || self.retry_interval > self.total_timeout
        {
            return Err(PublicReachabilityError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicReachabilityMonitorConfig {
    pub interval: Duration,
    pub failure_threshold: u64,
}

impl PublicReachabilityMonitorConfig {
    pub fn validate(self) -> Result<(), PublicReachabilityError> {
        if self.interval < MIN_PUBLIC_REACHABILITY_MONITOR_INTERVAL
            || self.interval > MAX_PUBLIC_REACHABILITY_MONITOR_INTERVAL
            || self.failure_threshold == 0
            || self.failure_threshold > MAX_PUBLIC_REACHABILITY_FAILURE_THRESHOLD
        {
            return Err(PublicReachabilityError::InvalidMonitorConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicReachabilityOutcome {
    pub attempts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicReachabilityFailureClass {
    Resolve,
    Connect,
    Tls,
    Http,
    RouteUnavailable,
    InvalidProof,
}

impl PublicReachabilityFailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::RouteUnavailable => "route_unavailable",
            Self::InvalidProof => "invalid_proof",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicReachabilityError {
    InvalidConfig,
    InvalidMonitorConfig,
    InvalidCa,
    Challenge,
    AttemptFailed(PublicReachabilityFailureClass),
    Cancelled {
        attempts: u64,
    },
    Timeout {
        attempts: u64,
        last_failure: PublicReachabilityFailureClass,
    },
}

impl std::fmt::Display for PublicReachabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => {
                formatter.write_str("public reachability configuration is invalid")
            }
            Self::InvalidMonitorConfig => {
                formatter.write_str("public reachability monitor configuration is invalid")
            }
            Self::InvalidCa => formatter.write_str("public reachability CA bundle is invalid"),
            Self::Challenge => {
                formatter.write_str("public reachability challenge generation failed")
            }
            Self::AttemptFailed(failure) => write!(
                formatter,
                "public reachability attempt failed ({})",
                failure.as_str()
            ),
            Self::Cancelled { attempts } => write!(
                formatter,
                "public reachability verification was cancelled after {attempts} attempts"
            ),
            Self::Timeout {
                attempts,
                last_failure,
            } => write!(
                formatter,
                "public reachability verification timed out after {attempts} attempts ({})",
                last_failure.as_str()
            ),
        }
    }
}

impl std::error::Error for PublicReachabilityError {}

#[derive(Clone)]
pub struct PublicReachabilityProbe {
    config: PublicReachabilityConfig,
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for PublicReachabilityProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicReachabilityProbe")
            .field("hostname", &self.config.hostname)
            .field("ca_pem", &self.config.ca_pem.as_ref().map(|_| "[REDACTED]"))
            .field("total_timeout", &self.config.total_timeout)
            .field("attempt_timeout", &self.config.attempt_timeout)
            .field("retry_interval", &self.config.retry_interval)
            .finish_non_exhaustive()
    }
}

impl PublicReachabilityProbe {
    pub fn new(config: PublicReachabilityConfig) -> Result<Self, PublicReachabilityError> {
        config.validate()?;
        let mut roots = RootCertStore::empty();
        if let Some(ca_pem) = &config.ca_pem {
            let certificates: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut ca_pem.as_slice())
                    .collect::<Result<_, _>>()
                    .map_err(|_| PublicReachabilityError::InvalidCa)?;
            if certificates.is_empty() {
                return Err(PublicReachabilityError::InvalidCa);
            }
            let (added, _) = roots.add_parsable_certificates(certificates);
            if added == 0 {
                return Err(PublicReachabilityError::InvalidCa);
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let mut tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config,
            tls: Arc::new(tls),
        })
    }

    pub async fn verify_until_success(
        &self,
        signal: ShutdownSignal,
    ) -> Result<PublicReachabilityOutcome, PublicReachabilityError> {
        let deadline = tokio::time::Instant::now() + self.config.total_timeout;
        let mut attempts = 0_u64;
        let mut last_failure = PublicReachabilityFailureClass::Http;
        loop {
            if signal.is_shutdown() {
                return Err(PublicReachabilityError::Cancelled { attempts });
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(PublicReachabilityError::Timeout {
                    attempts,
                    last_failure,
                });
            }
            attempts = attempts.saturating_add(1);
            let attempt_timeout = self.config.attempt_timeout.min(deadline - now);
            let attempted = tokio::select! {
                biased;
                () = signal.cancelled() => return Err(PublicReachabilityError::Cancelled { attempts }),
                result = tokio::time::timeout(attempt_timeout, self.attempt_once()) => result,
            };
            last_failure = match attempted {
                Ok(Ok(())) => return Ok(PublicReachabilityOutcome { attempts }),
                Ok(Err(failure)) => failure,
                Err(_) => PublicReachabilityFailureClass::Http,
            };
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(PublicReachabilityError::Timeout {
                    attempts,
                    last_failure,
                });
            }
            let delay = self.config.retry_interval.min(deadline - now);
            tokio::select! {
                biased;
                () = signal.cancelled() => return Err(PublicReachabilityError::Cancelled { attempts }),
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    pub async fn verify_once(&self, signal: ShutdownSignal) -> Result<(), PublicReachabilityError> {
        if signal.is_shutdown() {
            return Err(PublicReachabilityError::Cancelled { attempts: 0 });
        }
        let attempted = tokio::select! {
            biased;
            () = signal.cancelled() => {
                return Err(PublicReachabilityError::Cancelled { attempts: 0 });
            }
            result = tokio::time::timeout(self.config.attempt_timeout, self.attempt_once()) => result,
        };
        match attempted {
            Ok(Ok(())) => Ok(()),
            Ok(Err(failure)) => Err(PublicReachabilityError::AttemptFailed(failure)),
            Err(_) => Err(PublicReachabilityError::AttemptFailed(
                PublicReachabilityFailureClass::Http,
            )),
        }
    }

    async fn attempt_once(&self) -> Result<(), PublicReachabilityFailureClass> {
        let challenge = PublicReachabilityChallenge::generate()
            .map_err(|_| PublicReachabilityFailureClass::Http)?;
        let addresses = self.resolve().await?;
        let mut stream = None;
        for address in addresses {
            if let Ok(connected) = TcpStream::connect(address).await {
                stream = Some(connected);
                break;
            }
        }
        let stream = stream.ok_or(PublicReachabilityFailureClass::Connect)?;
        let server_name = ServerName::try_from(self.config.hostname.as_str().to_owned())
            .map_err(|_| PublicReachabilityFailureClass::Tls)?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, stream)
            .await
            .map_err(|_| PublicReachabilityFailureClass::Tls)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| PublicReachabilityFailureClass::Http)?;
        let connection = tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::GET)
            .uri(PUBLIC_REACHABILITY_PATH)
            .header(HOST, self.config.hostname.as_str())
            .header(CONNECTION, "close")
            .header(PUBLIC_REACHABILITY_CHALLENGE_HEADER, challenge.encoded())
            .body(Empty::<Bytes>::new())
            .map_err(|_| PublicReachabilityFailureClass::Http)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| PublicReachabilityFailureClass::Http)?;
        if response.status() == StatusCode::SERVICE_UNAVAILABLE
            || response.status() == StatusCode::NOT_FOUND
        {
            connection.abort();
            return Err(PublicReachabilityFailureClass::RouteUnavailable);
        }
        if response.status() != StatusCode::NO_CONTENT
            || response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                != Some("no-store")
            || response
                .headers()
                .get(PUBLIC_REACHABILITY_PROOF_HEADER)
                .and_then(|value| value.to_str().ok())
                != Some(challenge.proof().as_str())
        {
            connection.abort();
            return Err(PublicReachabilityFailureClass::InvalidProof);
        }
        Limited::new(response.into_body(), MAX_RESPONSE_BODY_BYTES)
            .collect()
            .await
            .map_err(|_| PublicReachabilityFailureClass::Http)?;
        connection.abort();
        Ok(())
    }

    async fn resolve(&self) -> Result<Vec<SocketAddr>, PublicReachabilityFailureClass> {
        if let Some(address) = self.config.server_addr_override {
            return Ok(vec![address]);
        }
        let addresses = tokio::net::lookup_host((self.config.hostname.as_str(), 443))
            .await
            .map_err(|_| PublicReachabilityFailureClass::Resolve)?
            .take(MAX_RESOLVED_ADDRESSES)
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            Err(PublicReachabilityFailureClass::Resolve)
        } else {
            Ok(addresses)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelproxy_common::shutdown_channel;

    fn config() -> PublicReachabilityConfig {
        PublicReachabilityConfig {
            hostname: PublicHostname::new("probe.example.test").unwrap(),
            ca_pem: None,
            total_timeout: Duration::from_millis(50),
            attempt_timeout: Duration::from_millis(25),
            retry_interval: Duration::from_millis(5),
            server_addr_override: Some("127.0.0.1:9".parse().unwrap()),
        }
    }

    #[test]
    fn configuration_and_custom_ca_are_validated_offline() {
        let mut invalid = config();
        invalid.total_timeout = Duration::ZERO;
        assert!(matches!(
            PublicReachabilityProbe::new(invalid),
            Err(PublicReachabilityError::InvalidConfig)
        ));

        let mut invalid = config();
        invalid.ca_pem = Some(b"not a certificate".to_vec());
        assert!(matches!(
            PublicReachabilityProbe::new(invalid),
            Err(PublicReachabilityError::InvalidCa)
        ));

        assert!(PublicReachabilityMonitorConfig {
            interval: MIN_PUBLIC_REACHABILITY_MONITOR_INTERVAL,
            failure_threshold: DEFAULT_PUBLIC_REACHABILITY_FAILURE_THRESHOLD,
        }
        .validate()
        .is_ok());
        assert!(matches!(
            PublicReachabilityMonitorConfig {
                interval: Duration::from_secs(1),
                failure_threshold: 1,
            }
            .validate(),
            Err(PublicReachabilityError::InvalidMonitorConfig)
        ));
    }

    #[tokio::test]
    async fn preexisting_shutdown_cancels_without_a_network_attempt() {
        let probe = PublicReachabilityProbe::new(config()).unwrap();
        let (trigger, signal) = shutdown_channel();
        trigger.shutdown();
        assert_eq!(
            probe.verify_until_success(signal).await,
            Err(PublicReachabilityError::Cancelled { attempts: 0 })
        );
        let (trigger, signal) = shutdown_channel();
        trigger.shutdown();
        assert_eq!(
            probe.verify_once(signal).await,
            Err(PublicReachabilityError::Cancelled { attempts: 0 })
        );
    }
}
