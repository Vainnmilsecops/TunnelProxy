//! Agent client for authenticated managed-hostname lifecycle requests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tunnelproxy_common::{AgentId, PublicHostname, TunnelId};
use tunnelproxy_protocol::{
    read_hostname_message, write_hostname_message, HostnameErrorCode, HostnameMessage,
    HostnameProtocolError, HOSTNAME_PROTOCOL_ALPN,
};

use crate::{AgentTlsConfig, AgentTlsConfigError};

#[derive(Clone)]
pub struct HostnameClientConfig {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub server_ca_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub request_timeout: Duration,
}

impl std::fmt::Debug for HostnameClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostnameClientConfig")
            .field("server_addr", &self.server_addr)
            .field("server_name", &self.server_name)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl HostnameClientConfig {
    fn build_tls(&self) -> Result<(Arc<ClientConfig>, ServerName<'static>), AgentHostnameError> {
        if self.connect_timeout.is_zero()
            || self.handshake_timeout.is_zero()
            || self.request_timeout.is_zero()
        {
            return Err(AgentHostnameError::InvalidConfig);
        }
        let base = AgentTlsConfig::from_pem(
            &self.server_ca_pem,
            &self.client_cert_pem,
            &self.client_key_pem,
            &self.server_name,
            self.handshake_timeout,
        )
        .map_err(AgentHostnameError::TlsConfig)?;
        let mut tls = (*base.client_config.current()).clone();
        tls.alpn_protocols = vec![HOSTNAME_PROTOCOL_ALPN.to_vec()];
        Ok((Arc::new(tls), base.server_name.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameAllocation {
    pub hostname: PublicHostname,
    pub catalog_version: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameRelease {
    pub hostname: Option<PublicHostname>,
    pub catalog_version: u64,
    pub changed: bool,
}

#[derive(Clone)]
pub struct AgentHostnameClient {
    config: HostnameClientConfig,
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl AgentHostnameClient {
    pub fn new(config: HostnameClientConfig) -> Result<Self, AgentHostnameError> {
        let (tls, server_name) = config.build_tls()?;
        Ok(Self {
            config,
            tls,
            server_name,
        })
    }

    pub async fn allocate(
        &self,
        agent_id: AgentId,
        tunnel_id: TunnelId,
    ) -> Result<HostnameAllocation, AgentHostnameError> {
        match self
            .exchange(HostnameMessage::Allocate {
                agent_id,
                tunnel_id,
            })
            .await?
        {
            HostnameMessage::Allocated {
                hostname,
                catalog_version,
                changed,
            } => Ok(HostnameAllocation {
                hostname,
                catalog_version,
                changed,
            }),
            HostnameMessage::Error { code } => Err(AgentHostnameError::Rejected(code)),
            _ => Err(AgentHostnameError::UnexpectedResponse),
        }
    }

    pub async fn release(
        &self,
        agent_id: AgentId,
        tunnel_id: TunnelId,
    ) -> Result<HostnameRelease, AgentHostnameError> {
        match self
            .exchange(HostnameMessage::Release {
                agent_id,
                tunnel_id,
            })
            .await?
        {
            HostnameMessage::Released {
                hostname,
                catalog_version,
                changed,
            } => Ok(HostnameRelease {
                hostname,
                catalog_version,
                changed,
            }),
            HostnameMessage::Error { code } => Err(AgentHostnameError::Rejected(code)),
            _ => Err(AgentHostnameError::UnexpectedResponse),
        }
    }

    async fn exchange(
        &self,
        request: HostnameMessage,
    ) -> Result<HostnameMessage, AgentHostnameError> {
        let socket = timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.config.server_addr),
        )
        .await
        .map_err(|_| AgentHostnameError::ConnectTimeout)?
        .map_err(|_| AgentHostnameError::Connect)?;
        let connector = TlsConnector::from(Arc::clone(&self.tls));
        let mut stream = timeout(
            self.config.handshake_timeout,
            connector.connect(self.server_name.clone(), socket),
        )
        .await
        .map_err(|_| AgentHostnameError::HandshakeTimeout)?
        .map_err(|_| AgentHostnameError::Tls)?;
        if stream.get_ref().1.alpn_protocol() != Some(HOSTNAME_PROTOCOL_ALPN) {
            return Err(AgentHostnameError::Alpn);
        }
        timeout(
            self.config.request_timeout,
            write_hostname_message(&mut stream, &request),
        )
        .await
        .map_err(|_| AgentHostnameError::RequestTimeout)?
        .map_err(AgentHostnameError::Protocol)?;
        timeout(
            self.config.request_timeout,
            read_hostname_message(&mut stream),
        )
        .await
        .map_err(|_| AgentHostnameError::RequestTimeout)?
        .map_err(AgentHostnameError::Protocol)?
        .ok_or(AgentHostnameError::UnexpectedResponse)
    }
}

#[derive(Debug)]
pub enum AgentHostnameError {
    InvalidConfig,
    TlsConfig(AgentTlsConfigError),
    ConnectTimeout,
    Connect,
    HandshakeTimeout,
    Tls,
    Alpn,
    RequestTimeout,
    Protocol(HostnameProtocolError),
    Rejected(HostnameErrorCode),
    UnexpectedResponse,
}

impl std::fmt::Display for AgentHostnameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "hostname client configuration is invalid",
            Self::TlsConfig(_) => "hostname client TLS configuration is invalid",
            Self::ConnectTimeout => "hostname server connection timed out",
            Self::Connect => "hostname server connection failed",
            Self::HandshakeTimeout => "hostname TLS handshake timed out",
            Self::Tls => "hostname TLS handshake failed",
            Self::Alpn => "hostname ALPN negotiation failed",
            Self::RequestTimeout => "hostname request timed out",
            Self::Protocol(_) => "hostname protocol failed",
            Self::Rejected(_) => "hostname request was rejected",
            Self::UnexpectedResponse => "hostname server returned an unexpected response",
        })
    }
}

impl std::error::Error for AgentHostnameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_debug_redacts_pem_and_zero_deadlines_fail_before_tls_parsing() {
        let config = HostnameClientConfig {
            server_addr: "127.0.0.1:7400".parse().unwrap(),
            server_name: "control.test".to_owned(),
            server_ca_pem: b"secret-ca".to_vec(),
            client_cert_pem: b"secret-cert".to_vec(),
            client_key_pem: b"secret-key".to_vec(),
            connect_timeout: Duration::ZERO,
            handshake_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(matches!(
            AgentHostnameClient::new(config),
            Err(AgentHostnameError::InvalidConfig)
        ));
    }
}
