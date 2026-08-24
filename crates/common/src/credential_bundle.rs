use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct AgentCredentialPaths {
    pub server_ca: PathBuf,
    pub client_certificate: PathBuf,
    pub client_private_key: PathBuf,
    pub reload_manifest: PathBuf,
}

impl AgentCredentialPaths {
    pub fn validate(&self) -> Result<(), CredentialBundleError> {
        if [
            &self.server_ca,
            &self.client_certificate,
            &self.client_private_key,
            &self.reload_manifest,
        ]
        .iter()
        .any(|path| path.as_os_str().is_empty() || path.parent().is_none())
        {
            return Err(CredentialBundleError::InvalidPath);
        }
        Ok(())
    }
}

pub fn publish_agent_credential_bundle(
    paths: &AgentCredentialPaths,
    generation: u64,
    server_ca_pem: &[u8],
    client_certificate_pem: &[u8],
    client_private_key_pem: &[u8],
) -> Result<(), CredentialBundleError> {
    paths.validate()?;
    if generation == 0
        || server_ca_pem.is_empty()
        || client_certificate_pem.is_empty()
        || client_private_key_pem.is_empty()
    {
        return Err(CredentialBundleError::InvalidMaterial);
    }
    replace_file(&paths.server_ca, server_ca_pem, false)?;
    replace_file(&paths.client_certificate, client_certificate_pem, false)?;
    replace_file(&paths.client_private_key, client_private_key_pem, true)?;

    let mut files = BTreeMap::new();
    files.insert("server_ca", digest_hex(server_ca_pem));
    files.insert("client_certificate", digest_hex(client_certificate_pem));
    files.insert("client_private_key", digest_hex(client_private_key_pem));
    let manifest = serde_json::to_vec(&CredentialManifest { generation, files })
        .map_err(|_| CredentialBundleError::Manifest)?;
    replace_file(&paths.reload_manifest, &manifest, false)
}

pub fn replace_secret_file(path: &Path, bytes: &[u8]) -> Result<(), CredentialBundleError> {
    if path.as_os_str().is_empty() || path.parent().is_none() || bytes.is_empty() {
        return Err(CredentialBundleError::InvalidPath);
    }
    replace_file(path, bytes, true)
}

fn replace_file(path: &Path, bytes: &[u8], private: bool) -> Result<(), CredentialBundleError> {
    #[cfg(not(unix))]
    let _ = private;
    let parent = path.parent().ok_or(CredentialBundleError::InvalidPath)?;
    fs::create_dir_all(parent).map_err(|_| CredentialBundleError::Io)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(CredentialBundleError::InvalidPath)?;
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| CredentialBundleError::Io)?;
        file.write_all(bytes)
            .map_err(|_| CredentialBundleError::Io)?;
        file.sync_all().map_err(|_| CredentialBundleError::Io)?;
        drop(file);
        if path.exists() {
            fs::remove_file(path).map_err(|_| CredentialBundleError::Io)?;
        }
        fs::rename(&temporary, path).map_err(|_| CredentialBundleError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Serialize)]
struct CredentialManifest<'a> {
    generation: u64,
    files: BTreeMap<&'a str, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBundleError {
    InvalidPath,
    InvalidMaterial,
    Manifest,
    Io,
}

impl std::fmt::Display for CredentialBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPath => "credential bundle path is invalid",
            Self::InvalidMaterial => "credential bundle material is invalid",
            Self::Manifest => "credential reload manifest could not be encoded",
            Self::Io => "credential bundle could not be published",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CredentialBundleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_bundle_is_published_with_manifest_last() {
        let directory = std::env::temp_dir().join(format!(
            "tunnelproxy-agent-credentials-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let paths = AgentCredentialPaths {
            server_ca: directory.join("edge-ca.pem"),
            client_certificate: directory.join("agent.pem"),
            client_private_key: directory.join("agent-key.pem"),
            reload_manifest: directory.join("reload.json"),
        };
        publish_agent_credential_bundle(&paths, 9, b"ca", b"certificate", b"private-key").unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&paths.reload_manifest).unwrap()).unwrap();
        assert_eq!(manifest["generation"], 9);
        assert_eq!(fs::read(&paths.client_private_key).unwrap(), b"private-key");
        fs::remove_dir_all(directory).unwrap();
    }
}
