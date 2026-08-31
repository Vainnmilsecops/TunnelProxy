use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const MAX_RELOAD_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_RELOAD_MATERIAL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationReloadFile {
    pub name: String,
    pub path: PathBuf,
}

impl GenerationReloadFile {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GenerationReload {
    generation: u64,
    manifest_digest: [u8; 32],
    files: BTreeMap<String, Vec<u8>>,
}

impl GenerationReload {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub fn file(&self, name: &str) -> Result<&[u8], GenerationReloadError> {
        self.files
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| GenerationReloadError::MissingFile(name.to_owned()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    generation: u64,
    files: BTreeMap<String, String>,
}

pub async fn load_generation_reload(
    manifest_path: PathBuf,
    files: Vec<GenerationReloadFile>,
) -> Result<GenerationReload, GenerationReloadError> {
    tokio::task::spawn_blocking(move || load_generation_sync(&manifest_path, &files))
        .await
        .map_err(|_| GenerationReloadError::Task)?
}

fn load_generation_sync(
    manifest_path: &Path,
    files: &[GenerationReloadFile],
) -> Result<GenerationReload, GenerationReloadError> {
    let manifest_bytes = read_bounded(manifest_path, MAX_RELOAD_MANIFEST_BYTES)
        .map_err(GenerationReloadError::ManifestIo)?;
    let manifest: RawManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| GenerationReloadError::ManifestSyntax)?;
    if manifest.generation == 0 || manifest.files.is_empty() {
        return Err(GenerationReloadError::InvalidManifest);
    }
    let expected: BTreeSet<_> = files.iter().map(|file| file.name.as_str()).collect();
    let declared: BTreeSet<_> = manifest.files.keys().map(String::as_str).collect();
    if expected != declared || expected.len() != files.len() {
        return Err(GenerationReloadError::FileSet);
    }

    let mut loaded = BTreeMap::new();
    for file in files {
        if file.name.is_empty() {
            return Err(GenerationReloadError::FileSet);
        }
        let expected_digest = decode_digest(
            manifest
                .files
                .get(&file.name)
                .ok_or(GenerationReloadError::FileSet)?,
        )?;
        let bytes = read_bounded(&file.path, MAX_RELOAD_MATERIAL_BYTES)
            .map_err(|_| GenerationReloadError::MaterialIo(file.name.clone()))?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != expected_digest {
            return Err(GenerationReloadError::DigestMismatch(file.name.clone()));
        }
        loaded.insert(file.name.clone(), bytes);
    }
    Ok(GenerationReload {
        generation: manifest.generation,
        manifest_digest: Sha256::digest(manifest_bytes).into(),
        files: loaded,
    })
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > limit as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bounded reload input exceeds its limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bounded reload input exceeds its limit",
        ));
    }
    Ok(bytes)
}

fn decode_digest(value: &str) -> Result<[u8; 32], GenerationReloadError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GenerationReloadError::InvalidDigest);
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| GenerationReloadError::InvalidDigest)?;
    }
    Ok(digest)
}

#[derive(Debug)]
pub enum GenerationReloadError {
    ManifestIo(std::io::Error),
    MaterialIo(String),
    ManifestSyntax,
    InvalidManifest,
    InvalidDigest,
    FileSet,
    DigestMismatch(String),
    MissingFile(String),
    Task,
}

impl std::fmt::Display for GenerationReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestIo(_) => formatter.write_str("reload manifest could not be read"),
            Self::MaterialIo(name) => write!(formatter, "reload material {name} could not be read"),
            Self::ManifestSyntax => formatter.write_str("reload manifest is invalid JSON"),
            Self::InvalidManifest => formatter.write_str("reload manifest fields are invalid"),
            Self::InvalidDigest => {
                formatter.write_str("reload manifest contains an invalid digest")
            }
            Self::FileSet => {
                formatter.write_str("reload manifest file set does not match configuration")
            }
            Self::DigestMismatch(name) => write!(
                formatter,
                "reload material {name} does not match its manifest digest"
            ),
            Self::MissingFile(name) => write!(formatter, "reload material {name} is missing"),
            Self::Task => formatter.write_str("reload blocking task failed"),
        }
    }
}

impl std::error::Error for GenerationReloadError {}
