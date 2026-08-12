//! Signed release manifest model, version detection, target detection, and release URL construction.
//!
//! The signed manifest schema is provider-neutral. GitHub Releases are only the
//! current transport used by the default URL resolver.

use std::{cmp::Ordering, collections::BTreeSet, env, time::Duration};

use cord::Cord;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::verify::{verify_signed_manifest, VerifyError};
use crate::{download::MAX_ARTIFACT_BYTES, state::AcceptedReleaseV1};

/// The default release repository used by the current GitHub Releases transport.
pub const REPO: &str = "backbone-hq/thorax";

/// Signed release manifest asset name.
pub const MANIFEST_FILE: &str = "MANIFEST.cord";

/// Release artifact kind used by `thorax update` for the self-updatable CLI.
pub const CLI_ARTIFACT_KIND: &str = "thorax-cli";
pub const MAX_MANIFEST_ARTIFACTS: usize = 4096;
pub const MAX_MANIFEST_KEYS: usize = 64;
pub const MAX_MANIFEST_FIELD_BYTES: usize = 4096;

/// Build target metadata for an artifact. Empty optional fields mean "not applicable".
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtifactTargetV1 {
    pub triple: String,
    pub os: String,
    pub arch: String,
    pub abi: Option<String>,
}

/// One release asset covered by the signed manifest.
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseArtifactV1 {
    /// Stable artifact name within the release.
    pub name: String,
    /// Logical artifact kind, for example `thorax-cli`, `python-wheel`, `npm-tarball`, or `sbom`.
    pub kind: String,
    /// Packaging/install format, for example `raw`, `gz`, `zip`, `msi`, `pkg`, `whl`, or `tgz`.
    pub format: String,
    /// Optional direct URL. If absent, clients resolve `name` through the configured transport.
    pub url: Option<String>,
    /// Target metadata. Non-installable shared artifacts may leave fields empty.
    pub target: ArtifactTargetV1,
    /// Expected artifact byte length.
    pub size: u64,
    /// SHA-256 digest of the exact release asset bytes.
    pub sha256: Vec<u8>,
}

/// Source/provenance pointers for the build that produced the release artifacts.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct ReleaseSourceV1 {
    pub tag: String,
    pub commit: String,
    /// GitHub Actions run that produced the unsigned artifact set. Identification, not trust:
    /// the offline signature binds it so an operator can audit the exact CI execution.
    pub workflow_run_id: String,
}

/// Additive key/delegation seam. V1 clients only enforce the compiled-in release key.
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseKeyV1 {
    pub role: String,
    pub public_key: Vec<u8>,
}

/// V1 release manifest body. Its canonical cord bytes are the signature preimage.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct ReleaseManifestV1 {
    pub version: String,
    pub release_epoch: u64,
    pub published_at: String,
    pub source: ReleaseSourceV1,
    pub artifacts: Vec<ReleaseArtifactV1>,
    pub keys: Vec<ReleaseKeyV1>,
}

/// Versioned release manifest body.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub enum ReleaseManifest {
    #[cord(index = 0)]
    V1(ReleaseManifestV1),
}

/// Signed release manifest file. The signature covers `body`'s canonical cord bytes.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct SignedReleaseManifest {
    pub body: ReleaseManifest,
    pub signing_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ReleaseManifest {
    pub fn v1(&self) -> &ReleaseManifestV1 {
        match self {
            ReleaseManifest::V1(v1) => v1,
        }
    }
}

impl ReleaseManifestV1 {
    pub fn version(&self) -> Result<Version, ManifestError> {
        Version::parse(&self.version)
    }

    pub fn cli_artifact_for_current_platform(&self) -> Result<&ReleaseArtifactV1, ManifestError> {
        let target = detect_target()?;
        let matches = self
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == CLI_ARTIFACT_KIND && artifact.target.triple == target.triple
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(ManifestError::MissingArtifact {
                kind: CLI_ARTIFACT_KIND.to_string(),
                target: target.triple,
            });
        }
        if matches.len() != 1 {
            return Err(ManifestError::DuplicatePlatformArtifact {
                kind: CLI_ARTIFACT_KIND.to_string(),
                target: target.triple,
            });
        }
        let artifact = matches[0];
        if !matches!(artifact.format.as_str(), "raw" | "binary" | "gz" | "gzip") {
            return Err(ManifestError::UnsupportedArtifactFormat {
                format: artifact.format.clone(),
            });
        }
        Ok(artifact)
    }
}

/// Detected build target metadata for the running binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentTarget {
    pub triple: String,
    pub os: String,
    pub arch: String,
    pub abi: Option<String>,
}

/// Detect the current platform target triple.
pub fn detect_target() -> Result<CurrentTarget, ManifestError> {
    let arch = env::consts::ARCH;
    let os = env::consts::OS;

    let (triple, abi) = match (os, arch) {
        ("linux", "x86_64") => ("x86_64-unknown-linux-gnu", Some("gnu")),
        ("linux", "aarch64") => ("aarch64-unknown-linux-gnu", Some("gnu")),
        ("macos", "x86_64") => ("x86_64-apple-darwin", Some("darwin")),
        ("macos", "aarch64") => ("aarch64-apple-darwin", Some("darwin")),
        ("windows", "x86_64") => ("x86_64-pc-windows-msvc", Some("msvc")),
        ("windows", "aarch64") => ("aarch64-pc-windows-msvc", Some("msvc")),
        _ => {
            return Err(ManifestError::UnsupportedPlatform {
                os: os.to_string(),
                arch: arch.to_string(),
            });
        }
    };

    Ok(CurrentTarget {
        triple: triple.to_string(),
        os: os.to_string(),
        arch: arch.to_string(),
        abi: abi.map(str::to_string),
    })
}

/// Construct the download URL for a release asset using the current default transport.
pub fn asset_url(owner_repo: &str, filename: &str) -> String {
    format!(
        "https://github.com/{owner_repo}/releases/latest/download/{filename}",
        owner_repo = owner_repo,
        filename = filename
    )
}

/// Resolve an artifact URL, using the direct manifest URL when present.
pub fn artifact_url(owner_repo: &str, artifact: &ReleaseArtifactV1) -> String {
    artifact
        .url
        .clone()
        .unwrap_or_else(|| asset_url(owner_repo, &artifact.name))
}

/// Build release URLs for the current update metadata.
pub struct ReleaseUrls {
    pub manifest_url: String,
    pub platform: CurrentTarget,
}

impl ReleaseUrls {
    pub fn for_current_platform(repo: &str) -> Result<Self, ManifestError> {
        Ok(ReleaseUrls {
            manifest_url: asset_url(repo, MANIFEST_FILE),
            platform: detect_target()?,
        })
    }
}

/// A parsed semantic version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parse a semver string ("0.1.0") into components.
    pub fn parse(s: &str) -> Result<Self, ManifestError> {
        let s = s.trim();
        let parts: Vec<&str> = s.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(ManifestError::BadVersion {
                raw: s.to_string(),
                detail: "expected exactly 3 dot-separated components (major.minor.patch)"
                    .to_string(),
            });
        }
        let major = parse_version_component(s, "major", parts[0])?;
        let minor = parse_version_component(s, "minor", parts[1])?;
        let patch = parse_version_component(s, "patch", parts[2])?;
        Ok(Version {
            major,
            minor,
            patch,
        })
    }

    /// The current binary's version, from `CARGO_PKG_VERSION`.
    pub fn current() -> Self {
        // Unwrap is safe: our own Cargo.toml version is always valid semver.
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
    }

    pub fn release_epoch(&self) -> Result<u64, ManifestError> {
        if self.minor >= 1_000 || self.patch >= 1_000 {
            return Err(ManifestError::BadVersion {
                raw: self.to_string(),
                detail: "minor and patch components must be below 1000".to_string(),
            });
        }
        self.major
            .checked_mul(1_000_000)
            .and_then(|value| value.checked_add(self.minor * 1_000))
            .and_then(|value| value.checked_add(self.patch))
            .ok_or_else(|| ManifestError::BadVersion {
                raw: self.to_string(),
                detail: "derived release epoch overflows u64".to_string(),
            })
    }
}

fn parse_version_component(raw: &str, name: &str, component: &str) -> Result<u64, ManifestError> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ManifestError::BadVersion {
            raw: raw.to_string(),
            detail: format!("{name} version is not an unsigned decimal integer"),
        });
    }
    if component.len() > 1 && component.starts_with('0') {
        return Err(ManifestError::BadVersion {
            raw: raw.to_string(),
            detail: format!("{name} version has a leading zero"),
        });
    }
    component
        .parse()
        .map_err(|error| ManifestError::BadVersion {
            raw: raw.to_string(),
            detail: format!("{name} version is not a valid integer: {error}"),
        })
}

pub fn derive_release_epoch(version: &str) -> Result<u64, ManifestError> {
    Version::parse(version)?.release_epoch()
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse a version string from a legacy VERSION endpoint body.
pub fn parse_latest_version(body: &str) -> Result<Version, ManifestError> {
    Version::parse(body.trim())
}

/// Fetch and verify the latest signed manifest from the configured release transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedReleaseManifest {
    pub manifest: ReleaseManifestV1,
    pub accepted: AcceptedReleaseV1,
}

pub fn fetch_latest_manifest(repo: &str) -> Result<ValidatedReleaseManifest, ManifestError> {
    let url = asset_url(repo, MANIFEST_FILE);
    let bytes = crate::download::download_small(&url).map_err(|e| ManifestError::Network {
        detail: e.to_string(),
    })?;
    parse_signed_manifest_bytes(&bytes)
}

/// Fetch and verify the latest signed manifest with caller-supplied short timeouts.
pub fn fetch_latest_manifest_with_timeout(
    repo: &str,
    connect: Duration,
    global: Duration,
) -> Result<ValidatedReleaseManifest, ManifestError> {
    let url = asset_url(repo, MANIFEST_FILE);
    let bytes =
        crate::download::download_small_with_timeout(&url, connect, global).map_err(|e| {
            ManifestError::Network {
                detail: e.to_string(),
            }
        })?;
    parse_signed_manifest_bytes(&bytes)
}

pub fn accept_signed_manifest_bytes(
    bytes: &[u8],
) -> Result<ValidatedReleaseManifest, ManifestError> {
    let manifest = verify_signed_manifest(bytes).map_err(ManifestError::Verify)?;
    let manifest = manifest.v1().clone();
    validate_complete_manifest(&manifest)?;
    let accepted = AcceptedReleaseV1 {
        version: manifest.version.clone(),
        epoch: manifest.release_epoch,
        signed_manifest_sha256: Some(Sha256::digest(bytes).to_vec()),
    };
    crate::state::accept_seen(&accepted).map_err(ManifestError::ReleaseState)?;
    Ok(ValidatedReleaseManifest { manifest, accepted })
}

fn parse_signed_manifest_bytes(bytes: &[u8]) -> Result<ValidatedReleaseManifest, ManifestError> {
    accept_signed_manifest_bytes(bytes)
}

pub fn validate_complete_manifest(manifest: &ReleaseManifestV1) -> Result<(), ManifestError> {
    let version = manifest.version()?;
    let derived = version.release_epoch()?;
    if manifest.release_epoch != derived {
        return Err(ManifestError::EpochMismatch {
            version: manifest.version.clone(),
            declared: manifest.release_epoch,
            derived,
        });
    }
    let published = OffsetDateTime::parse(&manifest.published_at, &Rfc3339).map_err(|error| {
        ManifestError::BadPublishedAt {
            value: manifest.published_at.clone(),
            detail: error.to_string(),
        }
    })?;
    if published > OffsetDateTime::now_utc() + time::Duration::hours(24) {
        return Err(ManifestError::PublishedInFuture {
            value: manifest.published_at.clone(),
        });
    }
    bounded_field("version", &manifest.version, 64)?;
    bounded_field("published_at", &manifest.published_at, 128)?;
    bounded_field("source tag", &manifest.source.tag, MAX_MANIFEST_FIELD_BYTES)?;
    bounded_field(
        "source commit",
        &manifest.source.commit,
        MAX_MANIFEST_FIELD_BYTES,
    )?;
    bounded_field(
        "workflow run ID",
        &manifest.source.workflow_run_id,
        MAX_MANIFEST_FIELD_BYTES,
    )?;
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_MANIFEST_ARTIFACTS {
        return Err(ManifestError::InvalidManifest(
            "artifact list is empty or exceeds the supported maximum".into(),
        ));
    }
    if manifest.keys.len() > MAX_MANIFEST_KEYS {
        return Err(ManifestError::InvalidManifest(
            "release key list exceeds the supported maximum".into(),
        ));
    }
    let mut names = BTreeSet::new();
    for artifact in &manifest.artifacts {
        bounded_field("artifact name", &artifact.name, 255)?;
        bounded_field("artifact kind", &artifact.kind, 128)?;
        bounded_field("artifact format", &artifact.format, 64)?;
        bounded_optional_field("artifact target triple", &artifact.target.triple, 255)?;
        bounded_optional_field("artifact target OS", &artifact.target.os, 64)?;
        bounded_optional_field("artifact target architecture", &artifact.target.arch, 64)?;
        if let Some(abi) = &artifact.target.abi {
            bounded_optional_field("artifact target ABI", abi, 64)?;
        }
        if let Some(url) = &artifact.url {
            bounded_field("artifact URL", url, MAX_MANIFEST_FIELD_BYTES)?;
        }
        if !names.insert(artifact.name.clone()) {
            return Err(ManifestError::InvalidManifest(format!(
                "duplicate artifact name {:?}",
                artifact.name
            )));
        }
        if artifact.size == 0 || artifact.size > MAX_ARTIFACT_BYTES as u64 {
            return Err(ManifestError::InvalidManifest(format!(
                "artifact {:?} has an invalid size",
                artifact.name
            )));
        }
        if artifact.sha256.len() != 32 {
            return Err(ManifestError::InvalidManifest(format!(
                "artifact {:?} SHA-256 is not 32 bytes",
                artifact.name
            )));
        }
    }
    for key in &manifest.keys {
        bounded_field("release key role", &key.role, 128)?;
        if key.public_key.is_empty() || key.public_key.len() > MAX_MANIFEST_FIELD_BYTES {
            return Err(ManifestError::InvalidManifest(
                "release public key is empty or too large".into(),
            ));
        }
    }
    let _ = manifest.cli_artifact_for_current_platform()?;
    Ok(())
}

fn bounded_field(name: &str, value: &str, max: usize) -> Result<(), ManifestError> {
    if value.is_empty() || value.len() > max {
        return Err(ManifestError::InvalidManifest(format!(
            "{name} is empty or exceeds {max} bytes"
        )));
    }
    Ok(())
}

fn bounded_optional_field(name: &str, value: &str, max: usize) -> Result<(), ManifestError> {
    if value.len() > max {
        return Err(ManifestError::InvalidManifest(format!(
            "{name} exceeds {max} bytes"
        )));
    }
    Ok(())
}

/// Fetch the latest version from the signed manifest.
pub fn fetch_latest_version(repo: &str) -> Result<Version, ManifestError> {
    fetch_latest_manifest(repo)?.manifest.version()
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("unsupported platform: {os}-{arch}")]
    UnsupportedPlatform { os: String, arch: String },
    #[error("failed to parse version from {raw:?}: {detail}")]
    BadVersion { raw: String, detail: String },
    #[error("network error: {detail}")]
    Network { detail: String },
    #[error("manifest verification error: {0}")]
    Verify(#[from] VerifyError),
    #[error("release state check failed: {0}")]
    ReleaseState(#[from] crate::state::StateError),
    #[error("missing release artifact kind {kind:?} for target {target:?}")]
    MissingArtifact { kind: String, target: String },
    #[error("multiple release artifacts of kind {kind:?} target {target:?}")]
    DuplicatePlatformArtifact { kind: String, target: String },
    #[error("unsupported CLI artifact format {format:?}")]
    UnsupportedArtifactFormat { format: String },
    #[error("release {version} declares epoch {declared}, derived epoch is {derived}")]
    EpochMismatch {
        version: String,
        declared: u64,
        derived: u64,
    },
    #[error("invalid published_at {value:?}: {detail}")]
    BadPublishedAt { value: String, detail: String },
    #[error("release published_at {value:?} is implausibly far in the future")]
    PublishedInFuture { value: String },
    #[error("invalid release manifest: {0}")]
    InvalidManifest(String),
    #[error("release version {offered} is older than this binary {current}")]
    OlderThanCurrent { offered: String, current: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ArtifactTargetV1 {
        ArtifactTargetV1 {
            triple: "x86_64-unknown-linux-gnu".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            abi: Some("gnu".to_string()),
        }
    }

    fn valid_manifest() -> ReleaseManifestV1 {
        let current = detect_target().unwrap();
        ReleaseManifestV1 {
            version: "1.0.0".into(),
            release_epoch: 1_000_000,
            published_at: "2026-08-12T00:00:00Z".into(),
            source: ReleaseSourceV1 {
                tag: "v1.0.0".into(),
                commit: "0123456789abcdef".into(),
                workflow_run_id: "123".into(),
            },
            artifacts: vec![ReleaseArtifactV1 {
                name: "thorax".into(),
                kind: CLI_ARTIFACT_KIND.into(),
                format: "raw".into(),
                url: None,
                target: ArtifactTargetV1 {
                    triple: current.triple,
                    os: current.os,
                    arch: current.arch,
                    abi: current.abi,
                },
                size: 1,
                sha256: vec![0; 32],
            }],
            keys: Vec::new(),
        }
    }

    #[test]
    fn test_detect_target_runs() {
        let target = detect_target().unwrap();
        assert!(!target.triple.is_empty());
    }

    #[test]
    fn test_asset_url_format() {
        let url = asset_url("backbone-hq/thorax", "MANIFEST.cord");
        assert_eq!(
            url,
            "https://github.com/backbone-hq/thorax/releases/latest/download/MANIFEST.cord"
        );
    }

    #[test]
    fn test_parse_latest_version_ok() {
        let v = parse_latest_version("0.2.0\n").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_parse_latest_version_bad() {
        let err = parse_latest_version("not-a-version").unwrap_err();
        assert!(matches!(err, ManifestError::BadVersion { .. }));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("0.1.0").unwrap();
        let v2 = Version::parse("0.2.0").unwrap();
        let v3 = Version::parse("1.0.0").unwrap();
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 == v1);
    }

    #[test]
    fn test_artifact_url_prefers_direct_url() {
        let artifact = ReleaseArtifactV1 {
            name: "thorax".to_string(),
            kind: CLI_ARTIFACT_KIND.to_string(),
            format: "raw".to_string(),
            url: Some("https://example.test/thorax".to_string()),
            target: target(),
            size: 1,
            sha256: vec![0; 32],
        };
        assert_eq!(
            artifact_url("backbone-hq/thorax", &artifact),
            "https://example.test/thorax"
        );
    }

    #[test]
    fn release_epoch_is_deterministic_and_bounded() {
        assert_eq!(derive_release_epoch("2.34.56").unwrap(), 2_034_056);
        assert!(derive_release_epoch("1.1000.0").is_err());
        assert!(derive_release_epoch("1.0.1000").is_err());
        assert!(derive_release_epoch("1.0.0-alpha").is_err());
        assert!(derive_release_epoch("01.0.0").is_err());
        assert!(derive_release_epoch("18446744073710.0.0").is_err());
    }

    #[test]
    fn complete_manifest_rejects_epoch_mismatch_and_duplicate_platform_artifacts() {
        let mut manifest = valid_manifest();
        manifest.release_epoch += 1;
        assert!(matches!(
            validate_complete_manifest(&manifest),
            Err(ManifestError::EpochMismatch { .. })
        ));

        let mut manifest = valid_manifest();
        let mut duplicate = manifest.artifacts[0].clone();
        duplicate.name = "thorax-copy".into();
        manifest.artifacts.push(duplicate);
        assert!(matches!(
            validate_complete_manifest(&manifest),
            Err(ManifestError::DuplicatePlatformArtifact { .. })
        ));
    }

    #[test]
    fn complete_manifest_rejects_future_timestamp_and_bad_artifact_hash() {
        let mut future = valid_manifest();
        future.published_at = "9999-01-01T00:00:00Z".into();
        assert!(matches!(
            validate_complete_manifest(&future),
            Err(ManifestError::PublishedInFuture { .. })
        ));

        let mut bad_hash = valid_manifest();
        bad_hash.artifacts[0].sha256.pop();
        assert!(matches!(
            validate_complete_manifest(&bad_hash),
            Err(ManifestError::InvalidManifest(_))
        ));
    }

    #[test]
    fn complete_manifest_accepts_the_current_platform_artifact() {
        validate_complete_manifest(&valid_manifest()).unwrap();
    }
}
