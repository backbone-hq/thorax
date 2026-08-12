//! Signed self-update for the `thorax` binary.
//!
//! This crate fetches, verifies, and applies updates from the configured release transport.
//! Verification happens before decompression or process replacement.

use std::io::{self, Read};
use std::time::Duration;

use flate2::read::GzDecoder;
use tempfile::TempDir;

pub mod download;
pub mod manifest;
pub mod state;
pub mod verify;

pub use download::download_with_progress;
pub const MAX_EXTRACTED_BINARY_BYTES: u64 = 512 * 1024 * 1024;
pub use manifest::{
    accept_signed_manifest_bytes, artifact_url, derive_release_epoch, detect_target,
    fetch_latest_manifest, fetch_latest_version, parse_latest_version, validate_complete_manifest,
    ArtifactTargetV1, ReleaseArtifactV1, ReleaseKeyV1, ReleaseManifest, ReleaseManifestV1,
    ReleaseSourceV1, ReleaseUrls, SignedReleaseManifest, ValidatedReleaseManifest, Version,
    CLI_ARTIFACT_KIND, MANIFEST_FILE, REPO,
};
pub use state::{
    accept_seen, read_update_state, record_installed, update_state_base, AcceptedReleaseV1,
    StateError, UpdateStateV1, UPDATE_STATE_DIR_ENV,
};
pub use verify::{
    manifest_body_bytes, manifest_signature_message, signed_manifest_bytes, verify_artifact_bytes,
    verify_signed_archive, verify_signed_manifest, verify_signed_manifest_with_key,
    RELEASE_MANIFEST_DOMAIN,
};

/// The compiled-in release repository override. Set at build time or defaults.
const DEFAULT_REPO: &str = REPO;

/// Run a full update check → download → verify → replace cycle.
///
/// * `check_only` — if true, only compare versions and report, don't download.
/// * `repo` — optional override for the release repository used in URL construction.
pub fn update(check_only: bool, repo: Option<&str>) -> Result<UpdateOutcome, UpdateError> {
    let repo = repo.unwrap_or(DEFAULT_REPO);

    let validated = fetch_latest_manifest(repo).map_err(UpdateError::Manifest)?;
    let manifest = &validated.manifest;
    let latest = manifest.version().map_err(UpdateError::Manifest)?;
    let current = Version::current();

    if latest < current {
        return Err(UpdateError::Manifest(
            manifest::ManifestError::OlderThanCurrent {
                offered: latest.to_string(),
                current: current.to_string(),
            },
        ));
    }
    if latest == current {
        state::record_installed(&validated.accepted)?;
        return Ok(UpdateOutcome::UpToDate {
            current_version: current,
        });
    }

    if check_only {
        return Ok(UpdateOutcome::Available {
            current_version: current,
            latest_version: latest,
        });
    }

    let artifact = manifest
        .cli_artifact_for_current_platform()
        .map_err(UpdateError::Manifest)?;
    let artifact_url = artifact_url(repo, artifact);
    let download_limit = usize::try_from(artifact.size)
        .ok()
        .filter(|size| *size <= download::MAX_ARTIFACT_BYTES)
        .ok_or(UpdateError::ArtifactTooLarge {
            size: artifact.size,
            max: download::MAX_ARTIFACT_BYTES as u64,
        })?;
    let artifact_bytes = download::download_with_progress_bounded(&artifact_url, download_limit)
        .map_err(|e| UpdateError::Download {
            stage: "binary download",
            source: e,
        })?;

    verify_artifact_bytes(artifact, &artifact_bytes).map_err(|e| UpdateError::Verify {
        detail: e.to_string(),
    })?;

    let tmp = TempDir::new().map_err(|e| UpdateError::Io {
        stage: "temp directory",
        detail: e.to_string(),
    })?;

    let binary_path = extract_installable_artifact(&tmp, artifact, &artifact_bytes)?;

    self_replace::self_replace(&binary_path).map_err(|e| UpdateError::Io {
        stage: "replace binary",
        detail: e.to_string(),
    })?;
    state::record_installed(&validated.accepted)?;

    // TempDir is dropped here, cleaning up the temp file.

    Ok(UpdateOutcome::Updated {
        from: current,
        to: latest,
    })
}

/// Return a human update notice suitable for passive CLI/TUI display.
///
/// This is best-effort: it is suppressed in CI/no-update mode, cached for a day, and never
/// returns errors to callers.
pub fn passive_update_notice(repo: Option<&str>) -> Option<String> {
    if passive_check_disabled() {
        return None;
    }

    if let Some(text) = state::read_passive_cache(Duration::from_secs(24 * 60 * 60)) {
        return (!text.is_empty()).then_some(text);
    }

    let repo = repo.unwrap_or(DEFAULT_REPO);
    let notice = manifest::fetch_latest_manifest_with_timeout(
        repo,
        Duration::from_millis(500),
        Duration::from_secs(2),
    )
    .ok()
    .and_then(|validated| {
        let latest = validated.manifest.version().ok()?;
        let current = Version::current();
        (latest > current)
            .then(|| format!("update available: {current} -> {latest}; run `thorax update`"))
    })
    .unwrap_or_default();

    let _ = state::write_passive_cache(&notice);
    (!notice.is_empty()).then_some(notice)
}

fn extract_installable_artifact(
    tmp: &TempDir,
    artifact: &ReleaseArtifactV1,
    artifact_bytes: &[u8],
) -> Result<std::path::PathBuf, UpdateError> {
    let binary_path = tmp.path().join(if cfg!(windows) {
        "thorax.exe"
    } else {
        "thorax"
    });

    match artifact.format.as_str() {
        "raw" | "binary" => {
            std::fs::write(&binary_path, artifact_bytes).map_err(|e| UpdateError::Io {
                stage: "write binary",
                detail: e.to_string(),
            })?;
        }
        "gz" | "gzip" => {
            let mut decoder = GzDecoder::new(artifact_bytes);
            let mut out = std::fs::File::create(&binary_path).map_err(|e| UpdateError::Io {
                stage: "extract binary",
                detail: e.to_string(),
            })?;
            let written = io::copy(
                &mut decoder.by_ref().take(MAX_EXTRACTED_BINARY_BYTES + 1),
                &mut out,
            )
            .map_err(|e| UpdateError::Io {
                stage: "decompress",
                detail: e.to_string(),
            })?;
            if written > MAX_EXTRACTED_BINARY_BYTES {
                return Err(UpdateError::ArtifactTooLarge {
                    size: written,
                    max: MAX_EXTRACTED_BINARY_BYTES,
                });
            }
        }
        other => {
            return Err(UpdateError::UnsupportedArtifactFormat {
                format: other.to_string(),
            });
        }
    }

    make_executable(&binary_path)?;
    Ok(binary_path)
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)
        .map_err(|e| UpdateError::Io {
            stage: "read binary metadata",
            detail: e.to_string(),
        })?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).map_err(|e| UpdateError::Io {
        stage: "mark binary executable",
        detail: e.to_string(),
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) -> Result<(), UpdateError> {
    Ok(())
}

fn passive_check_disabled() -> bool {
    env_flag("THORAX_NO_SELF_UPDATE") || env_flag("CI")
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

/// The result of calling `update()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Already on the latest version.
    UpToDate { current_version: Version },
    /// A new version is available (only returned when `check_only` is true).
    Available {
        current_version: Version,
        latest_version: Version,
    },
    /// The binary was successfully updated.
    Updated { from: Version, to: Version },
}

impl std::fmt::Display for UpdateOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateOutcome::UpToDate { current_version } => {
                write!(f, "Already up to date ({})", current_version)
            }
            UpdateOutcome::Available {
                current_version,
                latest_version,
            } => {
                write!(
                    f,
                    "Update available: {} → {}",
                    current_version, latest_version
                )
            }
            UpdateOutcome::Updated { from, to } => {
                write!(f, "Updated {} → {}", from, to)
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("manifest error: {0}")]
    Manifest(#[from] manifest::ManifestError),
    #[error("update state error: {0}")]
    State(#[from] state::StateError),
    #[error("download failed during {stage}: {source}")]
    Download {
        stage: &'static str,
        #[source]
        source: download::DownloadError,
    },
    #[error("signature verification failed: {detail}")]
    Verify { detail: String },
    #[error("I/O error during {stage}: {detail}")]
    Io { stage: &'static str, detail: String },
    #[error("unsupported installable artifact format: {format}")]
    UnsupportedArtifactFormat { format: String },
    #[error("release artifact is {size} bytes, above the supported maximum of {max}")]
    ArtifactTooLarge { size: u64, max: u64 },
}
