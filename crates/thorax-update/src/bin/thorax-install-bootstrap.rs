use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use thorax_update::{
    accept_signed_manifest_bytes, detect_target, download, record_installed, verify_artifact_bytes,
    ReleaseArtifactV1, Version, CLI_ARTIFACT_KIND, MANIFEST_FILE, MAX_EXTRACTED_BINARY_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(err) = run() {
        eprintln!("thorax install: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let opts = Opts::parse(env::args().skip(1).collect())?;
    let base_url = opts.base_url.trim_end_matches('/').to_string();
    require_https(&base_url)?;

    let manifest_url = format!("{base_url}/{MANIFEST_FILE}");
    eprintln!("downloading {manifest_url}");
    let manifest_bytes = download::download_small(&manifest_url)?;
    let validated = accept_signed_manifest_bytes(&manifest_bytes)?;
    let manifest = &validated.manifest;
    let offered = manifest.version()?;
    let minimum = Version::current();
    if offered < minimum {
        return Err(
            format!("refusing release {offered}, older than bootstrap minimum {minimum}").into(),
        );
    }

    let target = detect_target()?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == CLI_ARTIFACT_KIND && artifact.target.triple == target.triple
        })
        .ok_or_else(|| {
            format!(
                "MANIFEST.cord has no {CLI_ARTIFACT_KIND} artifact for {}",
                target.triple
            )
        })?;

    let artifact_url = resolve_artifact_url(&base_url, artifact)?;
    eprintln!("downloading {artifact_url}");
    let download_limit = usize::try_from(artifact.size)
        .ok()
        .filter(|size| *size <= download::MAX_ARTIFACT_BYTES)
        .ok_or("signed artifact size exceeds the bootstrap safety limit")?;
    let artifact_bytes = download::download_with_progress_bounded(&artifact_url, download_limit)?;
    verify_artifact_bytes(artifact, &artifact_bytes)?;

    let tmp = TempDir::new()?;
    let binary_path = materialize_artifact(&tmp, artifact, &artifact_bytes)?;
    let installed = install_binary(&binary_path, &opts.install_dir)?;
    record_installed(&validated.accepted)?;
    eprintln!(
        "installed thorax {} at {}",
        manifest.version,
        installed.display()
    );
    Ok(())
}

fn resolve_artifact_url(base_url: &str, artifact: &ReleaseArtifactV1) -> Result<String> {
    let url = artifact
        .url
        .clone()
        .unwrap_or_else(|| format!("{base_url}/{}", artifact.name));
    require_https(&url)?;
    Ok(url)
}

fn require_https(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-HTTPS download URL: {url}").into())
    }
}

fn materialize_artifact(
    tmp: &TempDir,
    artifact: &ReleaseArtifactV1,
    artifact_bytes: &[u8],
) -> Result<PathBuf> {
    let binary_path = tmp.path().join(binary_name());

    match artifact.format.as_str() {
        "raw" | "binary" => {
            std::fs::write(&binary_path, artifact_bytes)?;
        }
        "gz" | "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(artifact_bytes);
            let mut out = std::fs::File::create(&binary_path)?;
            let written = std::io::copy(
                &mut std::io::Read::take(&mut decoder, MAX_EXTRACTED_BINARY_BYTES + 1),
                &mut out,
            )?;
            if written > MAX_EXTRACTED_BINARY_BYTES {
                return Err("decompressed binary exceeds the bootstrap safety limit".into());
            }
        }
        other => return Err(format!("unsupported install artifact format: {other}").into()),
    }

    make_executable(&binary_path)?;
    Ok(binary_path)
}

fn install_binary(binary_path: &Path, install_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(install_dir)?;
    let destination = install_dir.join(binary_name());
    let mut staged = tempfile::Builder::new()
        .prefix(&format!(".{}.install.", binary_name()))
        .tempfile_in(install_dir)?;
    let mut source = std::fs::File::open(binary_path)?;
    std::io::copy(&mut source, staged.as_file_mut())?;
    staged.as_file().sync_all()?;
    make_executable(staged.path())?;
    staged.persist(&destination)?;
    #[cfg(unix)]
    std::fs::File::open(install_dir)?.sync_all()?;
    Ok(destination)
}

fn binary_name() -> &'static str {
    if cfg!(windows) {
        "thorax.exe"
    } else {
        "thorax"
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

struct Opts {
    base_url: String,
    install_dir: PathBuf,
}

impl Opts {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut base_url = None;
        let mut install_dir = None;
        let mut idx = 0;

        while idx < args.len() {
            match args[idx].as_str() {
                "--base-url" => {
                    idx += 1;
                    base_url = args.get(idx).cloned();
                }
                "--install-dir" => {
                    idx += 1;
                    install_dir = args.get(idx).map(PathBuf::from);
                }
                "-h" | "--help" => {
                    usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
            idx += 1;
        }

        Ok(Opts {
            base_url: base_url.ok_or("missing required --base-url")?,
            install_dir: install_dir.ok_or("missing required --install-dir")?,
        })
    }
}

fn usage() {
    eprintln!(
        "\
usage: thorax-install-bootstrap --base-url URL --install-dir DIR

Downloads and verifies MANIFEST.cord, then installs the signed thorax-cli
artifact for the current platform.
"
    );
}
