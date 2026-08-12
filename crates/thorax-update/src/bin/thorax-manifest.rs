use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use thorax_update::{
    derive_release_epoch, manifest_body_bytes, manifest_signature_message, signed_manifest_bytes,
    verify_artifact_bytes, ArtifactTargetV1, ReleaseArtifactV1, ReleaseKeyV1, ReleaseManifest,
    ReleaseManifestV1, ReleaseSourceV1, SignedReleaseManifest,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("build-body") => build_body(args.collect()),
        Some("message") => message(args.collect()),
        Some("seal") => seal(args.collect()),
        Some("verify") => verify(args.collect()),
        Some("verify-bundle") => verify_bundle(args.collect()),
        Some("inspect") => inspect(args.collect()),
        Some("-h") | Some("--help") | None => {
            usage();
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}").into()),
    }
}

fn build_body(args: Vec<String>) -> Result<()> {
    let mut opts = Opts::new(args);
    let version = opts.required("--version")?;
    let release_epoch = derive_release_epoch(&version)?;
    let published_at = opts.required("--published-at")?;
    let tag = opts.required("--tag")?;
    let commit = opts.required("--commit")?;
    let workflow_run_id = opts.required("--workflow-run-id")?;
    let out = PathBuf::from(opts.required("--out")?);
    let asset_specs = opts.repeated("--asset");
    opts.finish()?;

    if asset_specs.is_empty() {
        return Err("at least one --asset is required".into());
    }

    let mut artifacts = Vec::with_capacity(asset_specs.len());
    for spec in asset_specs {
        artifacts.push(parse_asset_spec(&spec)?);
    }
    artifacts.sort();

    let body = ReleaseManifest::V1(ReleaseManifestV1 {
        version,
        release_epoch,
        published_at,
        source: ReleaseSourceV1 {
            tag,
            commit,
            workflow_run_id,
        },
        artifacts,
        keys: Vec::<ReleaseKeyV1>::new(),
    });

    std::fs::write(out, manifest_body_bytes(&body)?)?;
    Ok(())
}

fn message(args: Vec<String>) -> Result<()> {
    let mut opts = Opts::new(args);
    let body = PathBuf::from(opts.required("--body")?);
    let out = PathBuf::from(opts.required("--out")?);
    opts.finish()?;

    let body_bytes = std::fs::read(body)?;
    std::fs::write(out, manifest_signature_message(&body_bytes))?;
    Ok(())
}

fn seal(args: Vec<String>) -> Result<()> {
    let mut opts = Opts::new(args);
    let body_path = PathBuf::from(opts.required("--body")?);
    let public_key_path = PathBuf::from(opts.required("--public-key")?);
    let signature_path = PathBuf::from(opts.required("--signature")?);
    let out = PathBuf::from(opts.required("--out")?);
    opts.finish()?;

    let body: ReleaseManifest = cord::deserialize(&std::fs::read(body_path)?)?;
    let signed = SignedReleaseManifest {
        body,
        signing_public_key: std::fs::read(public_key_path)?,
        signature: std::fs::read(signature_path)?,
    };
    std::fs::write(out, signed_manifest_bytes(&signed)?)?;
    Ok(())
}

fn verify(args: Vec<String>) -> Result<()> {
    let mut opts = Opts::new(args);
    let manifest = PathBuf::from(opts.required("--manifest")?);
    let public_key = PathBuf::from(opts.required("--public-key")?);
    opts.finish()?;

    let key_bytes = std::fs::read(public_key)?;
    let key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes")?;
    let manifest = thorax_update::verify_signed_manifest_with_key(&std::fs::read(manifest)?, &key)?;
    thorax_update::validate_complete_manifest(manifest.v1())?;
    Ok(())
}

fn verify_bundle(args: Vec<String>) -> Result<()> {
    let mut opts = Opts::new(args);
    let manifest_path = PathBuf::from(opts.required("--manifest")?);
    let public_key_path = PathBuf::from(opts.required("--public-key")?);
    let artifacts_dir = PathBuf::from(opts.required("--artifacts-dir")?);
    opts.finish()?;

    let key_bytes = std::fs::read(public_key_path)?;
    let key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes")?;
    let manifest =
        thorax_update::verify_signed_manifest_with_key(&std::fs::read(manifest_path)?, &key)?;
    thorax_update::validate_complete_manifest(manifest.v1())?;

    let mut expected = BTreeSet::new();
    for artifact in &manifest.v1().artifacts {
        if !expected.insert(artifact.name.clone()) {
            return Err(format!("duplicate manifest artifact name {:?}", artifact.name).into());
        }
        let path = artifacts_dir.join(&artifact.name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(
                format!("release artifact is not a regular file: {}", path.display()).into(),
            );
        }
        if metadata.len() != artifact.size {
            return Err(format!(
                "release artifact size mismatch for {:?}: expected {}, got {}",
                artifact.name,
                artifact.size,
                metadata.len()
            )
            .into());
        }
        verify_artifact_bytes(artifact, &std::fs::read(path)?)?;
    }

    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(&artifacts_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(format!(
                "unexpected non-file in release artifacts: {}",
                entry.path().display()
            )
            .into());
        }
        actual.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "release artifact name is not valid UTF-8")?,
        );
    }
    if actual != expected {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let extra = actual.difference(&expected).cloned().collect::<Vec<_>>();
        return Err(
            format!("release artifact set mismatch: missing={missing:?} extra={extra:?}").into(),
        );
    }
    Ok(())
}

fn inspect(args: Vec<String>) -> Result<()> {
    let mut opts = Opts::new(args);
    let manifest_path = PathBuf::from(opts.required("--manifest")?);
    let public_key_path = PathBuf::from(opts.required("--public-key")?);
    opts.finish()?;

    let key_bytes = std::fs::read(public_key_path)?;
    let key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes")?;
    let manifest =
        thorax_update::verify_signed_manifest_with_key(&std::fs::read(manifest_path)?, &key)?;
    let manifest = manifest.v1();
    println!("version={}", manifest.version);
    println!("tag={}", manifest.source.tag);
    println!("commit={}", manifest.source.commit);
    println!("workflow_run_id={}", manifest.source.workflow_run_id);
    println!("published_at={}", manifest.published_at);
    Ok(())
}

fn parse_asset_spec(spec: &str) -> Result<ReleaseArtifactV1> {
    let parts: Vec<&str> = spec.split(',').collect();
    if parts.len() < 7 {
        return Err(format!(
            "asset spec requires path,kind,format,triple,os,arch,abi[,name[,url]], got {spec:?}"
        )
        .into());
    }

    let path = PathBuf::from(parts[0]);
    let bytes = std::fs::read(&path)?;
    let name = parts
        .get(7)
        .filter(|s| !s.is_empty())
        .map(|s| (*s).to_string())
        .unwrap_or_else(|| {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("artifact")
                .to_string()
        });
    let url = parts
        .get(8)
        .filter(|s| !s.is_empty())
        .map(|s| (*s).to_string());

    Ok(ReleaseArtifactV1 {
        name,
        kind: parts[1].to_string(),
        format: parts[2].to_string(),
        url,
        target: ArtifactTargetV1 {
            triple: parts[3].to_string(),
            os: parts[4].to_string(),
            arch: parts[5].to_string(),
            abi: (!parts[6].is_empty()).then(|| parts[6].to_string()),
        },
        size: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).to_vec(),
    })
}

struct Opts {
    args: Vec<String>,
}

impl Opts {
    fn new(args: Vec<String>) -> Self {
        Self { args }
    }

    fn required(&mut self, flag: &str) -> Result<String> {
        self.take(flag)?
            .ok_or_else(|| format!("missing required {flag}").into())
    }

    fn repeated(&mut self, flag: &str) -> Vec<String> {
        let mut values = Vec::new();
        let mut idx = 0;
        while idx < self.args.len() {
            if self.args[idx] == flag {
                self.args.remove(idx);
                if idx >= self.args.len() {
                    break;
                }
                values.push(self.args.remove(idx));
            } else {
                idx += 1;
            }
        }
        values
    }

    fn take(&mut self, flag: &str) -> Result<Option<String>> {
        let Some(idx) = self.args.iter().position(|arg| arg == flag) else {
            return Ok(None);
        };
        self.args.remove(idx);
        if idx >= self.args.len() {
            return Err(format!("{flag} requires a value").into());
        }
        Ok(Some(self.args.remove(idx)))
    }

    fn finish(self) -> Result<()> {
        if self.args.is_empty() {
            Ok(())
        } else {
            Err(format!("unexpected arguments: {}", self.args.join(" ")).into())
        }
    }
}

fn usage() {
    eprintln!(
        "\
usage:
  thorax-manifest build-body --version V --published-at TS --tag TAG --commit SHA --workflow-run-id ID --asset SPEC --out BODY.cord
  thorax-manifest message --body BODY.cord --out MESSAGE.bin
  thorax-manifest seal --body BODY.cord --public-key pubkey.bin --signature sig.bin --out MANIFEST.cord
  thorax-manifest verify --manifest MANIFEST.cord --public-key pubkey.bin
  thorax-manifest verify-bundle --manifest MANIFEST.cord --public-key pubkey.bin --artifacts-dir DIR
  thorax-manifest inspect --manifest MANIFEST.cord --public-key pubkey.bin

asset spec:
  path,kind,format,triple,os,arch,abi[,release_asset_name[,url]]
"
    );
}
