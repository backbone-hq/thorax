use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

pub const UPDATE_STATE_DIR_ENV: &str = "THORAX_UPDATE_STATE_DIR";
pub const UPDATE_STATE_FILE: &str = "update-state.cord";
pub const UPDATE_STATE_LOCK_FILE: &str = "update-state.lock";
pub const UPDATE_STATE_MAGIC: &[u8] = b"thorax-update-state\0";
pub const MAX_UPDATE_STATE_BYTES: usize = 64 * 1024;
pub const PASSIVE_CACHE_FILE: &str = "passive-check.txt";
pub const MAX_PASSIVE_CACHE_BYTES: usize = 4 * 1024;

const LEGACY_RELEASE_EPOCH_DIR: &str = "release-epochs";
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(100);

#[derive(cord::Cord, Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateStateV1 {
    pub highest_seen: Option<AcceptedReleaseV1>,
    pub highest_installed: Option<AcceptedReleaseV1>,
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
pub struct AcceptedReleaseV1 {
    pub version: String,
    pub epoch: u64,
    /// `None` exists only for a migrated legacy numeric marker.
    pub signed_manifest_sha256: Option<Vec<u8>>,
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum UpdateStateStore {
    #[cord(index = 0)]
    V1(UpdateStateV1),
}

pub fn update_state_base() -> Result<PathBuf, StateError> {
    if let Some(path) = std::env::var_os(UPDATE_STATE_DIR_ENV) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("APPDATA") {
        return Ok(PathBuf::from(path).join("Thorax"));
    }
    #[cfg(not(windows))]
    {
        if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(path).join("thorax"));
        }
        if let Some(path) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(path).join(".local/state/thorax"));
        }
    }
    Err(StateError::NoStateDirectory)
}

pub fn accept_seen(release: &AcceptedReleaseV1) -> Result<(), StateError> {
    accept_seen_in(&update_state_base()?, release)
}

pub fn record_installed(release: &AcceptedReleaseV1) -> Result<(), StateError> {
    record_installed_in(&update_state_base()?, release)
}

pub fn read_update_state() -> Result<UpdateStateV1, StateError> {
    let base = update_state_base()?;
    let _lock = acquire_lock(&base)?;
    load_or_migrate_locked(&base)
}

pub(crate) fn passive_cache_path() -> Result<PathBuf, StateError> {
    Ok(update_state_base()?.join(PASSIVE_CACHE_FILE))
}

pub(crate) fn read_passive_cache(max_age: Duration) -> Option<String> {
    let path = passive_cache_path().ok()?;
    read_passive_cache_at(&path, max_age)
}

fn read_passive_cache_at(path: &Path, max_age: Duration) -> Option<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_PASSIVE_CACHE_BYTES as u64 {
        return None;
    }
    let age = std::time::SystemTime::now()
        .duration_since(metadata.modified().ok()?)
        .ok()?;
    if age > max_age {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PASSIVE_CACHE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_PASSIVE_CACHE_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub(crate) fn write_passive_cache(text: &str) -> Result<(), StateError> {
    write_passive_cache_in(&update_state_base()?, text)
}

fn write_passive_cache_in(base: &Path, text: &str) -> Result<(), StateError> {
    if text.len() > MAX_PASSIVE_CACHE_BYTES {
        return Err(StateError::InvalidState(
            "passive update cache exceeds 4 KiB".into(),
        ));
    }
    let path = base.join(PASSIVE_CACHE_FILE);
    create_private_dir(base)?;
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{PASSIVE_CACHE_FILE}.tmp."))
        .tempfile_in(base)
        .map_err(|source| io_at(base, source))?;
    if let Err(source) = temp
        .as_file_mut()
        .write_all(text.as_bytes())
        .and_then(|()| temp.as_file().sync_all())
    {
        return Err(io_at(temp.path(), source));
    }
    temp.persist(&path)
        .map_err(|error| io_at(&path, error.error))?;
    sync_directory(base)?;
    let reopened =
        read_bounded(&path, MAX_PASSIVE_CACHE_BYTES).map_err(|source| io_at(&path, source))?;
    if reopened != text.as_bytes() {
        return Err(StateError::InvalidState(
            "passive update cache differed after atomic write".into(),
        ));
    }
    Ok(())
}

fn accept_seen_in(base: &Path, release: &AcceptedReleaseV1) -> Result<(), StateError> {
    validate_release(release)?;
    let _lock = acquire_lock(base)?;
    let mut state = load_or_migrate_locked(base)?;
    if advance(&mut state.highest_seen, release, "seen")? {
        write_state(base, &state)?;
    }
    Ok(())
}

fn record_installed_in(base: &Path, release: &AcceptedReleaseV1) -> Result<(), StateError> {
    validate_release(release)?;
    let _lock = acquire_lock(base)?;
    let mut state = load_or_migrate_locked(base)?;
    let mut changed = if state
        .highest_seen
        .as_ref()
        .is_none_or(|seen| release.epoch >= seen.epoch)
    {
        advance(&mut state.highest_seen, release, "seen")?
    } else {
        false
    };
    changed |= advance(&mut state.highest_installed, release, "installed")?;
    if changed {
        write_state(base, &state)?;
    }
    Ok(())
}

fn advance(
    current: &mut Option<AcceptedReleaseV1>,
    offered: &AcceptedReleaseV1,
    field: &'static str,
) -> Result<bool, StateError> {
    let Some(remembered) = current else {
        *current = Some(offered.clone());
        return Ok(true);
    };
    if offered.epoch < remembered.epoch {
        return Err(StateError::Rollback {
            field,
            offered: offered.epoch,
            remembered: remembered.epoch,
        });
    }
    if offered.epoch > remembered.epoch {
        *remembered = offered.clone();
        return Ok(true);
    }
    if offered.version != remembered.version {
        return Err(StateError::Equivocation {
            epoch: offered.epoch,
        });
    }
    match (
        remembered.signed_manifest_sha256.as_ref(),
        offered.signed_manifest_sha256.as_ref(),
    ) {
        (Some(existing), Some(incoming)) if existing != incoming => Err(StateError::Equivocation {
            epoch: offered.epoch,
        }),
        (None, Some(incoming)) => {
            remembered.signed_manifest_sha256 = Some(incoming.clone());
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn load_or_migrate_locked(base: &Path) -> Result<UpdateStateV1, StateError> {
    match read_state_file(base)? {
        Some(state) => Ok(state),
        None => migrate_legacy_locked(base),
    }
}

fn migrate_legacy_locked(base: &Path) -> Result<UpdateStateV1, StateError> {
    let legacy = base.join(LEGACY_RELEASE_EPOCH_DIR);
    let entries = match fs::read_dir(&legacy) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(UpdateStateV1::default());
        }
        Err(source) => return Err(io_at(&legacy, source)),
    };
    let mut numeric = Vec::new();
    let mut highest = None;
    for entry in entries {
        let entry = entry.map_err(|source| io_at(&legacy, source))?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(epoch) = name.parse::<u64>() else {
            continue;
        };
        let metadata = entry
            .file_type()
            .map_err(|source| io_at(&entry.path(), source))?;
        if !metadata.is_file() {
            continue;
        }
        highest = Some(highest.map_or(epoch, |value: u64| value.max(epoch)));
        numeric.push(entry.path());
    }
    let state = UpdateStateV1 {
        highest_seen: highest.map(|epoch| AcceptedReleaseV1 {
            version: version_from_epoch(epoch),
            epoch,
            signed_manifest_sha256: None,
        }),
        highest_installed: None,
    };
    if highest.is_some() {
        write_state(base, &state)?;
        for marker in numeric {
            fs::remove_file(&marker).map_err(|source| io_at(&marker, source))?;
        }
        sync_directory(&legacy)?;
        if fs::read_dir(&legacy)
            .map_err(|source| io_at(&legacy, source))?
            .next()
            .is_none()
        {
            fs::remove_dir(&legacy).map_err(|source| io_at(&legacy, source))?;
            sync_directory(base)?;
        }
    }
    Ok(state)
}

fn version_from_epoch(epoch: u64) -> String {
    let major = epoch / 1_000_000;
    let remainder = epoch % 1_000_000;
    let minor = remainder / 1_000;
    let patch = remainder % 1_000;
    format!("{major}.{minor}.{patch}")
}

fn state_path(base: &Path) -> PathBuf {
    base.join(UPDATE_STATE_FILE)
}

fn read_state_file(base: &Path) -> Result<Option<UpdateStateV1>, StateError> {
    let path = state_path(base);
    let bytes = match read_bounded(&path, MAX_UPDATE_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_at(&path, source)),
    };
    let payload = bytes
        .strip_prefix(UPDATE_STATE_MAGIC)
        .ok_or_else(|| StateError::InvalidState("missing update-state magic".into()))?;
    let UpdateStateStore::V1(state) =
        cord::deserialize(payload).map_err(|error| StateError::InvalidState(error.to_string()))?;
    validate_state(&state)?;
    Ok(Some(state))
}

fn write_state(base: &Path, state: &UpdateStateV1) -> Result<(), StateError> {
    validate_state(state)?;
    create_private_dir(base)?;
    let payload = cord::serialize(&UpdateStateStore::V1(state.clone()))
        .map_err(|error| StateError::InvalidState(error.to_string()))?;
    let mut bytes = Vec::with_capacity(UPDATE_STATE_MAGIC.len() + payload.len());
    bytes.extend_from_slice(UPDATE_STATE_MAGIC);
    bytes.extend(payload);
    if bytes.len() > MAX_UPDATE_STATE_BYTES {
        return Err(StateError::InvalidState(
            "encoded update state exceeds 64 KiB".into(),
        ));
    }
    let path = state_path(base);
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{UPDATE_STATE_FILE}.tmp."))
        .tempfile_in(base)
        .map_err(|source| io_at(base, source))?;
    if let Err(source) = temp
        .as_file_mut()
        .write_all(&bytes)
        .and_then(|()| temp.as_file().sync_all())
    {
        return Err(io_at(temp.path(), source));
    }
    temp.persist(&path)
        .map_err(|error| io_at(&path, error.error))?;
    sync_directory(base)?;
    let reopened =
        read_bounded(&path, MAX_UPDATE_STATE_BYTES).map_err(|source| io_at(&path, source))?;
    if reopened != bytes {
        return Err(StateError::InvalidState(
            "update-state bytes differed after atomic write".into(),
        ));
    }
    let decoded = read_state_file(base)?.ok_or_else(|| {
        StateError::InvalidState("update state disappeared after atomic write".into())
    })?;
    if decoded != *state {
        return Err(StateError::InvalidState(
            "update-state value differed after atomic write".into(),
        ));
    }
    Ok(())
}

fn validate_state(state: &UpdateStateV1) -> Result<(), StateError> {
    if let Some(release) = &state.highest_seen {
        validate_release(release)?;
    }
    if let Some(release) = &state.highest_installed {
        validate_release(release)?;
        let seen = state.highest_seen.as_ref().ok_or_else(|| {
            StateError::InvalidState("installed release exists without a seen release".into())
        })?;
        if release.epoch > seen.epoch {
            return Err(StateError::InvalidState(
                "installed release is newer than seen release".into(),
            ));
        }
    }
    Ok(())
}

fn validate_release(release: &AcceptedReleaseV1) -> Result<(), StateError> {
    if release.version.is_empty() || release.version.len() > 64 {
        return Err(StateError::InvalidState(
            "release version is empty or too long".into(),
        ));
    }
    if release
        .signed_manifest_sha256
        .as_ref()
        .is_some_and(|hash| hash.len() != 32)
    {
        return Err(StateError::InvalidState(
            "signed manifest hash must be 32 bytes".into(),
        ));
    }
    Ok(())
}

struct UpdateStateLock {
    file: File,
}

impl Drop for UpdateStateLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn acquire_lock(base: &Path) -> Result<UpdateStateLock, StateError> {
    create_private_dir(base)?;
    let path = base.join(UPDATE_STATE_LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(|source| io_at(&path, source))?;
    let started = Instant::now();
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(UpdateStateLock { file }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if started.elapsed() >= LOCK_WAIT {
                    return Err(StateError::LockTimeout(path));
                }
                thread::sleep(LOCK_POLL);
            }
            Err(source) => return Err(io_at(&path, source)),
        }
    }
}

fn read_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    Ok(bytes)
}

fn create_private_dir(path: &Path) -> Result<(), StateError> {
    fs::create_dir_all(path).map_err(|source| io_at(path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_at(path, source))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StateError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|source| io_at(path, source))?;
    }
    Ok(())
}

fn io_at(path: &Path, source: io::Error) -> StateError {
    StateError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("release {field} rollback: offered epoch {offered}, remembered {remembered}")]
    Rollback {
        field: &'static str,
        offered: u64,
        remembered: u64,
    },
    #[error("different signed manifests claim release epoch {epoch}")]
    Equivocation { epoch: u64 },
    #[error("invalid update state: {0}")]
    InvalidState(String),
    #[error("timed out waiting for update state lock at {0}")]
    LockTimeout(PathBuf),
    #[error("no private update state directory is available")]
    NoStateDirectory,
    #[error("update state I/O failed at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, epoch: u64, hash: u8) -> AcceptedReleaseV1 {
        AcceptedReleaseV1 {
            version: version.into(),
            epoch,
            signed_manifest_sha256: Some(vec![hash; 32]),
        }
    }

    #[test]
    fn seen_and_installed_are_monotonic_and_distinct() {
        let temp = tempfile::tempdir().unwrap();
        accept_seen_in(temp.path(), &release("1.0.1", 1_000_001, 1)).unwrap();
        accept_seen_in(temp.path(), &release("1.0.2", 1_000_002, 2)).unwrap();
        record_installed_in(temp.path(), &release("1.0.1", 1_000_001, 1)).unwrap();

        let _lock = acquire_lock(temp.path()).unwrap();
        let state = load_or_migrate_locked(temp.path()).unwrap();
        assert_eq!(state.highest_seen.unwrap().version, "1.0.2");
        assert_eq!(state.highest_installed.unwrap().version, "1.0.1");
    }

    #[test]
    fn rollback_and_same_epoch_equivocation_fail() {
        let temp = tempfile::tempdir().unwrap();
        accept_seen_in(temp.path(), &release("1.0.2", 1_000_002, 2)).unwrap();
        assert!(matches!(
            accept_seen_in(temp.path(), &release("1.0.1", 1_000_001, 1)),
            Err(StateError::Rollback { .. })
        ));
        assert!(matches!(
            accept_seen_in(temp.path(), &release("1.0.2", 1_000_002, 3)),
            Err(StateError::Equivocation { .. })
        ));
    }

    #[test]
    fn legacy_markers_migrate_once_and_fill_hash() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join(LEGACY_RELEASE_EPOCH_DIR);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("1000001"), []).unwrap();
        fs::write(legacy.join("1000002"), []).unwrap();

        accept_seen_in(temp.path(), &release("1.0.2", 1_000_002, 9)).unwrap();

        assert!(!legacy.exists());
        let _lock = acquire_lock(temp.path()).unwrap();
        let state = load_or_migrate_locked(temp.path()).unwrap();
        assert_eq!(
            state.highest_seen.unwrap().signed_manifest_sha256,
            Some(vec![9; 32])
        );
    }

    #[test]
    fn passive_cache_is_private_bounded_and_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(PASSIVE_CACHE_FILE);
        create_private_dir(temp.path()).unwrap();
        write_passive_cache_in(temp.path(), "update available").unwrap();
        assert_eq!(
            read_passive_cache_at(&path, Duration::from_secs(60)).as_deref(),
            Some("update available")
        );
        assert_eq!(fs::read(&path).unwrap(), b"update available");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn passive_cache_refuses_a_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join(PASSIVE_CACHE_FILE);
        fs::write(&target, "attacker controlled").unwrap();
        symlink(&target, &link).unwrap();
        assert_eq!(read_passive_cache_at(&link, Duration::from_secs(60)), None);
    }
}
