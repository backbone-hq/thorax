//! Chunked HTTP download with progress bar.
//!
//! Uses `ureq` for synchronous HTTP and `indicatif` for the progress display.
//! The download is streamed in chunks so we can update the progress bar as
//! bytes arrive.

use std::io::Read;

use indicatif::{ProgressBar, ProgressStyle};

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;

/// Create a ureq agent with sensible timeouts and a custom user-agent.
fn agent() -> ureq::Agent {
    agent_with_timeouts(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(120),
    )
}

fn agent_with_timeouts(connect: std::time::Duration, global: std::time::Duration) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_connect(Some(connect))
            .timeout_global(Some(global))
            .user_agent(concat!("thorax-update/", env!("CARGO_PKG_VERSION")))
            .build(),
    )
}

/// Download a URL into memory, showing a progress bar.
///
/// Returns the raw bytes. On failure returns a `DownloadError`.
pub fn download_with_progress(url: &str) -> Result<Vec<u8>, DownloadError> {
    download_with_progress_bounded(url, MAX_ARTIFACT_BYTES)
}

pub fn download_with_progress_bounded(
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DownloadError> {
    let agent = agent();

    // First, do a HEAD request to get the content-length (if available).
    // Some release transports do not return it, so we fall back to unknown size.
    let head_size = agent.head(url).call().ok().and_then(|resp| {
        resp.headers()
            .get("content-length")?
            .to_str()
            .ok()?
            .parse::<u64>()
            .ok()
    });

    // Now download the body.
    let response = agent.get(url).call().map_err(|e| DownloadError::Http {
        url: url.to_string(),
        detail: e.to_string(),
    })?;

    if head_size.is_some_and(|size| size > max_bytes as u64) {
        return Err(DownloadError::TooLarge { max_bytes });
    }
    let total = head_size.unwrap_or(0);
    let pb = if total > 0 {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{bar:32.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("##-"),
        );
        pb.set_message("Downloading");
        Some(pb)
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg} ({bytes})")
                .unwrap(),
        );
        pb.set_message("Downloading");
        Some(pb)
    };

    let mut buf = Vec::with_capacity(total as usize);
    let mut reader = response.into_body().into_reader();

    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).map_err(|e| DownloadError::Http {
            url: url.to_string(),
            detail: format!("read error: {e}"),
        })?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max_bytes {
            return Err(DownloadError::TooLarge { max_bytes });
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(ref pb) = pb {
            pb.inc(n as u64);
        }
    }

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

    Ok(buf)
}

/// Download a small URL (like the VERSION endpoint) without a progress bar.
pub fn download_small(url: &str) -> Result<Vec<u8>, DownloadError> {
    download_small_with_agent(url, agent(), MAX_MANIFEST_BYTES)
}

/// Download a small URL without a progress bar and with short caller-supplied timeouts.
pub fn download_small_with_timeout(
    url: &str,
    connect: std::time::Duration,
    global: std::time::Duration,
) -> Result<Vec<u8>, DownloadError> {
    download_small_with_agent(
        url,
        agent_with_timeouts(connect, global),
        MAX_MANIFEST_BYTES,
    )
}

fn download_small_with_agent(
    url: &str,
    agent: ureq::Agent,
    max_bytes: usize,
) -> Result<Vec<u8>, DownloadError> {
    let response = agent.get(url).call().map_err(|e| DownloadError::Http {
        url: url.to_string(),
        detail: e.to_string(),
    })?;

    let mut buf = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| DownloadError::Http {
            url: url.to_string(),
            detail: format!("read error: {e}"),
        })?;

    if buf.len() > max_bytes {
        return Err(DownloadError::TooLarge { max_bytes });
    }
    Ok(buf)
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("failed to download {url}: {detail}")]
    Http { url: String, detail: String },
    #[error("download exceeds the supported maximum of {max_bytes} bytes")]
    TooLarge { max_bytes: usize },
}
