use std::io;

use clap::{Parser, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    fn directive(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "thorax-kubernetes-controller")]
struct Args {
    /// Namespace to reconcile. Defaults to POD_NAMESPACE from the downward API.
    #[arg(long)]
    namespace: Option<String>,
    /// Coordination Lease used for namespaced leader election.
    #[arg(long, default_value = "thorax-kubernetes-controller")]
    lease_name: String,
    /// Unique contender identity. Defaults to POD_NAME or the process ID.
    #[arg(long)]
    holder_identity: Option<String>,
    /// Controller log level. Dependency tracing is always capped at warn so Kubernetes
    /// request bodies containing Secret data cannot be enabled through RUST_LOG.
    #[arg(long, value_enum, default_value = "info")]
    log_level: LogLevel,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    harden_process()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(format!(
            "warn,thorax_kubernetes_controller={}",
            args.log_level.directive()
        )))
        .init();

    let namespace = args
        .namespace
        .or_else(|| std::env::var("POD_NAMESPACE").ok())
        .ok_or("pass --namespace or set POD_NAMESPACE")?;
    let holder = args
        .holder_identity
        .or_else(|| std::env::var("POD_NAME").ok())
        .unwrap_or_else(|| format!("process-{}", std::process::id()));
    let config = kube::Config::infer().await?;
    if config.accept_invalid_certs || config.cluster_url.scheme_str() != Some("https") {
        return Err("Kubernetes API must use verified HTTPS".into());
    }
    let client = kube::Client::try_from(config)?;

    tokio::select! {
        result = thorax_kubernetes_controller::run_leader_elected(
            client,
            namespace,
            args.lease_name,
            holder,
        ) => result?,
        signal = shutdown_signal() => signal?,
    }
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(target_os = "linux")]
fn harden_process() -> io::Result<()> {
    // The controller handles decrypted values. Core dumps and same-UID ptrace are not
    // acceptable recovery/debug mechanisms, and newly created files must default to
    // owner-only access even if a future code path bypasses tempfile's safe defaults.
    unsafe {
        libc::umask(0o077);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn harden_process() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "thorax-kubernetes-controller requires Linux process hardening",
    ))
}
