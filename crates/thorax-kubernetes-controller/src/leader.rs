use std::time::{Duration, Instant};

use k8s_openapi::{
    api::coordination::v1::{Lease, LeaseSpec},
    apimachinery::pkg::apis::meta::v1::MicroTime,
};
use kube::{
    api::{Api, PostParams},
    Client,
};

const LEASE_DURATION_SECONDS: i32 = 30;
const RENEW_INTERVAL: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_secs(3);

/// Run the namespaced controllers only while this process owns the coordination Lease.
/// Dropping the controller futures immediately stops reconciliation if renewal cannot be
/// confirmed before the local lease deadline; the process then waits to acquire again.
pub async fn run_leader_elected(
    client: Client,
    namespace: String,
    lease_name: String,
    holder: String,
) -> Result<(), crate::ControllerError> {
    let leases: Api<Lease> = Api::namespaced(client.clone(), &namespace);
    loop {
        while !acquire_or_renew(&leases, &lease_name, &holder).await? {
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
        tracing::info!(%holder, %lease_name, "leader lease acquired");
        let controller = crate::run(client.clone(), namespace.clone());
        tokio::pin!(controller);
        let renewal = maintain(&leases, &lease_name, &holder);
        tokio::pin!(renewal);
        tokio::select! {
            result = &mut controller => return result,
            result = &mut renewal => {
                result?;
                tracing::warn!(%holder, %lease_name, "leader lease lost; reconciliation stopped");
            }
        }
    }
}

async fn maintain(
    leases: &Api<Lease>,
    lease_name: &str,
    holder: &str,
) -> Result<(), crate::ControllerError> {
    let mut last_success = Instant::now();
    loop {
        tokio::time::sleep(RENEW_INTERVAL).await;
        match acquire_or_renew(leases, lease_name, holder).await {
            Ok(true) => last_success = Instant::now(),
            Ok(false) => return Ok(()),
            Err(error)
                if last_success.elapsed() < Duration::from_secs(LEASE_DURATION_SECONDS as u64) =>
            {
                tracing::warn!("leader lease renewal was not confirmed; retrying");
                let _ = error;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn acquire_or_renew(
    leases: &Api<Lease>,
    name: &str,
    holder: &str,
) -> Result<bool, crate::ControllerError> {
    let now = k8s_openapi::jiff::Timestamp::now();
    let Some(mut lease) = leases.get_opt(name).await? else {
        let lease = Lease {
            metadata: kube::core::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                acquire_time: Some(MicroTime(now)),
                renew_time: Some(MicroTime(now)),
                holder_identity: Some(holder.to_string()),
                lease_duration_seconds: Some(LEASE_DURATION_SECONDS),
                lease_transitions: Some(0),
                ..Default::default()
            }),
        };
        return match leases.create(&PostParams::default(), &lease).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(response)) if response.code == 409 => Ok(false),
            Err(error) => Err(error.into()),
        };
    };

    let spec = lease.spec.get_or_insert_with(LeaseSpec::default);
    let current_holder = spec.holder_identity.as_deref();
    let renewed_at = spec
        .renew_time
        .as_ref()
        .or(spec.acquire_time.as_ref())
        .map(|time| time.0.as_second())
        .unwrap_or(i64::MIN);
    let duration = spec
        .lease_duration_seconds
        .unwrap_or(LEASE_DURATION_SECONDS) as i64;
    let expired = now.as_second().saturating_sub(renewed_at) >= duration;
    if current_holder != Some(holder) && !expired {
        return Ok(false);
    }
    if current_holder != Some(holder) {
        spec.acquire_time = Some(MicroTime(now));
        spec.lease_transitions = Some(spec.lease_transitions.unwrap_or_default().saturating_add(1));
    }
    spec.holder_identity = Some(holder.to_string());
    spec.lease_duration_seconds = Some(LEASE_DURATION_SECONDS);
    spec.renew_time = Some(MicroTime(now));
    match leases.replace(name, &PostParams::default(), &lease).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(response)) if response.code == 409 => Ok(false),
        Err(error) => Err(error.into()),
    }
}
