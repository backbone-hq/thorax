//! Vault scaling harness.
//!
//! Builds synthetic-but-valid vaults of varying size and times the paths that run on every
//! command and every TUI action, so the scaling story rests on measured numbers rather than a
//! complexity model. Run with `cargo run -p thorax-bench --release`.
//!
//! What it isolates:
//!   * `validate` (DeterministicCrypto): the *structural* derivation cost — record scan, the
//!     authority fixpoint, LWW resolution, deletion admission. Paid on every `load`,
//!     `reload_if_stale`, and post-commit `validate`. The fake crypto is ~free, so this is the
//!     non-crypto skeleton of validation in isolation.
//!   * `verify/validate` (CountingCrypto): how many signature verifications one validate issues.
//!     Multiplied by the real-Ed25519 microbench below, this is the crypto component.
//!   * `read1` / `list`: querying the *already-validated, warm* effective state for one secret
//!     and for all secrets — the TUI read path. A warm session still pays these per action.
//!
//! Crypto note: the `test_support` builders sign with DeterministicCrypto and seal with `Fake`
//! schemes, so a real-Ed25519 vault can't be fed through `validate` here. Instead we measure
//! real verify throughput once and project: crypto_cost ≈ verify_count × per_verify.

use std::hint::black_box;
use std::time::{Duration, Instant};

use thorax_core::test_support::{
    secret_record, secret_selector, trust_root, user_deleted_record, user_record,
    vault_from_records, vault_root_record, CountingCrypto, Fixture, TestUser,
};
use thorax_core::{
    decode_vault, encode_vault, validate_vault, validate_vault_with_verified, CryptoProvider,
    DeterministicCrypto, Ratchet, SecretSelectorV1, VaultRecordV1, VaultStore,
};

/// Min-of-`reps` wall time for `f`. Min suppresses scheduler noise for compute-bound work.
fn bench<T>(reps: u32, mut f: impl FnMut() -> T) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..reps.max(1) {
        let start = Instant::now();
        let out = f();
        let elapsed = start.elapsed();
        black_box(out);
        best = best.min(elapsed);
    }
    best
}

struct Vault {
    store: VaultStore,
    ratchet: Ratchet,
    /// A selector that exists in the vault — the target of the single-read benchmark.
    sample: SecretSelectorV1,
}

/// A valid vault: one root, `users` readers (each an effective user with an entry point), `secrets`
/// root-signed secrets each sealed to every reader, and `deletions` admitted user tombstones.
fn build(secrets: usize, users: usize, deletions: usize) -> Vault {
    let fixture = Fixture::new();
    let crypto = &fixture.crypto;
    let mut records: Vec<VaultRecordV1> = Vec::new();
    records.push(vault_root_record(&fixture));

    let readers: Vec<TestUser> = (0..users)
        .map(|u| {
            let user = thorax_core::test_support::test_user(crypto, &format!("u{u}"));
            records.push(user_record(&fixture, &user, 1));
            records.push(trust_root(crypto, &user, &fixture, 1));
            user
        })
        .collect();
    let reader_refs: Vec<&TestUser> = readers.iter().collect();

    let mut sample = secret_selector(&["app", "s0"]);
    for i in 0..secrets {
        let name = format!("s{i}");
        let selector = secret_selector(&["app", &name]);
        if i == secrets / 2 {
            sample = selector.clone();
        }
        records.push(secret_record(
            crypto,
            &fixture.root,
            &selector,
            &reader_refs,
            1,
        ));
    }

    // Each deletion is an admitted UserDeleted tombstone (counter 2 beats the add's 1). Every
    // admission forces a from-scratch effective-state recompute over *all* records, secrets
    // included — this is the (D+1)x amplifier the deletion sweep exposes.
    for d in 0..deletions {
        let victim = thorax_core::test_support::test_user(crypto, &format!("victim{d}"));
        records.push(user_record(&fixture, &victim, 1));
        records.push(trust_root(crypto, &victim, &fixture, 1));
        records.push(user_deleted_record(
            crypto,
            &fixture.root,
            victim.id.clone(),
            2,
        ));
    }

    Vault {
        store: vault_from_records(records),
        ratchet: Ratchet::new(fixture.root_signing_public_key_hash()),
        sample,
    }
}

fn record_count(store: &VaultStore) -> usize {
    let VaultStore::V1(v) = store;
    v.records.len()
}

fn main() {
    println!("# Thorax vault scaling benchmark\n");
    let crypto = DeterministicCrypto;

    // ---- Real Ed25519 verify microbench: the per-verify constant we project with. ----
    let per_verify = {
        use thorax_crypto::{Crypto, SigningKeypair};
        let kp = SigningKeypair::generate();
        let msg = b"thorax.signed.v1 benchmark transcript of a representative record body";
        let sig = kp.sign("thorax.signed.v1", msg);
        let pk = kp.public_key_bytes();
        let real = Crypto;
        let reps = 2000u32;
        let total = bench(1, || {
            for _ in 0..reps {
                black_box(real.verify_signature("thorax.signed.v1", &pk, msg, &sig));
            }
        });
        let per = total / reps;
        println!(
            "Real Ed25519 verify: {:.1} µs/verify ({} samples)",
            per.as_secs_f64() * 1e6,
            reps
        );
        per
    };

    // ---- Real SHA-256 record-hash microbench: the per-record cost of a cache lookup ----
    // (the hash is already computed for dedup on every load; this bounds its share and
    // the verify/hash ratio the signed verification cache trades on).
    {
        use thorax_core::CryptoProvider;
        let real = thorax_crypto::Crypto;
        let reps = 20_000u32;
        for &size in &[256usize, 1024, 2048, 8192] {
            let record = vec![0xa5u8; size];
            let total = bench(1, || {
                for _ in 0..reps {
                    black_box(real.hash("thorax.record-hash.v1", &record));
                }
            });
            let per = total / reps;
            println!(
                "Real SHA-256 record-hash ({size} B record): {:.2} µs/hash ({:.0}x cheaper than verify)",
                per.as_secs_f64() * 1e6,
                per_verify.as_secs_f64() / per.as_secs_f64()
            );
        }
        println!();
    }

    // ---- Size + per-command + warm-read sweep over secret count. ----
    println!("## Sweep: secret count (users=20, deletions=0)\n");
    println!("Every row's `validate` is paid on each load / reload_if_stale / commit.");
    println!("`verifs(c)`/`total(c)` are the same command with a warm signed verification");
    println!("cache (all hashes pre-verified; +1 verify for the cache's own signature).");
    println!("`read1` and `list` are warm-session queries (the TUI read path).\n");
    println!("| secrets | records | encoded | decode | validate | verifs | proj.crypto | total/cmd | verifs(c) | total(c) | read1 | list |");
    println!("|--------:|--------:|--------:|-------:|---------:|-------:|------------:|----------:|----------:|---------:|------:|-----:|");
    for &secrets in &[100usize, 1_000, 5_000, 10_000, 25_000, 50_000] {
        let reps = if secrets >= 25_000 { 3 } else { 6 };
        let v = build(secrets, 20, 0);
        let bytes = encode_vault(&v.store).unwrap();
        let decode_t = bench(reps, || decode_vault(black_box(&bytes)).unwrap());
        let validate_t = bench(reps, || {
            validate_vault(black_box(&v.store), &v.ratchet, &crypto).unwrap()
        });

        let counting = CountingCrypto::default();
        let report = validate_vault(&v.store, &v.ratchet, &counting).unwrap();
        let verifs = counting.verifications.get();
        let proj_crypto = per_verify * verifs as u32;

        // The signed-cache path: every previously verified hash skips its check; the
        // command's residual crypto is the cache's own signature verify (+ any delta).
        let cache = report.effective.verified_record_hashes();
        let counting_cached = CountingCrypto::default();
        validate_vault_with_verified(&v.store, &v.ratchet, &counting_cached, &cache).unwrap();
        let verifs_cached = counting_cached.verifications.get() + 1;
        let validate_cached_t = bench(reps, || {
            validate_vault_with_verified(black_box(&v.store), &v.ratchet, &crypto, &cache).unwrap()
        });
        let total_cached = validate_cached_t + per_verify * verifs_cached as u32;

        let report = validate_vault(&v.store, &v.ratchet, &crypto).unwrap();
        let eff = &report.effective;
        let read1 = bench(50, || {
            black_box(eff.secret_record(&v.sample, &crypto).unwrap())
        });
        let list = bench(reps, || black_box(eff.secret_records()));

        println!(
            "| {:>7} | {:>7} | {:>7} | {:>6} | {:>8} | {:>6} | {:>11} | {:>9} | {:>9} | {:>8} | {:>5} | {:>4} |",
            secrets,
            record_count(&v.store),
            fmt_bytes(bytes.len()),
            fmt_ms(decode_t),
            fmt_ms(validate_t),
            verifs,
            fmt_ms(proj_crypto),
            fmt_ms(validate_t + proj_crypto),
            verifs_cached,
            fmt_ms(total_cached),
            fmt_ms(read1),
            fmt_ms(list),
        );
    }

    // ---- Deletion sweep: the from-scratch recompute per admission. ----
    println!("\n## Sweep: deletion tombstones (secrets=5000, users=20)\n");
    println!("Each admitted deletion re-derives the whole effective state from scratch.\n");
    println!("| deletions | validate | vs D=0 |");
    println!("|----------:|---------:|-------:|");
    let mut base = Duration::ZERO;
    for &deletions in &[0usize, 1, 2, 4, 8, 16, 32] {
        let v = build(5_000, 20, deletions);
        let t = bench(4, || {
            validate_vault(black_box(&v.store), &v.ratchet, &crypto).unwrap()
        });
        if deletions == 0 {
            base = t;
        }
        let ratio = t.as_secs_f64() / base.as_secs_f64().max(f64::MIN_POSITIVE);
        println!("| {:>9} | {:>8} | {:>5.1}x |", deletions, fmt_ms(t), ratio);
    }

    // ---- Reader sweep: per-secret per-recipient slots → O(secrets × readers) size. ----
    println!("\n## Sweep: readers per secret (secrets=2000, deletions=0)\n");
    println!("Each reader adds a recipient slot to *every* secret.\n");
    println!("| readers | encoded | bytes/secret | validate |");
    println!("|--------:|--------:|-------------:|---------:|");
    for &users in &[1usize, 10, 25, 50, 100] {
        let v = build(2_000, users, 0);
        let bytes = encode_vault(&v.store).unwrap();
        let validate_t = bench(4, || {
            validate_vault(black_box(&v.store), &v.ratchet, &crypto).unwrap()
        });
        println!(
            "| {:>7} | {:>7} | {:>12} | {:>8} |",
            users,
            fmt_bytes(bytes.len()),
            bytes.len() / 2_000,
            fmt_ms(validate_t),
        );
    }
}

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1e3;
    if ms >= 100.0 {
        format!("{ms:.0}ms")
    } else if ms >= 1.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{:.0}µs", ms * 1e3)
    }
}

fn fmt_bytes(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.1}MB", n as f64 / (1 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.0}KB", n as f64 / (1 << 10) as f64)
    } else {
        format!("{n}B")
    }
}
