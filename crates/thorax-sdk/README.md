# Thorax SDK for Rust

Native Rust SDK for [Thorax](https://github.com/backbone-hq/thorax), secrets management for humans, agents, and apps.

The SDK is a small application-facing facade over Thorax's shared operation layer. It uses the same vault validation, authorization, keychain, and cryptography as the CLI, TUI, Python SDK, and Node SDK.

## Installation

```sh
cargo add thorax-sdk
```

The SDK opens an existing Thorax vault. Install the [Thorax CLI](https://github.com/backbone-hq/thorax#installation) and run `thorax init` in your project if you do not have one yet.

## Quick start

`Vault::open` accepts the project root containing `.thorax` and authenticates with the configured local identity and keychain:

```rust
use thorax_sdk::Vault;

fn main() -> Result<(), thorax_sdk::Error> {
    let vault = Vault::open(".")?;
    let database_url = vault.get_string("app/prod/db")?;
    println!("database URL loaded ({} bytes)", database_url.len());
    Ok(())
}
```

Use `get` for an opaque byte value and `get_string` for UTF-8 text.

## Working with secrets

```rust
use thorax_sdk::Vault;

fn update_config() -> thorax_sdk::Result<()> {
    let mut vault = Vault::open(".")?;

    vault.set("app/prod/db", "postgres://localhost/app")?;
    vault.set_field("app/prod/db", "username", "app")?;

    let username = vault.get_field_string("app/prod/db", "username")?;
    let fields = vault.fields("app/prod/db")?;
    let selectors = vault.list();

    vault.delete_field("app/prod/db", "username")?;
    vault.move_secret("app/prod/db", "app/archive/db")?;
    vault.delete("app/archive/db")?;
    Ok(())
}
```

Selectors support paths and optional labels, for example `app/prod/db@region=eu`.

## Authentication

Local development uses the keychain by default. You can select a particular identity or supply a passphrase to a noninteractive caller:

```rust
use thorax_sdk::{Auth, KeychainConfig, Vault};

fn main() -> thorax_sdk::Result<()> {
    let auth = Auth::from_keychain_with(KeychainConfig {
        user: Some("alice".into()),
        passphrase: Some("...".into()),
    });
    let _vault = Vault::open_with(".", auth)?;
    Ok(())
}
```

For CI and deployed applications, use a dedicated, least-privilege invite identity. `Auth::from_env()` reads exactly one of `THORAX_UNSAFE_INVITE` or `THORAX_UNSAFE_INVITE_FILE`:

```rust
use thorax_sdk::{Auth, Vault};

fn main() -> thorax_sdk::Result<()> {
    let _vault = Vault::open_with(".", Auth::from_env())?;
    Ok(())
}
```

An invite is a private capability. Keep it out of source control and prefer the file variable when your runtime can mount it as a secret. `Auth::from_invite` also accepts an invite directly.

## Errors and session behavior

All fallible operations return `thorax_sdk::Result<T>`, whose error type is `thorax_sdk::Error`.

A session validates the vault when it opens and sees its own writes immediately. Open a new `Vault` to pick up changes written by another process. Opening fails while the vault has unresolved conflicts.

See the [API documentation](https://docs.rs/thorax-sdk) and the [Thorax documentation](https://github.com/backbone-hq/thorax) for the complete API, vault setup, selectors, access control, and the security model.

Thorax is licensed under the [Apache License 2.0](https://github.com/backbone-hq/thorax/blob/master/LICENSE).
