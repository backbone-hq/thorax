# Thorax for Python

Native Python SDK for [Thorax](https://github.com/backbone-hq/thorax), secrets management for humans, agents, and apps.

The SDK is a small application-facing facade over Thorax's shared operation layer. It uses the same vault validation, authorization, keychain, and cryptography as the CLI, TUI, Rust SDK, and Node SDK.

## Installation

Thorax requires Python 3.9 or later.

```sh
pip install thorax
```

The SDK opens an existing Thorax vault. Install the [Thorax CLI](https://github.com/backbone-hq/thorax#installation) and run `thorax init` in your project if you do not have one yet.

## Quick start

By default, `Vault` opens `.thorax/vault.cord` and authenticates with the configured local identity and keychain:

```python
import thorax

vault = thorax.Vault()
database_url = vault.get("app/prod/db")
```

Pass the directory containing `vault.cord` when the vault is elsewhere:

```python
vault = thorax.Vault("/srv/my-app/.thorax")
```

Values are UTF-8 strings by default. Set `as_bytes=True` when reading a binary value:

```python
certificate = vault.get("app/prod/certificate", as_bytes=True)
vault.set("app/prod/token", b"binary value")
```

## Working with secrets

```python
vault.set("app/prod/db", "postgres://localhost/app")
vault.set_field("app/prod/db", "username", "app")

username = vault.get_field("app/prod/db", "username")
fields = vault.fields("app/prod/db")
selectors = vault.list("app/prod")

vault.delete_field("app/prod/db", "username")
vault.delete("app/prod/db")
```

Selectors may be strings such as `app/prod/db@region=eu`, or structured `thorax.Selector` objects.

## Authentication

Local development uses the keychain by default. You can select a particular identity or supply a passphrase to a noninteractive caller:

```python
auth = thorax.Auth.from_keychain("alice", passphrase="...")
vault = thorax.Vault(auth=auth)
```

For CI and deployed applications, use a dedicated, least-privilege invite identity. `Auth.from_env()` reads exactly one of `THORAX_UNSAFE_INVITE` or `THORAX_UNSAFE_INVITE_FILE`:

```python
vault = thorax.Vault(auth=thorax.Auth.from_env())
```

An invite is a private capability. Keep it out of source control and prefer the file variable when your runtime can mount it as a secret. `Auth.from_invite()` also accepts an invite directly.

## Errors and session behavior

Operations raise subclasses of `thorax.ThoraxError`: `NotFound`, `PermissionDenied`, `ConflictError`, `ValidationError`, and `IdentityError`.

A session validates the vault when it opens and sees its own writes immediately. Create a new `Vault` to pick up changes written by another process. Opening fails while the vault has unresolved conflicts.

See the [Thorax documentation](https://github.com/backbone-hq/thorax) for vault setup, selectors, access control, and the security model.

Thorax is licensed under the [Apache License 2.0](https://github.com/backbone-hq/thorax/blob/master/LICENSE).
