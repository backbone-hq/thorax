# Thorax for Node.js

Native Node.js SDK for [Thorax](https://github.com/backbone-hq/thorax), secrets management for humans, agents, and apps.

The SDK is a small application-facing facade over Thorax's shared operation layer. It uses the same vault validation, authorization, keychain, and cryptography as the CLI, TUI, Rust SDK, and Python SDK.

## Installation

Thorax requires Node.js 18 or later.

```sh
npm install @backbone-hq/thorax
```

The SDK opens an existing Thorax vault. Install the [Thorax CLI](https://github.com/backbone-hq/thorax#installation) and run `thorax init` in your project if you do not have one yet.

## Quick start

By default, `Vault.open()` opens `.thorax/vault.cord` and authenticates with the configured local identity and keychain:

```js
const { Vault } = require("@backbone-hq/thorax");

const vault = await Vault.open();
const databaseUrl = await vault.get("app/prod/db");
```

Or with TypeScript and an explicit directory containing `vault.cord`:

```ts
import { Vault } from "@backbone-hq/thorax";

const vault = await Vault.open({ path: "/srv/my-app/.thorax" });
const databaseUrl = await vault.get("app/prod/db");
```

Values are strings by default. Set `asBuffer: true` when reading a binary value:

```js
const certificate = await vault.get("app/prod/certificate", { asBuffer: true });
await vault.set("app/prod/token", Buffer.from("binary value"));
```

## Working with secrets

```js
await vault.set("app/prod/db", "postgres://localhost/app");
await vault.setField("app/prod/db", "username", "app");

const username = await vault.getField("app/prod/db", "username");
const fields = await vault.fields("app/prod/db");
const selectors = await vault.list("app/prod");

await vault.deleteField("app/prod/db", "username");
await vault.delete("app/prod/db");
vault.close();
```

Selectors may be strings such as `app/prod/db@region=eu`, or structured objects such as `{ path: ["app", "prod", "db"], labels: { region: "eu" } }`.

## Authentication

Local development uses the keychain by default. You can select a particular identity or supply a passphrase to a noninteractive caller:

```js
const { Auth, Vault } = require("@backbone-hq/thorax");

const auth = Auth.fromKeychain({ user: "alice", passphrase: "..." });
const vault = await Vault.open({ auth });
```

For CI and deployed applications, use a dedicated, least-privilege invite identity. `Auth.fromEnv()` reads exactly one of `THORAX_UNSAFE_INVITE` or `THORAX_UNSAFE_INVITE_FILE`:

```js
const vault = await Vault.open({ auth: Auth.fromEnv() });
```

An invite is a private capability. Keep it out of source control and prefer the file variable when your runtime can mount it as a secret. `Auth.fromInvite()` also accepts an invite directly.

## Errors and session behavior

Rejected operations use Node `Error` objects whose messages are prefixed with a Thorax error category. A session validates the vault when it opens and sees its own writes immediately. Reopen the vault to pick up changes written by another process. Opening fails while the vault has unresolved conflicts.

See the [Thorax documentation](https://github.com/backbone-hq/thorax) for vault setup, selectors, access control, and the security model.

Thorax is licensed under the [Apache License 2.0](https://github.com/backbone-hq/thorax/blob/master/LICENSE).
