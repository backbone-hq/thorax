# Contributing

Thorax accepts focused contributions to its Rust crates, CLI, TUI, SDKs, Kubernetes integration, tests, and documentation.

Use [GitHub issues](https://github.com/backbone-hq/thorax/issues) for reproducible bugs and concrete feature proposals. Security vulnerabilities must follow [SECURITY.md](./SECURITY.md) and must not be reported publicly. Architectural or project-direction questions may be sent to [root@backbone.dev](mailto:root@backbone.dev).

## Before Starting

For a substantial change, open an issue before investing in an implementation. Describe the problem, the affected interface, the intended behavior, and any compatibility or security consequences.

Keep changes scoped. Preserve unrelated work in the repository, and do not combine broad formatting or dependency changes with a behavioral fix unless they are required.

Thorax is a security-sensitive system. Changes must preserve these principles:

- Invalid, unauthorized, conflicted, and suspected rollback states fail closed
- Frontends use the shared operation layer instead of manipulating signed records directly
- Tests, fixtures, logs, screenshots, and examples contain no real secrets or private identity material
- Public behavior and documentation describe implemented guarantees only
- Compatibility follows the contract in [README.md](./README.md#compatibility)

## Development Requirements

The workspace requires Rust 1.92. Use the committed `Cargo.lock` for reproducible checks.

Run the same core checks used by the public GitHub workflow before opening a pull request:

```sh
cargo fmt --check
scripts/bump-version.sh --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS=-Dwarnings cargo doc --locked --no-deps --all-features
cargo test --locked --workspace
```

Changes to the Kubernetes API or controller also require Helm and the public security checks:

```sh
generated_crds="$(mktemp)"
cargo run --locked --quiet -p thorax-kubernetes-api --example crdgen > "$generated_crds"
diff -u deploy/charts/thorax-kubernetes-controller/crds/thorax.backbone.dev.yaml "$generated_crds"
helm lint deploy/charts/thorax-kubernetes-controller \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
deploy/tests/security-static.sh
```

The GitHub workflow runs the complete workspace checks and the Kubernetes acceptance suite on pull requests to `master`.

## Pull Requests

A pull request should explain:

- The problem being solved
- The chosen behavior and security implications
- Compatibility considerations
- The tests or checks that cover the change
- Any operational or migration steps users must take

Add focused tests for behavioral changes. Update public documentation when a command, SDK, vault behavior, Kubernetes resource, security boundary, or compatibility guarantee changes.

## Documentation Style

Use the README as the tone and terminology reference.

- Write in direct, precise language
- Use sentence case for prose and title case for headings
- Use `Thorax`, `Kubernetes`, `Git`, `Rust`, `Python`, and `Node` consistently
- Prefer concrete behavior over promotional claims
- Distinguish guarantees, assumptions, limitations, and recommendations
- Do not use emojis, decorative symbols, jokes, hype, or em dashes
- Reference only commands, packages, files, and workflows present in the public GitHub repository

Thorax is maintained by [Backbone](https://backbone.dev) and licensed under the [Apache License 2.0](./LICENSE).
