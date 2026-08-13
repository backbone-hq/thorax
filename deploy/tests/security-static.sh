#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

fail() {
  echo "security invariant failed: $*" >&2
  exit 1
}

while IFS= read -r use; do
  reference=${use##*@}
  reference=${reference%% *}
  [[ "$reference" == ./* ]] && continue
  [[ "$reference" =~ ^[0-9a-f]{40}$ ]] || fail "GitHub Action is not commit-pinned: $use"
done < <(sed -nE 's/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+([^#]+).*/\2/p' .github/workflows/*.y*ml)

grep -Fq 'FROM scratch' deploy/thorax-kubernetes-controller.Dockerfile \
  || fail "controller runtime is not scratch"
grep -Eq '^FROM .*@sha256:[0-9a-f]{64} AS builder$' \
  deploy/thorax-kubernetes-controller.Dockerfile \
  || fail "controller builder is not digest-pinned"
grep -Fq 'cargo build --locked --profile controller' \
  deploy/thorax-kubernetes-controller.Dockerfile \
  || fail "controller image does not use the hardened Cargo profile"
grep -Fq 'panic = "abort"' Cargo.toml || fail "controller profile permits panic unwinding"
grep -Fq 'overflow-checks = true' Cargo.toml || fail "controller profile disables overflow checks"
if grep -Eq '(^|[[:space:]])latest([[:space:]]|$)' \
  deploy/thorax-kubernetes-controller.Dockerfile .github/workflows/release-artifacts.yml; then
  fail "mutable latest image reference is present"
fi
if grep -REq '^([[:space:]]*)(runs-on:|-[[:space:]]+os:).*latest' .github/workflows; then
  fail "GitHub-hosted runner label is mutable"
fi
if grep -Eq 'pip install|npm install -g' .github/workflows/release-artifacts.yml; then
  fail "release tooling bypasses commit or lockfile integrity pins"
fi
grep -Fq 'maturin-version: v1.14.1' .github/workflows/release-artifacts.yml \
  || fail "maturin version is not explicit"
grep -Fq 'npm ci --ignore-scripts' .github/workflows/release-artifacts.yml \
  || fail "Node release tooling does not use the checked-in lockfile"
grep -Fq 'merge-multiple: true' .github/workflows/release-artifacts.yml \
  || fail "Node release packaging does not merge the platform artifact matrix"
grep -Fq 'workflow_call:' .github/workflows/ci.yml \
  || fail "release builds cannot invoke the complete reusable CI gate"
grep -Fq 'uses: ./.github/workflows/ci.yml' .github/workflows/release-artifacts.yml \
  || fail "release workflow does not require the complete CI gate"
grep -Fq 'expected_ref="refs/tags/v$REQUESTED_VERSION"' .github/workflows/release-artifacts.yml \
  || fail "release workflow is not bound to its version tag"
grep -Fq 'build-${{ github.run_id }}' .github/workflows/release-artifacts.yml \
  || fail "controller image does not use a retry-safe run-scoped staging tag"
if grep -Eq 'promote-controller-image:|thorax-kubernetes-controller:\$\{\{ inputs\.version \}\}' \
  .github/workflows/release-artifacts.yml; then
  fail "public CI may stage controller images but may not publish a versioned GHCR image"
fi
grep -Fq 'STAGING_IMAGE: ghcr.io/backbone-hq/thorax-kubernetes-controller:build-${{ github.run_id }}' \
  .github/workflows/release-artifacts.yml \
  || fail "controller manifest assembly does not target a run-scoped staging image"
if grep -F 'imagetools create' .github/workflows/release-artifacts.yml \
    | grep -Fqv -- '--tag "$STAGING_IMAGE"'; then
  fail "public CI may assemble only the run-scoped controller staging image"
fi
if grep -Fq 'gh release ' .github/workflows/release-artifacts.yml; then
  fail "public CI may not create or mutate GitHub Releases"
fi
grep -Fq '"integrity":' crates/thorax-node/package-lock.json \
  || fail "Node release lockfile lacks package integrity hashes"
grep -Fq 'kubeVersion: ">=1.31.0-0"' \
  deploy/charts/thorax-kubernetes-controller/Chart.yaml \
  || fail "chart Kubernetes compatibility floor changed without review"
if grep -Fq 'all(key, value,' \
  deploy/charts/thorax-kubernetes-controller/crds/thorax.backbone.dev.yaml; then
  fail "CRD uses a two-variable CEL map comprehension unsupported by Kubernetes 1.31"
fi
for required in \
  'THORAX_E2E_DISPOSABLE_CLUSTER' \
  'the public acceptance test runs only against an explicitly disposable cluster' \
  'THORAX_E2E_NAMESPACE must begin with thorax-e2e-' \
  'thorax_e2e_cleanup_environment'; do
  grep -Fq "$required" deploy/tests/cnpg-e2e.sh \
    || fail "public acceptance harness lacks disposable-cluster guard: $required"
done
[[ "$(sed -n '1p' .dockerignore)" == "# The controller build context is an allow-list. In particular, local vaults," ]] \
  || fail "Docker context allow-list header changed unexpectedly"
grep -Fxq '**' .dockerignore || fail "Docker build context is not deny-by-default"

rendered=$(mktemp /tmp/thorax-security-render.XXXXXX)
trap 'rm -f -- "$rendered"' EXIT
helm template hardened deploy/charts/thorax-kubernetes-controller \
  --namespace thorax-security \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  >"$rendered"

for required in \
  'automountServiceAccountToken: false' \
  'runAsNonRoot: true' \
  'runAsUser: 65532' \
  'runAsGroup: 65532' \
  'allowPrivilegeEscalation: false' \
  'readOnlyRootFilesystem: true' \
  'seccompProfile:' \
  'drop: ["ALL"]' \
  'expirationSeconds: 3600' \
  'ingress: []' \
  'hardened-thorax-kubernetes-controller-publisher' \
  '@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
  grep -Fq -- "$required" "$rendered" || fail "rendered chart lacks $required"
done

if awk '
  /^kind: Role$/ { role_count++; controller = (role_count == 1); next }
  /resources: \["configmaps"\]/ || /resources: \["secrets"\]/ { sensitive=1; next }
  sensitive && /resources:/ { sensitive=0 }
  controller && sensitive && /verbs:/ && ($0 ~ /"list"/ || $0 ~ /"watch"/ || $0 ~ /"patch"/) { exit 1 }
' "$rendered"; then
  :
else
  fail "controller can list, watch, or patch core Secrets or ConfigMaps"
fi

for required in \
  'kind: ValidatingAdmissionPolicy' \
  "kind == 'ThoraxSecret'" \
  "kind == 'ThoraxVault'" \
  "variables.target.type != 'kubernetes.io/service-account-token'" \
  "variables.target.metadata.annotations.all" \
  "'master-seed' in variables.target.data" \
  'size(variables.target.data) == 4' \
  "'ratchet.cord' in variables.target.data" \
  "'ratchet.mac' in variables.target.data" \
  "'trusted-root' in variables.target.data" \
  "'user-id' in variables.target.data" \
  'validationActions: [Deny, Audit]'; do
  grep -Fq -- "$required" "$rendered" || fail "rendered chart lacks admission guard $required"
done

if grep -R -n --include='*.yaml' --include='*.yml' --include='*.tpl' 'RUST_LOG' \
  deploy/charts .github/workflows; then
  fail "dependency tracing can be enabled from a deployment manifest"
fi

echo "security static checks passed"
