#!/usr/bin/env bash
# Keep every committed Thorax release-version field consistent.
#
# Cargo.toml is the single source of truth. Rust packages and the Python wheel
# inherit it directly. npm and Helm sources use development sentinels and are
# assigned the Cargo version only when release artifacts are packaged.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/scripts/bump-version.sh"
STABLE_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

fail() {
    echo "version bump failed: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: scripts/bump-version.sh major|minor|patch|MAJOR.MINOR.PATCH
       scripts/bump-version.sh --check [MAJOR.MINOR.PATCH]

Cargo.toml is authoritative. A bump updates its workspace version and the
version requirements on publishable internal path dependencies, refreshes
Cargo.lock, and verifies all derived package surfaces.

npm package.json/package-lock.json and the source Helm chart deliberately carry
0.0.0-development. Public release packaging replaces that sentinel with the
authoritative Cargo version without modifying the source checkout.
EOF
}

workspace_version() {
    awk '
        /^\[workspace\.package\]$/ { in_workspace = 1; next }
        in_workspace && /^\[/ { exit }
        in_workspace && /^version = "/ {
            value = $0
            sub(/^version = "/, "", value)
            sub(/".*$/, "", value)
            print value
            exit
        }
    ' "$ROOT/Cargo.toml"
}

check_consistency() {
    local expected="$1"
    [[ "$expected" =~ $STABLE_RE ]] || fail "invalid stable version '$expected'"
    command -v python3 >/dev/null 2>&1 || fail "python3 is required"
    command -v cargo >/dev/null 2>&1 || fail "cargo is required"

    python3 - "$ROOT" "$expected" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
errors = []

cargo_path = root / "Cargo.toml"
cargo_text = cargo_path.read_text()
workspace_match = re.search(
    r"(?ms)^\[workspace\.package\]\s*$.*?^version\s*=\s*\"([^\"]+)\"",
    cargo_text,
)
if not workspace_match or workspace_match.group(1) != expected:
    actual = workspace_match.group(1) if workspace_match else "missing"
    errors.append(f"Cargo.toml workspace version is {actual}, expected {expected}")

internal_dependencies = list(
    re.finditer(r'(?m)^(thorax-[A-Za-z0-9-]+)\s*=\s*\{([^}\n]*\bpath\s*=[^}\n]*)\}', cargo_text)
)
if not internal_dependencies:
    errors.append("Cargo.toml contains no versioned internal path dependencies")
for dependency in internal_dependencies:
    name, fields = dependency.groups()
    version = re.search(r'\bversion\s*=\s*"([^"]+)"', fields)
    if not version or version.group(1) != expected:
        actual = version.group(1) if version else "missing"
        errors.append(f"Cargo dependency {name} requires {actual}, expected {expected}")

development = "0.0.0-development"
for relative in ("crates/thorax-node/package.json", "crates/thorax-node/package-lock.json"):
    path = root / relative
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{relative} is unreadable: {error}")
        continue
    if document.get("version") != development:
        errors.append(f"{relative} version must remain {development}")
    if relative.endswith("package-lock.json"):
        root_package = document.get("packages", {}).get("", {})
        if root_package.get("version") != development:
            errors.append(f"{relative} root package version must remain {development}")

chart_path = root / "deploy/charts/thorax-kubernetes-controller/Chart.yaml"
chart_text = chart_path.read_text()
for key, pattern in (
    ("version", r'(?m)^version:\s*([^\s]+)\s*$'),
    ("appVersion", r'(?m)^appVersion:\s*"?([^"\s]+)"?\s*$'),
):
    match = re.search(pattern, chart_text)
    if not match or match.group(1) != development:
        actual = match.group(1) if match else "missing"
        errors.append(f"Helm {key} is {actual}, expected source sentinel {development}")

scaffold_path = root / "tools/scripts/build-install.sh"
if scaffold_path.exists():
    scaffold = scaffold_path.read_text()
    if f'"version": "{development}"' not in scaffold:
        errors.append("Node fallback scaffold does not use the development version sentinel")

metadata = subprocess.run(
    ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if metadata.returncode:
    errors.append("Cargo.lock is stale: " + metadata.stderr.strip())
    package_count = 0
else:
    document = json.loads(metadata.stdout)
    by_id = {package["id"]: package for package in document["packages"]}
    packages = [by_id[member] for member in document["workspace_members"]]
    package_count = len(packages)
    for package in packages:
        if package["version"] != expected:
            errors.append(
                f'workspace package {package["name"]} is {package["version"]}, expected {expected}'
            )

if errors:
    for error in errors:
        print(f"version consistency error: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"version consistency OK: {expected} "
    f"({package_count} Cargo packages; npm and Helm derived at packaging)"
)
PY
}

current="$(workspace_version)"
[[ -n "$current" && "$current" =~ $STABLE_RE ]] \
    || fail "Cargo.toml does not contain a stable workspace version"

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    --check)
        (( $# <= 2 )) || fail "--check accepts at most one version"
        check_consistency "${2:-$current}"
        exit 0
        ;;
    "")
        usage >&2
        exit 2
        ;;
esac

(( $# == 1 )) || fail "expected exactly one bump kind or version"
request="$1"
IFS=. read -r major minor patch <<<"$current"
case "$request" in
    major) next="$((major + 1)).0.0" ;;
    minor) next="$major.$((minor + 1)).0" ;;
    patch) next="$major.$minor.$((patch + 1))" ;;
    *)
        [[ "$request" =~ $STABLE_RE ]] || fail "invalid stable version '$request'"
        next="$request"
        ;;
esac

if [[ "$next" == "$current" ]]; then
    check_consistency "$current"
    echo "version already $current; nothing changed"
    exit 0
fi

IFS=. read -r next_major next_minor next_patch <<<"$next"
if (( next_major < major \
    || (next_major == major && next_minor < minor) \
    || (next_major == major && next_minor == minor && next_patch < patch) )); then
    fail "refusing version downgrade from $current to $next"
fi

check_consistency "$current" >/dev/null

backup="$(mktemp -d "${TMPDIR:-/tmp}/thorax-version-bump.XXXXXX")"
cp "$ROOT/Cargo.toml" "$backup/Cargo.toml"
cp "$ROOT/Cargo.lock" "$backup/Cargo.lock"
completed=0
cleanup() {
    local status=$?
    trap - EXIT
    if (( ! completed )); then
        cp "$backup/Cargo.toml" "$ROOT/Cargo.toml"
        cp "$backup/Cargo.lock" "$ROOT/Cargo.lock"
        echo "version bump failed; restored Cargo.toml and Cargo.lock" >&2
    fi
    rm -rf -- "$backup"
    exit "$status"
}
trap cleanup EXIT

python3 - "$ROOT/Cargo.toml" "$current" "$next" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text()

workspace = re.compile(
    rf'(?ms)(^\[workspace\.package\]\s*$.*?^version\s*=\s*"){re.escape(old)}(".*$)'
)
text, count = workspace.subn(rf"\g<1>{new}\g<2>", text, count=1)
if count != 1:
    raise SystemExit("could not replace the workspace package version exactly once")

pattern = re.compile(
    rf'(?m)(^thorax-[A-Za-z0-9-]+\s*=\s*\{{(?=[^}}\n]*\bpath\s*=)[^}}\n]*'
    rf'\bversion\s*=\s*"){re.escape(old)}(")'
)
text, dependency_count = pattern.subn(rf"\g<1>{new}\g<2>", text)
if dependency_count == 0:
    raise SystemExit("could not replace any internal path dependency requirements")

temporary = path.with_name(path.name + ".version-bump.tmp")
temporary.write_text(text)
temporary.chmod(path.stat().st_mode)
temporary.replace(path)
PY

( cd "$ROOT" && cargo metadata --no-deps --format-version 1 >/dev/null )
"$SELF" --check "$next"

completed=1
echo "bumped Thorax $current -> $next"
echo "updated Cargo.toml and Cargo.lock; npm and Helm derive $next during packaging"
