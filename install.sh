#!/usr/bin/env sh
#
# Install the latest Thorax CLI release for Linux or macOS.
#
# Check the installer checksum before running it:
#
#   f="$(mktemp)" &&
#     curl -fsSL -o "$f" "https://github.com/backbone-hq/thorax/releases/download/vX.Y.Z/install.sh" &&
#     echo "<sha256 from the GitHub Release notes>  $f" | { command -v sha256sum >/dev/null && sha256sum -c - || shasum -a 256 -c -; } &&
#     THORAX_VERSION=vX.Y.Z sh "$f"
#
# Environment:
#   THORAX_REPO         owner/repo to install from (default: backbone-hq/thorax)
#   THORAX_VERSION      install a specific version, with or without leading v
#   THORAX_INSTALL_DIR  destination directory (default: ~/.local/bin)

set -eu
umask 077

repo="${THORAX_REPO:-backbone-hq/thorax}"
install_dir="${THORAX_INSTALL_DIR:-$HOME/.local/bin}"

say() {
    printf '%s\n' "$*" >&2
}

fail() {
    say "thorax install: $*"
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1
}

hash_file() {
    if need sha256sum; then
        sha256sum "$1" | awk '{ print $1 }'
    elif need shasum; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    elif need openssl; then
        openssl dgst -sha256 "$1" | awk '{ print $NF }'
    else
        fail "need sha256sum, shasum, or openssl to verify the bootstrap installer"
    fi
}

verify_hash() {
    path="$1"
    expected="$2"
    label="$3"
    case "$expected" in
        ""|__THORAX_*) fail "installer is missing embedded checksum for $label" ;;
    esac
    actual="$(hash_file "$path")"
    if [ "$actual" != "$expected" ]; then
        fail "$label checksum mismatch: expected $expected, got $actual"
    fi
}

download() {
    case "$1" in
        https://*) ;;
        *) fail "refusing non-HTTPS download URL: $1" ;;
    esac
    if need curl; then
        curl -fL --proto '=https' --tlsv1.2 "$1" -o "$2"
    elif need wget; then
        wget -O "$2" "$1"
    else
        fail "need curl or wget"
    fi
}

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "unsupported OS: $(uname -s)" ;;
esac

case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    arm64|aarch64) arch=aarch64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

case "$os-$arch" in
    linux-x86_64)
        target=x86_64-unknown-linux-gnu
        bootstrap_sha256="__THORAX_BOOTSTRAP_SHA256_x86_64_unknown_linux_gnu__"
        ;;
    linux-aarch64)
        target=aarch64-unknown-linux-gnu
        bootstrap_sha256="__THORAX_BOOTSTRAP_SHA256_aarch64_unknown_linux_gnu__"
        ;;
    macos-x86_64)
        target=x86_64-apple-darwin
        bootstrap_sha256="__THORAX_BOOTSTRAP_SHA256_x86_64_apple_darwin__"
        ;;
    macos-aarch64)
        target=aarch64-apple-darwin
        bootstrap_sha256="__THORAX_BOOTSTRAP_SHA256_aarch64_apple_darwin__"
        ;;
    *) fail "unsupported platform: $os-$arch" ;;
esac

if [ "${THORAX_VERSION:-}" ]; then
    version="$THORAX_VERSION"
    case "$version" in
        v*) ;;
        *) version="v$version" ;;
    esac
    base_url="https://github.com/$repo/releases/download/$version"
else
    base_url="https://github.com/$repo/releases/latest/download"
fi

bootstrap_asset="thorax-install-bootstrap-$target"
bootstrap_url="$base_url/$bootstrap_asset"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/thorax-install.XXXXXX")" \
    || fail "could not create a private temporary directory"
case "$tmp" in
    "${TMPDIR:-/tmp}"/thorax-install.*) ;;
    *) fail "mktemp returned an unexpected path" ;;
esac
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $bootstrap_url"
download "$bootstrap_url" "$tmp/$bootstrap_asset"
verify_hash "$tmp/$bootstrap_asset" "$bootstrap_sha256" "$bootstrap_asset"
chmod 755 "$tmp/$bootstrap_asset"

"$tmp/$bootstrap_asset" \
    --base-url "$base_url" \
    --install-dir "$install_dir"

case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) say "note: $install_dir is not on PATH" ;;
esac

"$install_dir/thorax" --version || true
