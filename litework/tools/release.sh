#!/usr/bin/env bash
# Build distributable LiteWork artifacts.
#   tools/release.sh            # host + x86_64 musl (static)
# Cross-targets (Windows/macOS) are built on their own hosts or in CI.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
OUT=dist
mkdir -p "$OUT"

build() {
    local target="$1" label="$2"
    echo "== building $label ($target)"
    cargo build --release --target "$target"
    local bin="target/$target/release/litework"
    strip "$bin" 2>/dev/null || true
    local pkg="$OUT/litework-$VERSION-$label"
    rm -rf "$pkg" && mkdir -p "$pkg"
    cp "$bin" README.md LICENSE-MIT LICENSE-APACHE "$pkg/"
    tar -C "$OUT" -czf "$pkg.tar.gz" "$(basename "$pkg")"
    rm -rf "$pkg"
    echo "   $(du -h "$pkg.tar.gz" | cut -f1)  $pkg.tar.gz"
}

# Static Linux binary: runs on any distro, no dependencies.
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
build x86_64-unknown-linux-musl linux-x86_64-static

echo "== checksums"
(cd "$OUT" && sha256sum litework-"$VERSION"-*.tar.gz | tee SHA256SUMS)
