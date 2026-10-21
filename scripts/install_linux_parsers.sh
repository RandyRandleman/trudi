#!/usr/bin/env bash
# Install TRUDI's Linux-native Windows-artifact parsers.
#
#   evtx_dump      0.12.2   EVTX      MIT/Apache-2.0  (cargo, locked)
#   trudi-prefetch 0.1.0    Prefetch  MIT over Apache-2.0 prefetch-core (built from rust/)
#   chainsaw       v2.10.2  SRUM      GPL-3.0 — separate, unmodified release binary
#
# Versions are pinned and the downloaded binary is checksum-verified. Nothing
# here runs during evidence processing: install first, then parse.
#
# Usage: scripts/install_linux_parsers.sh [--prefix /usr/local/bin] [--skip-chainsaw]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="/usr/local/bin"
SKIP_CHAINSAW=0
EVTX_VERSION="0.12.2"
CHAINSAW_TAG="v2.10.2"            # the binary in this release self-reports 2.10.1
CHAINSAW_SHA256_x86_64="c7cc7673117f5577a71f18f09d83a6c503301a0d4476d97da005d4235b74fcd2"
CHAINSAW_SHA256_aarch64="50b22ef9ef26d2e62ae0517bfcdb56772e30516410994e58a17a332b8d58a150"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --skip-chainsaw) SKIP_CHAINSAW=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '  %s\n' "$*"; }
die() { printf '  ✗ %s\n' "$*" >&2; exit 1; }

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  CS_ARCH=x86_64;  CS_SHA="$CHAINSAW_SHA256_x86_64" ;;
  aarch64|arm64) CS_ARCH=aarch64; CS_SHA="$CHAINSAW_SHA256_aarch64" ;;
  *) CS_ARCH=""; CS_SHA="" ;;
esac

command -v cargo >/dev/null || die "cargo (Rust 1.85+) is required to build the native parsers"
install -d "$PREFIX"

# ── EVTX ────────────────────────────────────────────────────────────────────
say "installing evtx_dump ${EVTX_VERSION} (pinned, --locked)"
CARGO_ROOT="$(mktemp -d)"
cargo install evtx --version "$EVTX_VERSION" --locked --root "$CARGO_ROOT" >/dev/null
install -m 0755 "$CARGO_ROOT/bin/evtx_dump" "$PREFIX/evtx_dump"
rm -rf "$CARGO_ROOT"
"$PREFIX/evtx_dump" --version

# ── Prefetch ────────────────────────────────────────────────────────────────
say "building trudi-prefetch (prefetch-core, clean-room Xpress-Huffman)"
cargo build --release --locked --manifest-path "$REPO/rust/trudi-prefetch/Cargo.toml" >/dev/null
install -m 0755 "$REPO/rust/trudi-prefetch/target/release/trudi-prefetch" "$PREFIX/trudi-prefetch"
"$PREFIX/trudi-prefetch" --version

# ── SRUM ────────────────────────────────────────────────────────────────────
if [ "$SKIP_CHAINSAW" = 1 ]; then
  say "skipping chainsaw (SRUM parsing will report parser_unavailable)"
elif [ -z "$CS_ARCH" ]; then
  say "! chainsaw has no release build for $ARCH — SRUM will report parser_unavailable"
else
  say "installing chainsaw ${CHAINSAW_TAG} (${CS_ARCH}, checksum-verified, GPL-3.0)"
  TMP="$(mktemp -d)"
  URL="https://github.com/WithSecureLabs/chainsaw/releases/download/${CHAINSAW_TAG}/chainsaw_${CS_ARCH}-unknown-linux-gnu.tar.gz"
  curl -fsSL -o "$TMP/chainsaw.tgz" "$URL" || die "could not download $URL"
  echo "${CS_SHA}  $TMP/chainsaw.tgz" | sha256sum -c - >/dev/null \
    || die "chainsaw checksum mismatch — refusing to install"
  tar -xzf "$TMP/chainsaw.tgz" -C "$TMP"
  install -m 0755 "$(find "$TMP" -type f -name chainsaw | head -1)" "$PREFIX/chainsaw"
  install -d /usr/local/share/chainsaw
  for d in sigma mappings rules; do
    s="$(find "$TMP" -type d -name "$d" | head -1)"
    [ -n "$s" ] && cp -r "$s" /usr/local/share/chainsaw/ || true
  done
  # GPL-3.0: ship the licence next to the binary we distribute.
  lic="$(find "$TMP" -maxdepth 3 -iname 'LICENSE*' | head -1)"
  [ -n "$lic" ] && install -m 0644 "$lic" /usr/local/share/chainsaw/LICENSE || true
  rm -rf "$TMP"
  "$PREFIX/chainsaw" --version
fi

say "health check:"
PATH="$PREFIX:$PATH" python3 - <<'EOF' || true
import json, sys
sys.path.insert(0, ".")
try:
    from core.parsers import capabilities
    print(json.dumps(capabilities(), indent=2)[:2000])
except Exception as e:
    print(f"(capability probe unavailable outside the repo: {e})")
EOF
