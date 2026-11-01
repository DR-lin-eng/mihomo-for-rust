#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
usage: docker-rust-test-clean.sh --target-dir NAME [--cargo-home NAME] -- <cargo test args...>

Runs one Rust test command in Docker after cleaning the previous target dir.

required:
  --target-dir NAME   target dir name under rust/ to delete before the run
  --cargo-home NAME   cargo home dir name under rust/ to delete before the run

example:
  sh scripts/docker-rust-test-clean.sh --target-dir target-codex-mixed-worker -- \
    cargo test -p mihomo-app slow_udp_no_longer_blocks_tcp_flow_progress -- --nocapture --test-threads=1
EOF
}

TARGET_DIR_NAME=""
CARGO_HOME_NAME=""
CONTAINER_NAME="codex-rust-test-clean"

while [ $# -gt 0 ]; do
  case "$1" in
    --target-dir)
      TARGET_DIR_NAME="${2-}"
      shift 2
      ;;
    --cargo-home)
      CARGO_HOME_NAME="${2-}"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[ -n "$TARGET_DIR_NAME" ] || {
  echo "missing --target-dir" >&2
  usage >&2
  exit 2
}

[ $# -gt 0 ] || {
  echo "missing cargo command" >&2
  usage >&2
  exit 2
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
RUST_DIR="$REPO_DIR/rust"
TARGET_DIR="$RUST_DIR/$TARGET_DIR_NAME"
CARGO_HOME_DIR="$RUST_DIR/${CARGO_HOME_NAME:-.cargo-home-test}"

mkdir -p "$CARGO_HOME_DIR"

# Stop stale local rust:1.88 containers from prior interrupted runs.
docker ps --format '{{.ID}} {{.Image}}' \
  | awk '$2 == "rust:1.88" { print $1 }' \
  | while IFS= read -r container_id; do
      [ -n "$container_id" ] || continue
      running_name="$(docker inspect --format '{{ index .Config.Labels "codex.rust-test-clean" }}' "$container_id" 2>/dev/null || true)"
      [ "$running_name" = "true" ] || continue
      docker rm -f "$container_id" >/dev/null 2>&1 || true
    done

rm -rf "$TARGET_DIR"

docker run --rm --platform linux/arm64 \
  --label codex.rust-test-clean=true \
  -e RUSTFLAGS \
  -v "$RUST_DIR":/work \
  -v "$CARGO_HOME_DIR":/cargo-home \
  -w /work \
  rust:1.88 \
  sh -lc 'export PATH=/usr/local/cargo/bin:$PATH; export CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/work/'"$TARGET_DIR_NAME"' CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0; "$@"' sh "$@"
