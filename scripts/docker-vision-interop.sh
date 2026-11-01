#!/bin/sh
# A fresh Docker build and an independent Xray peer; no host proxy or TUN needed.
# Set VISION_SECURITY=tls or reality to run one transport separately.
set -eu
REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RUST_IMAGE="${RUST_IMAGE:-rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97}"
XRAY_IMAGE="${XRAY_IMAGE:-ghcr.io/xtls/xray-core@sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044}"
SINGBOX_IMAGE="${SINGBOX_IMAGE:-ghcr.io/sagernet/sing-box@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279}"
RUN_ID="mihomo-vision-$$"
TASK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/mihomo-vision.XXXXXX")"
RESULT_DIR="${RESULT_DIR:-$TASK_TMP/results}"
VISION_SECURITY="${VISION_SECURITY:-all}"
mkdir -p "$RESULT_DIR"
RESULT_DIR="$(CDPATH= cd -- "$RESULT_DIR" && pwd)"
cleanup() {
    docker rm -f "$RUN_ID" "$RUN_ID-xray" "$RUN_ID-singbox" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker create --name "$RUN_ID-xray" "$XRAY_IMAGE" >/dev/null
docker cp "$RUN_ID-xray:/usr/local/bin/xray" "$TASK_TMP/xray"
docker rm "$RUN_ID-xray" >/dev/null
docker create --name "$RUN_ID-singbox" "$SINGBOX_IMAGE" >/dev/null
docker cp "$RUN_ID-singbox:/usr/local/bin/sing-box" "$TASK_TMP/sing-box"
docker rm "$RUN_ID-singbox" >/dev/null
# Anonymous volumes keep build files off the host checkout and are deleted on
# exit. The optional existing registry is copied, never modified.
SEED_DIR="$REPO_DIR/rust/.cargo-home-agent2"
if [ ! -d "$SEED_DIR/registry" ]; then
    SEED_DIR="$TASK_TMP/empty-seed"
    mkdir -p "$SEED_DIR"
fi
printf 'Docker validation output: %s\n' "$RESULT_DIR"
docker run --rm --name "$RUN_ID" \
    -v "$REPO_DIR:/repo:ro" \
    -v "$TASK_TMP/xray:/opt/xray:ro" \
    -v "$TASK_TMP/sing-box:/opt/sing-box:ro" \
    -v "$SEED_DIR:/seed:ro" \
    -v "$RESULT_DIR:/results" \
    -v /cargo -v /target \
    -e VISION_SECURITY="$VISION_SECURITY" \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
    -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -e CARGO_INCREMENTAL=0 \
    -w /repo/rust "$RUST_IMAGE" sh -c '
        set -eu
        export PATH=/usr/local/cargo/bin:$PATH
        if [ -d /seed/registry ]; then cp -a /seed/registry /cargo/registry; fi
        rustc --version > /results/toolchain.txt
        /opt/xray version >> /results/toolchain.txt
        /opt/sing-box version >> /results/toolchain.txt
        cargo test --locked -p mihomo-transport --lib -- --test-threads=1 > /results/transport.log 2>&1
        cargo test --locked -p mihomo-runtime --lib -- --test-threads=1 > /results/runtime.log 2>&1
        cargo test --locked -p mihomo-app vless -- --test-threads=1 > /results/app-vless.log 2>&1
        cargo build --locked -p mihomo-app --bin mihomo > /results/build.log 2>&1
        python3 /repo/scripts/vision-interop.py --xray /opt/xray --security "$VISION_SECURITY" --mlkem on --output /results/xray
        python3 /repo/scripts/vision-interop.py --xray /opt/xray --sing-box /opt/sing-box --server sing-box --security "$VISION_SECURITY" --mlkem off --output /results/sing-box-legacy-profile
        python3 /repo/scripts/vision-interop.py --xray /opt/xray --sing-box /opt/sing-box --server sing-box --security "$VISION_SECURITY" --mlkem on --output /results/sing-box-hybrid-profile
    '
printf 'Validation passed. Logs: %s\n' "$RESULT_DIR"
