#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: openwrt-device-deploy.sh --host HOST (--package PATH | --core PATH) [options]

Required:
  --host HOST                 target OpenWrt host or user@host
  --package PATH              local .gz package to upload and unpack remotely
  --core PATH                 local core binary to upload directly

Options:
  --port PORT                 ssh/scp port
  --remote-core PATH          live core path on device
  --remote-config PATH        config path on device
  --remote-tmp DIR            remote temp working directory
  --stop-cmd CMD              remote command to stop existing service before activation/smoke
  --start-cmd CMD             remote command to start existing service after activation
  --activate                  replace the live core after candidate checks pass
  --no-backup                 skip live core backup before activation
  --no-rollback               skip rollback when post-activation checks fail
  --skip-remote-smoke         skip remote candidate smoke
  --smoke-args STRING         candidate smoke args
  --live-smoke-args STRING    live-core smoke args after activation
  --keep-remote-tmp           keep uploaded temp files on device
  --help                      show this help

Defaults:
  remote-core   /data/kano_plugins/clash/Proxy/Clash.Core
  remote-config /data/kano_plugins/clash/Proxy/config.yaml
  remote-tmp    /tmp/mihomo-deploy
EOF
}

HOST=""
PORT=""
PACKAGE=""
CORE=""
REMOTE_CORE="/data/kano_plugins/clash/Proxy/Clash.Core"
REMOTE_CONFIG="/data/kano_plugins/clash/Proxy/config.yaml"
REMOTE_TMP="/tmp/mihomo-deploy"
STOP_CMD=""
START_CMD=""
ACTIVATE=0
BACKUP=1
ROLLBACK=1
RUN_REMOTE_SMOKE=1
KEEP_REMOTE_TMP=0
SMOKE_ARGS=""
LIVE_SMOKE_ARGS=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host) HOST="${2-}"; shift 2 ;;
    --port) PORT="${2-}"; shift 2 ;;
    --package) PACKAGE="${2-}"; shift 2 ;;
    --core) CORE="${2-}"; shift 2 ;;
    --remote-core) REMOTE_CORE="${2-}"; shift 2 ;;
    --remote-config) REMOTE_CONFIG="${2-}"; shift 2 ;;
    --remote-tmp) REMOTE_TMP="${2-}"; shift 2 ;;
    --stop-cmd) STOP_CMD="${2-}"; shift 2 ;;
    --start-cmd) START_CMD="${2-}"; shift 2 ;;
    --activate) ACTIVATE=1; shift ;;
    --no-backup) BACKUP=0; shift ;;
    --no-rollback) ROLLBACK=0; shift ;;
    --skip-remote-smoke) RUN_REMOTE_SMOKE=0; shift ;;
    --smoke-args) SMOKE_ARGS="${2-}"; shift 2 ;;
    --live-smoke-args) LIVE_SMOKE_ARGS="${2-}"; shift 2 ;;
    --keep-remote-tmp) KEEP_REMOTE_TMP=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$HOST" ] || { echo "missing --host" >&2; usage >&2; exit 2; }
[ -n "$PACKAGE" ] || [ -n "$CORE" ] || {
  echo "missing --package or --core" >&2
  usage >&2
  exit 2
}
[ -z "$PACKAGE" ] || [ -z "$CORE" ] || {
  echo "use either --package or --core, not both" >&2
  usage >&2
  exit 2
}
[ -z "$STOP_CMD" ] || [ -n "$START_CMD" ] || {
  echo "--stop-cmd requires --start-cmd so the service can be restored safely" >&2
  exit 2
}

if [ -n "$PACKAGE" ]; then
  [ -f "$PACKAGE" ] || { echo "package not found: $PACKAGE" >&2; exit 1; }
else
  [ -f "$CORE" ] || { echo "core not found: $CORE" >&2; exit 1; }
fi

SSH_ARGS=""
if [ -n "$PORT" ]; then
  SSH_ARGS="-p $PORT"
fi
SSH_BIN="${SSH_BIN:-ssh}"
SCP_BIN="${SCP_BIN:-scp}"

LOCAL_TMP_DIR="$(mktemp -d /tmp/mihomo-openwrt-deploy.XXXXXX)"
LOCAL_CORE="$LOCAL_TMP_DIR/Clash.Core"
LOCAL_SMOKE_SCRIPT="$LOCAL_TMP_DIR/openwrt-device-smoke.sh"
REMOTE_CANDIDATE="$REMOTE_TMP/Clash.Core.candidate"
REMOTE_SMOKE_SCRIPT="$REMOTE_TMP/openwrt-device-smoke.sh"
BACKUP_SUFFIX="$(date +%Y%m%d%H%M%S)"
REMOTE_BACKUP="${REMOTE_CORE}.bak.${BACKUP_SUFFIX}"
ACTIVATED=0
SERVICE_STOPPED=0
PRESERVE_REMOTE_TMP=0

cleanup_local() {
  rm -rf "$LOCAL_TMP_DIR"
}

run_ssh() {
  if [ -n "$PORT" ]; then
    "$SSH_BIN" -p "$PORT" "$HOST" "$@"
  else
    "$SSH_BIN" "$HOST" "$@"
  fi
}

run_scp() {
  if [ -n "$PORT" ]; then
    "$SCP_BIN" -P "$PORT" "$@"
  else
    "$SCP_BIN" "$@"
  fi
}

rollback_live() {
  if [ "$ACTIVATED" -eq 1 ] && [ "$ROLLBACK" -eq 1 ]; then
    echo "rollback=starting"
    run_ssh "set -eu; if [ -f '$REMOTE_BACKUP' ]; then mv '$REMOTE_BACKUP' '$REMOTE_CORE'; chmod +x '$REMOTE_CORE'; fi"
    if [ -n "$START_CMD" ]; then
      run_ssh "set -eu; $START_CMD"
      SERVICE_STOPPED=0
    fi
    echo "rollback=done"
  fi
}

restore_service() {
  if [ "$SERVICE_STOPPED" -eq 1 ] && [ -n "$START_CMD" ]; then
    echo "restore_service=starting"
    run_ssh "set -eu; $START_CMD"
    SERVICE_STOPPED=0
  fi
}

cleanup_remote() {
  if [ "$KEEP_REMOTE_TMP" -eq 0 ] && [ "$PRESERVE_REMOTE_TMP" -eq 0 ]; then
    run_ssh "rm -rf '$REMOTE_TMP'" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    rollback_live || true
    restore_service || true
  fi
  cleanup_remote || true
  cleanup_local || true
  exit "$status"
}

trap cleanup EXIT INT TERM

if [ -z "$LIVE_SMOKE_ARGS" ]; then
  if [ -n "$START_CMD" ]; then
    LIVE_SMOKE_ARGS="--running-service"
  else
    LIVE_SMOKE_ARGS="$SMOKE_ARGS"
  fi
fi

cp "$(dirname "$0")/openwrt-device-smoke.sh" "$LOCAL_SMOKE_SCRIPT"
chmod +x "$LOCAL_SMOKE_SCRIPT"

if [ -n "$PACKAGE" ]; then
  gzip -dc "$PACKAGE" > "$LOCAL_CORE"
else
  cp "$CORE" "$LOCAL_CORE"
fi
chmod +x "$LOCAL_CORE"

echo "host=$HOST"
echo "remote_core=$REMOTE_CORE"
echo "remote_config=$REMOTE_CONFIG"
echo "remote_tmp=$REMOTE_TMP"
echo "activate=$ACTIVATE"
echo "remote_smoke=$RUN_REMOTE_SMOKE"

run_ssh "set -eu; mkdir -p '$REMOTE_TMP' '$(dirname "$REMOTE_CORE")'"
run_scp "$LOCAL_CORE" "$HOST:$REMOTE_CANDIDATE"
run_scp "$LOCAL_SMOKE_SCRIPT" "$HOST:$REMOTE_SMOKE_SCRIPT"
run_ssh "set -eu; chmod +x '$REMOTE_CANDIDATE' '$REMOTE_SMOKE_SCRIPT'"

echo "candidate_version_check=starting"
run_ssh "set -eu; '$REMOTE_CANDIDATE' -v"

echo "candidate_config_test=starting"
run_ssh "set -eu; '$REMOTE_CANDIDATE' -t -f '$REMOTE_CONFIG'"

if [ "$RUN_REMOTE_SMOKE" -eq 1 ]; then
  if [ -n "$STOP_CMD" ]; then
    echo "stop_cmd=starting"
    run_ssh "set -eu; $STOP_CMD"
    SERVICE_STOPPED=1
  fi
  echo "candidate_smoke=starting"
  if [ -n "$SMOKE_ARGS" ]; then
    run_ssh "set -eu; sh '$REMOTE_SMOKE_SCRIPT' --core '$REMOTE_CANDIDATE' --config '$REMOTE_CONFIG' $SMOKE_ARGS"
  else
    run_ssh "set -eu; sh '$REMOTE_SMOKE_SCRIPT' --core '$REMOTE_CANDIDATE' --config '$REMOTE_CONFIG'"
  fi
fi

if [ "$ACTIVATE" -eq 0 ]; then
  restore_service
  PRESERVE_REMOTE_TMP=1
  echo "candidate_ready=yes"
  echo "candidate_path=$REMOTE_CANDIDATE"
  exit 0
fi

if [ "$BACKUP" -eq 1 ]; then
  echo "backup_path=$REMOTE_BACKUP"
  run_ssh "set -eu; if [ -f '$REMOTE_CORE' ]; then cp '$REMOTE_CORE' '$REMOTE_BACKUP'; chmod +x '$REMOTE_BACKUP'; fi"
fi

echo "activate=starting"
run_ssh "set -eu; mv '$REMOTE_CANDIDATE' '$REMOTE_CORE'; chmod +x '$REMOTE_CORE'"
ACTIVATED=1

if [ -n "$START_CMD" ]; then
  echo "start_cmd=starting"
  run_ssh "set -eu; $START_CMD"
  SERVICE_STOPPED=0
fi

if [ "$RUN_REMOTE_SMOKE" -eq 1 ]; then
  echo "live_smoke=starting"
  if [ -n "$LIVE_SMOKE_ARGS" ]; then
    run_ssh "set -eu; sh '$REMOTE_SMOKE_SCRIPT' --core '$REMOTE_CORE' --config '$REMOTE_CONFIG' $LIVE_SMOKE_ARGS"
  else
    run_ssh "set -eu; sh '$REMOTE_SMOKE_SCRIPT' --core '$REMOTE_CORE' --config '$REMOTE_CONFIG'"
  fi
fi

echo "deploy_status=ok"
echo "live_core=$REMOTE_CORE"
if [ "$BACKUP" -eq 1 ]; then
  echo "live_backup=$REMOTE_BACKUP"
fi
