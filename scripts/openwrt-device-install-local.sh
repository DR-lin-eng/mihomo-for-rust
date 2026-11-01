#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: openwrt-device-install-local.sh --core PATH [options]

Run this script on the OpenWrt device. Put the new Clash.Core and
openwrt-device-smoke.sh on the device first, then execute this script locally.

Required:
  --core PATH                 candidate core path already on the device

Options:
  --remote-core PATH          live core path
  --config PATH               live config path
  --smoke-script PATH         local smoke script path on the device
  --stop-cmd CMD              command to stop the existing service
  --start-cmd CMD             command to start the service after activation
  --smoke-args STRING         candidate smoke args
  --live-smoke-args STRING    live-core smoke args after activation
  --no-backup                 skip live core backup before activation
  --no-rollback               skip rollback when post-activation checks fail
  --skip-smoke                skip candidate and live smoke
  --help                      show this help

Defaults:
  remote-core   /data/kano_plugins/clash/Proxy/Clash.Core
  config        /data/kano_plugins/clash/Proxy/config.yaml
  smoke-script  ./openwrt-device-smoke.sh
  stop-cmd      /data/kano_plugins/clash/Proxy/Clash.Service stop
  start-cmd     /data/kano_plugins/clash/Proxy/Clash.Service start
  smoke-args    --start
  live-smoke    --running-service
EOF
}

CORE=""
REMOTE_CORE="/data/kano_plugins/clash/Proxy/Clash.Core"
CONFIG="/data/kano_plugins/clash/Proxy/config.yaml"
SMOKE_SCRIPT="./openwrt-device-smoke.sh"
STOP_CMD="/data/kano_plugins/clash/Proxy/Clash.Service stop"
START_CMD="/data/kano_plugins/clash/Proxy/Clash.Service start"
SMOKE_ARGS="--start"
LIVE_SMOKE_ARGS="--running-service"
BACKUP=1
ROLLBACK=1
RUN_SMOKE=1
BACKUP_PATH=""
ACTIVATED=0
SERVICE_STOPPED=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --core) CORE="${2-}"; shift 2 ;;
    --remote-core) REMOTE_CORE="${2-}"; shift 2 ;;
    --config) CONFIG="${2-}"; shift 2 ;;
    --smoke-script) SMOKE_SCRIPT="${2-}"; shift 2 ;;
    --stop-cmd) STOP_CMD="${2-}"; shift 2 ;;
    --start-cmd) START_CMD="${2-}"; shift 2 ;;
    --smoke-args) SMOKE_ARGS="${2-}"; shift 2 ;;
    --live-smoke-args) LIVE_SMOKE_ARGS="${2-}"; shift 2 ;;
    --no-backup) BACKUP=0; shift ;;
    --no-rollback) ROLLBACK=0; shift ;;
    --skip-smoke) RUN_SMOKE=0; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$CORE" ] || { echo "missing --core" >&2; usage >&2; exit 2; }
[ -f "$CORE" ] || { echo "candidate core not found: $CORE" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "config not found: $CONFIG" >&2; exit 1; }
[ "$RUN_SMOKE" -eq 0 ] || [ -f "$SMOKE_SCRIPT" ] || { echo "smoke script not found: $SMOKE_SCRIPT" >&2; exit 1; }
[ -z "$STOP_CMD" ] || [ -n "$START_CMD" ] || {
  echo "--stop-cmd requires --start-cmd so the service can be restored safely" >&2
  exit 2
}

restore_service() {
  if [ "$SERVICE_STOPPED" -eq 1 ] && [ -n "$START_CMD" ]; then
    echo "restore_service=starting"
    sh -c "$START_CMD" || true
    SERVICE_STOPPED=0
  fi
}

rollback_live() {
  if [ "$ACTIVATED" -eq 1 ] && [ "$ROLLBACK" -eq 1 ] && [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
    echo "rollback=starting"
    mv "$BACKUP_PATH" "$REMOTE_CORE"
    chmod +x "$REMOTE_CORE"
    if [ -n "$START_CMD" ]; then
      sh -c "$START_CMD" || true
      SERVICE_STOPPED=0
    fi
    echo "rollback=done"
  fi
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    rollback_live
    restore_service
  fi
  exit "$status"
}

trap cleanup EXIT INT TERM

chmod +x "$CORE"
[ "$RUN_SMOKE" -eq 0 ] || chmod +x "$SMOKE_SCRIPT"

echo "candidate_core=$CORE"
echo "remote_core=$REMOTE_CORE"
echo "config=$CONFIG"
echo "smoke=$RUN_SMOKE"

echo "candidate_version_check=starting"
"$CORE" -v

echo "candidate_config_test=starting"
"$CORE" -t -f "$CONFIG"

if [ "$RUN_SMOKE" -eq 1 ]; then
  if [ -n "$STOP_CMD" ]; then
    echo "stop_cmd=starting"
    sh -c "$STOP_CMD"
    SERVICE_STOPPED=1
  fi
  echo "candidate_smoke=starting"
  sh "$SMOKE_SCRIPT" --core "$CORE" --config "$CONFIG" $SMOKE_ARGS
fi

if [ "$BACKUP" -eq 1 ] && [ -f "$REMOTE_CORE" ]; then
  BACKUP_PATH="${REMOTE_CORE}.bak.$(date +%Y%m%d%H%M%S)"
  echo "backup_path=$BACKUP_PATH"
  cp "$REMOTE_CORE" "$BACKUP_PATH"
  chmod +x "$BACKUP_PATH"
fi

echo "activate=starting"
cp "$CORE" "$REMOTE_CORE"
chmod +x "$REMOTE_CORE"
ACTIVATED=1

if [ -n "$START_CMD" ]; then
  echo "start_cmd=starting"
  sh -c "$START_CMD"
  SERVICE_STOPPED=0
fi

if [ "$RUN_SMOKE" -eq 1 ]; then
  echo "live_smoke=starting"
  sh "$SMOKE_SCRIPT" --core "$REMOTE_CORE" --config "$CONFIG" $LIVE_SMOKE_ARGS
fi

echo "install_status=ok"
echo "live_core=$REMOTE_CORE"
[ -z "$BACKUP_PATH" ] || echo "live_backup=$BACKUP_PATH"
