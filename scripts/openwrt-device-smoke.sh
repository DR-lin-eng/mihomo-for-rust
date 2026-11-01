#!/bin/sh

set -eu

usage() {
  cat <<'EOF'
usage: openwrt-device-smoke.sh --core /path/to/Clash.Core --config /path/to/config.yaml [options]

Required:
  --core PATH
  --config PATH

Optional:
  --controller HOST:PORT
  --secret VALUE
  --mixed-port PORT
  --redir-port PORT
  --tproxy-port PORT
  --start
  --running-service
  --keep-running
  --http-url URL
  --timeout SEC
  --help
EOF
}

CORE=""
CONFIG=""
CONTROLLER=""
SECRET=""
MIXED_PORT=""
REDIR_PORT=""
TPROXY_PORT=""
START_CORE=0
RUNNING_SERVICE=0
KEEP_RUNNING=0
HTTP_URL="http://www.gstatic.com/generate_204"
TIMEOUT_SEC=30
STARTED_PID=""

cleanup() {
  if [ "$KEEP_RUNNING" -eq 0 ] && [ -n "$STARTED_PID" ]; then
    kill "$STARTED_PID" >/dev/null 2>&1 || true
    wait "$STARTED_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --core) CORE="${2-}"; shift 2 ;;
    --config) CONFIG="${2-}"; shift 2 ;;
    --controller) CONTROLLER="${2-}"; shift 2 ;;
    --secret) SECRET="${2-}"; shift 2 ;;
    --mixed-port) MIXED_PORT="${2-}"; shift 2 ;;
    --redir-port) REDIR_PORT="${2-}"; shift 2 ;;
    --tproxy-port) TPROXY_PORT="${2-}"; shift 2 ;;
    --start) START_CORE=1; shift ;;
    --running-service) RUNNING_SERVICE=1; shift ;;
    --keep-running) KEEP_RUNNING=1; shift ;;
    --http-url) HTTP_URL="${2-}"; shift 2 ;;
    --timeout) TIMEOUT_SEC="${2-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$CORE" ] || { echo "missing --core" >&2; usage >&2; exit 2; }
[ -n "$CONFIG" ] || { echo "missing --config" >&2; usage >&2; exit 2; }
[ -f "$CORE" ] || { echo "core not found: $CORE" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "config not found: $CONFIG" >&2; exit 1; }
[ "$START_CORE" -eq 0 ] || [ "$RUNNING_SERVICE" -eq 0 ] || {
  echo "use either --start or --running-service, not both" >&2
  exit 2
}

config_value() {
  key="$1"
  awk -v key="$key" '
    $0 ~ ("^" key ":") {
      line=$0
      sub(/^[^:]+:[[:space:]]*/, "", line)
      gsub(/"/, "", line)
      sub(/[[:space:]]*#.*/, "", line)
      print line
      exit
    }
  ' "$CONFIG"
}

tun_enabled_from_config() {
  awk '
    BEGIN { in_tun = 0 }
    /^tun:/ { in_tun = 1; next }
    in_tun && /^[^[:space:]]/ { in_tun = 0 }
    in_tun && /^  enable:/ {
      line = $0
      sub(/^[^:]+:[[:space:]]*/, "", line)
      gsub(/"/, "", line)
      sub(/[[:space:]]*#.*/, "", line)
      print line
      exit
    }
  ' "$CONFIG"
}

[ -n "$CONTROLLER" ] || CONTROLLER="$(config_value "external-controller")"
[ -n "$SECRET" ] || SECRET="$(config_value "secret")"
[ -n "$MIXED_PORT" ] || MIXED_PORT="$(config_value "mixed-port")"
[ -n "$REDIR_PORT" ] || REDIR_PORT="$(config_value "redir-port")"
[ -n "$TPROXY_PORT" ] || TPROXY_PORT="$(config_value "tproxy-port")"
TUN_ENABLED="$(tun_enabled_from_config)"

echo "core=$CORE"
echo "config=$CONFIG"
echo "external-controller=${CONTROLLER:-<missing>}"
echo "secret_present=$( [ -n "$SECRET" ] && echo yes || echo no )"
echo "mixed-port=${MIXED_PORT:-<missing>}"
echo "redir-port=${REDIR_PORT:-<missing>}"
echo "tproxy-port=${TPROXY_PORT:-<missing>}"
echo "tun.enable=${TUN_ENABLED:-<unset>}"

echo "version_check:"
"$CORE" -v

echo "config_test:"
"$CORE" -t -f "$CONFIG"

if [ "$TUN_ENABLED" = "true" ]; then
  [ -c /dev/net/tun ] || { echo "tun_device=missing (/dev/net/tun)" >&2; exit 1; }
  echo "tun_device=ok"
fi

controller_host=""
controller_port=""
if [ -n "$CONTROLLER" ]; then
  controller_host="${CONTROLLER%:*}"
  controller_port="${CONTROLLER##*:}"
fi

wait_for_listeners() {
  listener_ready=0
  deadline=$(( $(date +%s) + TIMEOUT_SEC ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ "$START_CORE" -eq 1 ] && ! kill -0 "$STARTED_PID" 2>/dev/null; then
      echo "core exited before listeners became ready" >&2
      tail -n 50 "$LOG_FILE" >&2 || true
      exit 1
    fi
    if command -v ss >/dev/null 2>&1; then
      listeners="$(ss -lntup 2>/dev/null || true)"
    else
      listeners="$(netstat -lntup 2>/dev/null || true)"
    fi
    ready=1
    if [ -n "$MIXED_PORT" ] && ! echo "$listeners" | grep -q ":$MIXED_PORT\\b"; then
      ready=0
    fi
    if [ -n "$controller_port" ] && ! echo "$listeners" | grep -q ":$controller_port\\b"; then
      ready=0
    fi
    if [ "$ready" -eq 1 ]; then
      listener_ready=1
      break
    fi
    sleep 1
  done

  [ "$listener_ready" -eq 1 ] || {
    echo "listener check failed" >&2
    if [ "$START_CORE" -eq 1 ]; then
      tail -n 50 "$LOG_FILE" >&2 || true
    fi
    exit 1
  }
}

proxy_code_ok() {
  case "$1" in
    2??|3??|403) return 0 ;;
    *) return 1 ;;
  esac
}

traffic_url() {
  case "$controller_host" in
    0.0.0.0|"[::]"|"::") connect_host="127.0.0.1" ;;
    *) connect_host="$controller_host" ;;
  esac
  echo "http://$connect_host:$controller_port/traffic"
}

read_traffic_snapshot() {
  curl -m 10 -s -H "Authorization: Bearer $SECRET" "$(traffic_url)" | sed -n '1p' || true
}

probe_proxy_and_controller() {
  echo "listeners_ready=ok"

  traffic_before=""
  traffic_after=""
  if [ -n "$controller_host" ] && [ -n "$controller_port" ] && [ -n "$SECRET" ] && command -v curl >/dev/null 2>&1; then
    traffic_before="$(read_traffic_snapshot)"
  fi

  if [ -n "$MIXED_PORT" ] && command -v curl >/dev/null 2>&1; then
    http_code="$(curl -x "http://127.0.0.1:$MIXED_PORT" -m 20 -s -o /dev/null -w '%{http_code}' "$HTTP_URL" || true)"
    socks_code="$(curl --socks5-hostname "127.0.0.1:$MIXED_PORT" -m 20 -s -o /dev/null -w '%{http_code}' "$HTTP_URL" || true)"
    echo "proxy_http_code=${http_code:-<empty>}"
    echo "proxy_socks5_code=${socks_code:-<empty>}"
    proxy_code_ok "$http_code" || { echo "proxy_http_probe=failed" >&2; return 1; }
    proxy_code_ok "$socks_code" || { echo "proxy_socks5_probe=failed" >&2; return 1; }
  fi

  if [ -n "$controller_host" ] && [ -n "$controller_port" ] && [ -n "$SECRET" ] && command -v curl >/dev/null 2>&1; then
    for _ in 1 2 3 4 5; do
      traffic_after="$(read_traffic_snapshot)"
      if [ -z "$traffic_before" ] || { [ -n "$traffic_after" ] && [ "$traffic_after" != "$traffic_before" ]; }; then
        break
      fi
      sleep 1
    done
    echo "traffic_before=${traffic_before:-<unavailable>}"
    echo "traffic_after=${traffic_after:-<unavailable>}"
    [ -n "$traffic_after" ] || {
      echo "traffic_probe=unavailable" >&2
      return 1
    }
    if [ -n "$traffic_before" ] && [ -n "$traffic_after" ] && [ "$traffic_after" = "$traffic_before" ]; then
      echo "traffic_probe=failed" >&2
      return 1
    fi
  fi
}

if [ "$RUNNING_SERVICE" -eq 1 ]; then
  wait_for_listeners
  probe_proxy_and_controller
  echo "running_service_probe=ok"
  exit 0
fi

if [ "$START_CORE" -eq 0 ]; then
  echo "preflight_only=ok"
  exit 0
fi

LOG_FILE="$(mktemp /tmp/mihomo-openwrt-device-smoke.XXXXXX)"
echo "log_file=$LOG_FILE"
"$CORE" -f "$CONFIG" >"$LOG_FILE" 2>&1 &
STARTED_PID="$!"
echo "started_pid=$STARTED_PID"

wait_for_listeners
probe_proxy_and_controller

tail -n 20 "$LOG_FILE" || true
echo "device_smoke=ok"
