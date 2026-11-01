#!/bin/sh

set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
TEST_TMP="$(mktemp -d /tmp/mihomo-openwrt-deploy-test.XXXXXX)"
REMOTE_ROOT="$TEST_TMP/remote"
BIN_DIR="$TEST_TMP/bin"
mkdir -p "$REMOTE_ROOT/data/kano_plugins/clash/Proxy" "$REMOTE_ROOT/tmp" "$BIN_DIR"

cleanup() {
  rm -rf "$TEST_TMP"
}

trap cleanup EXIT INT TERM

REMOTE_CORE="$REMOTE_ROOT/data/kano_plugins/clash/Proxy/Clash.Core"
REMOTE_CONFIG="$REMOTE_ROOT/data/kano_plugins/clash/Proxy/config.yaml"
REMOTE_TMP="$REMOTE_ROOT/tmp/mihomo-deploy"
SERVICE_STATE="$REMOTE_ROOT/service.state"

cat >"$REMOTE_CONFIG" <<'EOF'
mixed-port: 7890
external-controller: 127.0.0.1:7788
secret: "123456"
tun:
  enable: false
EOF

cat >"$TEST_TMP/old-core.sh" <<'EOF'
#!/bin/sh
echo old-core
EOF
chmod +x "$TEST_TMP/old-core.sh"
cp "$TEST_TMP/old-core.sh" "$REMOTE_CORE"

cat >"$TEST_TMP/new-core.sh" <<'EOF'
#!/bin/sh
set -eu
if [ "${1-}" = "-v" ]; then
  echo "new-core version"
  exit 0
fi
if [ "${1-}" = "-t" ]; then
  [ "${2-}" = "-f" ] || exit 9
  [ -f "${3-}" ] || exit 10
  echo "config ok"
  exit 0
fi
if [ "${1-}" = "-f" ]; then
  echo "run ${2-}"
  sleep 3600
  exit 0
fi
echo "unsupported args: $*" >&2
exit 11
EOF
chmod +x "$TEST_TMP/new-core.sh"

cat >"$BIN_DIR/fake-ssh" <<'EOF'
#!/bin/sh
set -eu
if [ "${1-}" = "-p" ]; then
  shift 2
fi
host="$1"
shift
cmd="${1-}"
shift || true
while [ "$#" -gt 0 ]; do
  cmd="$cmd $1"
  shift
done
sh -lc "$cmd"
EOF

cat >"$BIN_DIR/fake-scp" <<'EOF'
#!/bin/sh
set -eu
if [ "${1-}" = "-P" ]; then
  shift 2
fi
src="$1"
dest="$2"
case "$dest" in
  *:*) dest="${dest#*:}" ;;
esac
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
EOF
chmod +x "$BIN_DIR/fake-ssh" "$BIN_DIR/fake-scp"

SSH_ENV="SSH_BIN=$BIN_DIR/fake-ssh SCP_BIN=$BIN_DIR/fake-scp"
DEPLOY_SCRIPT="$REPO_ROOT/scripts/openwrt-device-deploy.sh"

echo "test=activate-success"
env $SSH_ENV sh "$DEPLOY_SCRIPT" \
  --host fake-host \
  --core "$TEST_TMP/new-core.sh" \
  --remote-core "$REMOTE_CORE" \
  --remote-config "$REMOTE_CONFIG" \
  --remote-tmp "$REMOTE_TMP" \
  --activate \
  --skip-remote-smoke

grep -q "new-core version" "$REMOTE_CORE"
set -- "$REMOTE_CORE".bak.*
[ -f "$1" ]

echo "test=candidate-retained"
env $SSH_ENV sh "$DEPLOY_SCRIPT" \
  --host fake-host \
  --core "$TEST_TMP/new-core.sh" \
  --remote-core "$REMOTE_CORE" \
  --remote-config "$REMOTE_CONFIG" \
  --remote-tmp "$REMOTE_TMP" \
  --stop-cmd "echo stopped > '$SERVICE_STATE'" \
  --start-cmd "echo started > '$SERVICE_STATE'"

test -f "$REMOTE_TMP/Clash.Core.candidate"
[ "$(cat "$SERVICE_STATE")" = "started" ]

echo "test=reject-stop-without-start"
set +e
env $SSH_ENV sh "$DEPLOY_SCRIPT" \
  --host fake-host \
  --core "$TEST_TMP/new-core.sh" \
  --remote-core "$REMOTE_CORE" \
  --remote-config "$REMOTE_CONFIG" \
  --remote-tmp "$REMOTE_TMP" \
  --stop-cmd "echo stopped > '$SERVICE_STATE'"
status=$?
set -e
[ "$status" -ne 0 ]

echo "test=restore-service-on-candidate-smoke-failure"
echo unknown > "$SERVICE_STATE"
set +e
env $SSH_ENV sh "$DEPLOY_SCRIPT" \
  --host fake-host \
  --core "$TEST_TMP/new-core.sh" \
  --remote-core "$REMOTE_CORE" \
  --remote-config "$REMOTE_CONFIG" \
  --remote-tmp "$REMOTE_TMP" \
  --stop-cmd "echo stopped > '$SERVICE_STATE'" \
  --start-cmd "echo started > '$SERVICE_STATE'" \
  --smoke-args "--running-service"
status=$?
set -e
[ "$status" -ne 0 ]
[ "$(cat "$SERVICE_STATE")" = "started" ]

echo "test=rollback-on-start-failure"
cp "$TEST_TMP/old-core.sh" "$REMOTE_CORE"
set +e
env $SSH_ENV sh "$DEPLOY_SCRIPT" \
  --host fake-host \
  --core "$TEST_TMP/new-core.sh" \
  --remote-core "$REMOTE_CORE" \
  --remote-config "$REMOTE_CONFIG" \
  --remote-tmp "$REMOTE_TMP" \
  --activate \
  --skip-remote-smoke \
  --start-cmd "false"
status=$?
set -e
[ "$status" -ne 0 ]
grep -q "old-core" "$REMOTE_CORE"

echo "local_deploy_test=ok"
