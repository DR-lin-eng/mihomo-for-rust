#!/usr/bin/env python3
"""Minimal crash/restart check in a fresh anonymous network namespace."""
import argparse
import http.client
import json
import pathlib
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--auto-route', choices=['on', 'off'], default='on')
args = parser.parse_args()
root = pathlib.Path('/results/crash-repro-' + args.auto_route)
root.mkdir(exist_ok=True)
core = None
result = {'auto_route': args.auto_route == 'on'}


def command(*args):
    return subprocess.check_output(args, text=True)


def ready(process):
    for _ in range(80):
        if process.poll() is not None:
            return False
        try:
            conn = http.client.HTTPConnection('127.0.0.1', 19091, timeout=.2)
            conn.request('GET', '/ebpf')
            response = conn.getresponse()
            state = json.loads(response.read())
            conn.close()
            if state.get('direct_offload', {}).get('running'):
                return True
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.05)
    return False


try:
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'add', 'ar-lan', 'type', 'veth', 'peer', 'name', 'ar-peer')
    command('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'ar-lan')
    command('ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'ar-peer')
    command('ip', 'link', 'set', 'ar-lan', 'up')
    command('ip', 'link', 'set', 'ar-peer', 'up')
    command('ip', 'route', 'add', 'default', 'via', '192.0.2.2', 'dev', 'ar-lan')
    pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    config = root / 'config.yaml'
    config.write_text('''allow-lan: true
ipv6: false
external-controller: 127.0.0.1:19091
log-level: warning
tun:
  enable: true
  device: ar-tun
  stack: mixed
  auto-route: true
  auto-redirect: false
ebpf:
  direct-offload: [ar-lan]
rules: ['MATCH,DIRECT']
'''.replace('auto-route: true', 'auto-route: ' + str(args.auto_route == 'on').lower()))
    log = (root / 'core.log').open('w')
    core_args = ['/repo/bin/Clash.Core', '-d', str(root), '-f', str(config)]
    core = subprocess.Popen(core_args, stdout=log, stderr=log)
    result['first_start_ready'] = ready(core)
    if not result['first_start_ready']:
        raise RuntimeError('first start failed')
    core.kill()
    core.wait(5)
    time.sleep(.2)
    result['rules_after_sigkill'] = command('ip', 'rule', 'show')
    core = subprocess.Popen(core_args, stdout=log, stderr=log)
    result['restart_ready'] = ready(core)
    result['restart_exit_code'] = core.poll()
    result['rules_after_restart'] = command('ip', 'rule', 'show')
except Exception as exc:
    result['error'] = repr(exc)
finally:
    if core is not None and core.poll() is None:
        core.terminate()
        try:
            core.wait(5)
        except subprocess.TimeoutExpired:
            core.kill()
            core.wait()
    subprocess.run(['ip', 'link', 'del', 'ar-lan'], capture_output=True)
    if 'log' in locals():
        log.close()
    result['core_log'] = (root / 'core.log').read_text() if (root / 'core.log').exists() else ''
    filename = 'auto-route-crash-repro.json' if args.auto_route == 'on' else 'manual-route-crash-repro.json'
    (pathlib.Path('/results') / filename).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result), flush=True)
