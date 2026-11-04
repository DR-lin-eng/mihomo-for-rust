#!/usr/bin/env python3
"""Run each route ownership case with unshare --net and a synthetic config."""
import argparse
import hashlib
import http.client
import json
import os
import pathlib
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--core', required=True)
parser.add_argument('--case', choices=['crash', 'concurrent', 'foreign-rule', 'startup-failure', 'many-filters', 'interrupted-startup'], required=True)
args = parser.parse_args()
root = pathlib.Path('/results') / ('routes-' + args.case)
root.mkdir(exist_ok=True)
children = []
checks = []


def command(*values, required=True):
    response = subprocess.run(values, capture_output=True, text=True, timeout=10)
    if required and response.returncode:
        raise RuntimeError((values, response.stderr))
    return response.stdout


def check(name, passed, detail=None):
    checks.append(dict(name=name, passed=bool(passed), detail=detail))
    print('PASS' if passed else 'FAIL', name, flush=True)


def snapshot():
    return dict(rules=json.loads(command('ip', '-j', 'rule', 'show')),
                routes=json.loads(command('ip', '-j', 'route', 'show', 'table', '2022')))


def tagged(rows, protocol):
    return [row for row in rows if str(row.get('protocol')) == str(protocol)]


def ready(process):
    for _ in range(100):
        if process.poll() is not None:
            return False
        try:
            connection = http.client.HTTPConnection('127.0.0.1', 19091, timeout=.2)
            connection.request('GET', '/ebpf')
            response = connection.getresponse()
            state = json.loads(response.read())
            connection.close()
            if state.get('direct_offload', {}).get('running'):
                return True
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.05)
    return False


def start(text, name):
    config = root / (name + '.yaml')
    config.write_text(text)
    log = (root / (name + '.log')).open('w')
    child = subprocess.Popen([args.core, '-d', str(root), '-f', str(config)], stdout=log, stderr=log)
    children.append(child)
    return child


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(8)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


try:
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'add', 'ar-lan', 'type', 'veth', 'peer', 'name', 'ar-peer')
    for device, address in [('ar-lan', '192.0.2.1/24'), ('ar-peer', '192.0.2.2/24')]:
        command('ip', 'addr', 'add', address, 'dev', device)
        command('ip', 'link', 'set', device, 'up')
    command('ip', 'route', 'add', 'default', 'via', '192.0.2.2', 'dev', 'ar-lan')
    pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    command('ip', 'rule', 'add', 'priority', '9999', 'from', '198.51.100.0/24', 'lookup', 'main', 'protocol', '99')
    command('ip', 'route', 'add', 'table', '2022', '203.0.113.0/24', 'dev', 'ar-lan', 'protocol', '99')
    if args.case == 'foreign-rule':
        command('ip', 'rule', 'add', 'priority', '9000', 'to', '203.0.113.0/24', 'lookup', 'main', 'protocol', '99')
    foreign = snapshot()
    config = '''allow-lan: true
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
'''
    if args.case == 'many-filters':
        ids = ', '.join(str(1000 + index * 2) for index in range(24))
        config = config.replace('  auto-route: true', '  auto-route: true\n  include-uid: [' + ids + ']')
    if args.case == 'startup-failure':
        failed = start(config.replace('[ar-lan]', '[missing-lan]'), 'failed')
        failed.wait(10)
        check('invalid BPF interface rejects startup', failed.returncode != 0)
        state = snapshot()
        check('startup failure rolls back owned rules', not tagged(state['rules'], 242), state)
        check('startup failure rolls back owned routes', not tagged(state['routes'], 242), state)
    if args.case == 'interrupted-startup':
        for index, delay in enumerate((0, .003, .01, .03, .06, .12)):
            interrupted = start(config, 'interrupted-' + str(index))
            time.sleep(delay)
            if interrupted.poll() is None:
                interrupted.kill()
                interrupted.wait(5)
            restored = start(config, 'restored-' + str(index))
            check(f'startup interrupted after {delay}s recovers', ready(restored))
            stop(restored)
    elif args.case == 'foreign-rule':
        primary = start(config, 'primary')
        primary.wait(10)
        check('conflicting foreign priority rejects startup', primary.returncode != 0)
    else:
        primary = start(config, 'primary')
        check('primary core starts', ready(primary))
        if primary.poll() is not None:
            raise RuntimeError((root / 'primary.log').read_text())
        state = snapshot()
        check('owned routes and rules carry protocol 242', bool(tagged(state['rules'], 242)) and bool(tagged(state['routes'], 242)), state)
        if args.case == 'concurrent':
            second = start(config.replace('ar-tun', 'ar-second').replace(':19091', ':19092'), 'second')
            second.wait(10)
            check('second owner cannot take the active routing table', second.returncode != 0)
            check('primary still works after second owner is rejected', ready(primary))
        if args.case == 'crash':
            namespace = os.stat('/proc/self/ns/net').st_ino
            journal = pathlib.Path(f'/tmp/mihomo-tun-routes-{namespace}-2022.json')
            check('active routes have a recovery journal', journal.exists())
            primary.kill()
            primary.wait(5)
            check('SIGKILL leaves the recovery journal', journal.exists())
            primary = start(config, 'restarted')
            check('same configuration restarts after SIGKILL', ready(primary))
        stop(primary)
    state = snapshot()
    check('normal cleanup preserves foreign rules', tagged(state['rules'], 99) == tagged(foreign['rules'], 99), state)
    check('normal cleanup preserves foreign routes', tagged(state['routes'], 99) == tagged(foreign['routes'], 99), state)
    check('owned rules are removed', not tagged(state['rules'], 242), state)
    check('owned routes are removed', not tagged(state['routes'], 242), state)
except Exception as error:
    check('route ownership execution', False, repr(error))
finally:
    for child in children:
        stop(child)
    result = dict(passed=all(row['passed'] for row in checks), case=args.case, checks=checks,
                  core_sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    (pathlib.Path('/results') / ('routes-' + args.case + '.json')).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(dict(passed=result['passed'], checks=len(checks))), flush=True)
raise SystemExit(not result['passed'])
