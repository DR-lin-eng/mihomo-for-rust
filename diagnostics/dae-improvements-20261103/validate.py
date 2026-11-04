#!/usr/bin/env python3
"""Run serial runtime checks after the Docker cargo tests have finished."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--core', default='/results/mihomo-after')
parser.add_argument('--only', nargs='*')
args = parser.parse_args()
root = pathlib.Path('/results')
core = args.core
core_hash = hashlib.sha256(pathlib.Path(core).read_bytes()).hexdigest()
previous_manifest = root / 'validation.json'
if args.only and previous_manifest.exists():
    previous = json.loads(previous_manifest.read_text())
    if previous.get('core_sha256') != core_hash:
        print('Core binary changed; run every runtime check for the new hash.', flush=True)
        args.only = None
inside = ['unshare', '--net', 'python3', '/results/netns_exec.py']
specs = [('behavior', ['python3', '/results/behavior.py', '--core', core], 'behavior.json')]
for case in ('crash', 'concurrent', 'foreign-rule', 'startup-failure', 'many-filters', 'interrupted-startup'):
    specs.append(('routes-' + case, inside + ['python3', '/results/route_checks.py', '--core', core, '--case', case], 'routes-' + case + '.json'))
for name, script, extra in (
    ('kernel', 'kernel-direct-smoke.py', ['--lifecycle', '--auto-route', '--masquerade']),
    ('domain', 'domain-routing-smoke.py', []),
    ('traffic-mixed', 'traffic-speed-smoke.py', ['--inbound', 'mixed', '--outbound', 'direct']),
    ('traffic-redir', 'traffic-speed-smoke.py', ['--inbound', 'redir', '--outbound', 'socks5']),
    ('tls-tun', 'tun-https-smoke.py', ['--inbound', 'tun', '--outbound', 'socks5', '--drop-first-reply']),
    ('smart', 'smart-smoke.py', ['--model', '/results/Model.bin']),
):
    specs.append((name, inside + ['python3', '/repo/scripts/' + script, '--core', core,
        '--output', '/results/' + name + '.json'] + extra, name + '.json'))
for name, script, object_name in (
    ('direct-packets', 'kernel-direct-packet-tests.py', 'direct.bpfel.o'),
    ('legacy-packets', 'ebpf-packet-tests.py', 'mihomo.bpfel.o'),
):
    specs.append((name, inside + ['python3', '/repo/scripts/' + script,
        '--object', '/repo/rust/crates/mihomo-ebpf/bpf/' + object_name,
        '--output', '/results/' + name + '.json'], name + '.json'))
status_path = root / 'validation-status.json'
status = json.loads(status_path.read_text()) if args.only and status_path.exists() else []
for name, command, result_file in specs:
    if args.only and name not in args.only:
        continue
    print('START', name, flush=True)
    started = time.monotonic()
    try:
        with (root / (name + '.log')).open('w') as log:
            process = subprocess.run(command, stdout=log, stderr=log, timeout=240)
        result = json.loads((root / result_file).read_text()) if (root / result_file).exists() else {}
        checks = result.get('checks', [])
        passed = process.returncode == 0 and bool(checks) and all(row['passed'] for row in checks)
        row = dict(name=name, returncode=process.returncode, passed=passed,
                   passed_checks=sum(check['passed'] for check in checks), checks=len(checks),
                   seconds=time.monotonic() - started, core_sha256=core_hash)
    except Exception as error:
        row = dict(name=name, passed=False, error=repr(error), seconds=time.monotonic() - started)
    status = [old for old in status if old['name'] != name] + [row]
    status_path.write_text(json.dumps(status, indent=2) + '\n')
    print('DONE', json.dumps(row), flush=True)
manifest = dict(core=core, core_sha256=core_hash, status=status)
(root / 'validation.json').write_text(json.dumps(manifest, indent=2) + '\n')
raise SystemExit(any(not row['passed'] for row in status))
