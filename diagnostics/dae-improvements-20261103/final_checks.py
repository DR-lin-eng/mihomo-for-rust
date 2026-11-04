#!/usr/bin/env python3
"""Complete the runtime gate, trace actual syscalls, then measure performance."""
import json
import pathlib
import subprocess

root = pathlib.Path('/results')


def run(name, command):
    print('START', name, flush=True)
    with (root / (name + '.log')).open('w') as log:
        subprocess.run(command, stdout=log, stderr=log, check=True)
    print('DONE', name, flush=True)


run('domain-retry', ['python3', '/results/validate.py', '--only', 'domain'])
assert all(row['passed'] for row in json.loads((root / 'validation-status.json').read_text()))
traces = {}
for label, core in (
    ('before', '/repo/bin/mihomo-rust-openwrt-arm64-kernel-direct'),
    ('after', '/results/mihomo-after'),
):
    path = root / ('syscalls-' + label + '.json')
    run('trace-' + label, ['python3', '/results/compare.py', '--rust', core,
        '--seconds', '0', '--repeats', '1', '--modes', 'rust-redir-socks',
        '--trace-syscalls', '--skip-behavior', '--work-suffix', 'trace-' + label,
        '--output', str(path)])
    result = json.loads(path.read_text())
    mode = result['modes'][0]
    assert mode['completed'] and mode['functional']['path_verified']
    traces[label] = mode['syscalls']
    # ptrace attach/detach interrupts blocking syscalls in the old core's DNS
    # listener. Use a fresh process for behavior; tracing is an independent
    # experiment and must not influence the before/after DNS comparison.
    behavior_path = root / ('baseline-behavior-' + label + '.json')
    run('baseline-behavior-' + label, ['python3', '/results/compare.py', '--rust', core,
        '--seconds', '0', '--repeats', '1', '--modes', 'rust-redir-socks',
        '--work-suffix', 'clean-' + label, '--output', str(behavior_path)])
    behavior = json.loads(behavior_path.read_text())['modes'][0]
    assert behavior['completed'] and behavior['functional']['path_verified']
    traces[label]['dns'] = behavior['dns']
    traces[label]['reload'] = behavior['reload']
assert traces['before']['calls'].get('splice', 0) == 0
assert traces['after']['calls'].get('splice', 0) > 0
assert traces['before']['dns']['burst_upstream_requests'] == 16
assert traces['after']['dns']['burst_upstream_requests'] == 1
assert not traces['before']['reload']['existing_tcp_preserved']
assert traces['after']['reload']['existing_tcp_preserved']
(root / 'syscalls-summary.json').write_text(json.dumps(traces, indent=2) + '\n')
run('performance', ['python3', '/results/performance.py'])
