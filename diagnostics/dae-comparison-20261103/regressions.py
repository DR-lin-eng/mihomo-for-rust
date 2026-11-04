#!/usr/bin/env python3
"""Run existing kernel checks serially after the comparative load finishes."""
import json
import pathlib
import subprocess

root = pathlib.Path('/results')
specs = [
    ('syscalls', ['python3', '/results/compare.py', '--seconds', '0', '--repeats', '1',
      '--modes', 'dae-socks', 'rust-redir-socks', '--trace-syscalls', '--skip-behavior',
      '--work-suffix', 'trace', '--output', '/results/syscall-report.json']),
    ('rust-kernel-regression', ['python3', '/repo/scripts/kernel-direct-smoke.py',
      '--core', '/repo/bin/Clash.Core', '--output', '/results/rust-kernel-regression.json',
      '--lifecycle', '--auto-route', '--masquerade']),
    ('rust-direct-packets', ['python3', '/repo/scripts/kernel-direct-packet-tests.py',
      '--object', '/repo/rust/crates/mihomo-ebpf/bpf/direct.bpfel.o',
      '--output', '/results/rust-direct-packets.json']),
    ('rust-legacy-packets', ['python3', '/repo/scripts/ebpf-packet-tests.py',
      '--object', '/repo/rust/crates/mihomo-ebpf/bpf/mihomo.bpfel.o',
      '--output', '/results/rust-legacy-packets.json']),
]
results = []
for name, command in specs:
    print('START', name, flush=True)
    with (root / (name + '.log')).open('w') as log:
        try:
            process = subprocess.run(command, stdout=log, stderr=log, timeout=240)
            result = dict(name=name, returncode=process.returncode)
        except subprocess.TimeoutExpired:
            result = dict(name=name, returncode=None, error='timeout')
    results.append(result)
    (root / 'regression-status.json').write_text(json.dumps(results, indent=2) + '\n')
    print('DONE', json.dumps(result), flush=True)
raise SystemExit(any(row['returncode'] != 0 for row in results))
