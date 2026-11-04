#!/usr/bin/env python3
"""Alternate before/after cores to reduce drift in the synthetic benchmark."""
import argparse
import hashlib
import json
import pathlib

import compare as bench

parser = argparse.ArgumentParser()
parser.add_argument('--before', default='/repo/bin/mihomo-rust-openwrt-arm64-kernel-direct')
parser.add_argument('--after', default='/results/mihomo-after')
parser.add_argument('--seconds', type=int, default=4)
parser.add_argument('--repeats', type=int, default=3)
args = parser.parse_args()
bench.A.seconds = args.seconds
root = pathlib.Path('/results')
report = dict(environment=dict(affinity=sorted(bench.os.sched_getaffinity(0)),
    cpu_max=pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
    kernel=bench.platform.release()), records=[],
    before_sha256=hashlib.sha256(pathlib.Path(args.before).read_bytes()).hexdigest(),
    after_sha256=hashlib.sha256(pathlib.Path(args.after).read_bytes()).hexdigest())


def measure(variant, mode, repeat):
    print('START', variant, mode, repeat, flush=True)
    work = root / 'performance' / f'{variant}-{mode}-{repeat}'
    work.mkdir(parents=True, exist_ok=True)
    try:
        bench.A.rust = args.before if variant == 'before' else args.after
        bench.start_core(mode, work)
        functional = bench.functional(mode)
        if not functional['path_verified'] or not functional['tcp_512k_integrity']:
            raise RuntimeError('forwarding path or payload check failed')
        for parallel, reverse in ((1, True), (8, True), (8, False)):
            row = bench.benchmark(mode, work, parallel, reverse, repeat)
            row.update(variant=variant, mode=mode)
            report['records'].append(row)
            if row['returncode'] or row['error'] or row.get('mbps', 0) <= 0:
                raise RuntimeError(row)
            print(variant, mode, row['name'], round(row['mbps'], 1), 'Mbps', flush=True)
            (root / 'performance.json').write_text(json.dumps(report, indent=2) + '\n')
    finally:
        bench.stop_core()


try:
    bench.setup()
    for mode in ('rust-direct', 'rust-tun-socks', 'rust-redir-socks'):
        for repeat in range(args.repeats):
            variants = ('before', 'after') if repeat % 2 == 0 else ('after', 'before')
            for variant in variants:
                measure(variant, mode, repeat)
    for repeat in range(args.repeats):
        measure('dae', 'dae-socks', repeat)
except Exception as error:
    report['error'] = repr(error)
    raise
finally:
    bench.stop_core()
    for child in bench.CHILDREN:
        child.terminate()
        try:
            child.wait(3)
        except bench.subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    for namespace in (bench.CLIENT, bench.TARGET):
        bench.run('ip', 'netns', 'del', namespace, required=False)
    (root / 'performance.json').write_text(json.dumps(report, indent=2) + '\n')
print('RESULT', len(report['records']), 'throughput rounds', flush=True)
