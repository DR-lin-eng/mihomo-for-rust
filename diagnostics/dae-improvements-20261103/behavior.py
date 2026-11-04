#!/usr/bin/env python3
"""Verify policy reload and DNS wire semantics through real LAN connections."""
import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import socket
import struct
import threading

import compare as bench

parser = argparse.ArgumentParser()
parser.add_argument('--core', required=True)
args = parser.parse_args()
bench.A.rust = args.core
root = pathlib.Path('/results')
checks = []


def check(name, passed, detail=None):
    checks.append(dict(name=name, passed=bool(passed), detail=detail))
    print('PASS' if passed else 'FAIL', name, flush=True)


def echo(sock, payload):
    sock.sendall(payload)
    return bench.receive(sock, len(payload)) == payload


def record_for(sock):
    port = str(sock.getsockname()[1])
    return next((row for row in bench.api('/connections')['connections']
                 if row['metadata']['sourcePort'] == port), None)


def burst_wire_queries(mode):
    name = mode + '-wire.test'
    question = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0\0\1\0\1'
    barrier = threading.Barrier(16)

    def query(index):
        identity = 0x6000 + index
        dnssec = bool(index % 2)
        packet = struct.pack('!6H', identity, 0x0100, 1, 0, 0, 1) + question
        packet += b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000 if dnssec else 0, 0)
        with bench.network(bench.CLIENT):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with sock:
            sock.settimeout(8)
            barrier.wait(10)
            sock.sendto(packet, ('192.0.2.1', 53))
            reply = sock.recv(4096)
        return struct.unpack('!H', reply[:2])[0] == identity and reply[-4:] == socket.inet_aton('203.0.113.30')

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        replies = list(pool.map(query, range(16)))
    count = json.loads((root / 'dns-counts.json').read_text()).get(name, 0)
    check(mode + ': transaction IDs survive shared DNS responses', all(replies))
    check(mode + ': different EDNS DO bits use separate upstream queries', count == 2, count)


try:
    bench.setup()
    for mode in ('rust-direct', 'rust-tun-direct', 'rust-tun-socks', 'rust-redir-socks'):
        print('START', mode, flush=True)
        work = root / (mode + '-behavior')
        work.mkdir(exist_ok=True)
        try:
            bench.start_core(mode, work)
            original = bench.config(mode)
            before_programs = bench.api('/ebpf').get('direct_offload', {}).get('program_ids')
            with bench.connection(18080) as old:
                check(mode + ': original TCP works', echo(old, b'before-policy'))
                before = record_for(old)
                replacement = original.split('proxies:\n')[0] if 'proxies:\n' in original else original.split('rules:')[0]
                replacement += "proxies:\n  - {name: alternate, type: direct}\nproxy-groups:\n  - {name: choose, type: select, proxies: [alternate, DIRECT]}\nrules: ['MATCH,choose']\n"
                bench.api('/configs?force=true', 'PUT', {'payload': replacement})
                group = bench.api('/proxies/choose')
                check(mode + ': new group is visible through the controller', group.get('name') == 'choose', group)
                bench.api('/proxies/choose', 'PUT', {'name': 'alternate'})
                check(mode + ': controller can select a newly added group', bench.api('/proxies/choose').get('now') == 'alternate')
                check(mode + ': old TCP survives removing its outbound definition', echo(old, b'after-new-node'))
                after = record_for(old)
                check(mode + ': connection identity and counters survive reload',
                      before is not None and after is not None and before['id'] == after['id']
                      and after['upload'] > before['upload'], dict(before=before, after=after))
                with bench.connection(18080) as new:
                    check(mode + ': new TCP uses the new registry', echo(new, b'new-outbound'))
                    row = record_for(new)
                    check(mode + ': new chain names the new outbound', row is not None and 'alternate' in row['chains'], row)
                rejected = replacement.replace('MATCH,choose', 'MATCH,REJECT')
                bench.api('/configs?force=true', 'PUT', {'payload': rejected})
                check(mode + ': old TCP survives a new REJECT rule', echo(old, b'after-reject-rule'))
                blocked = False
                try:
                    with bench.connection(18080) as new:
                        new.settimeout(.4)
                        blocked = not echo(new, b'rejected-new-flow')
                except (OSError, EOFError):
                    blocked = True
                check(mode + ': new TCP obeys the REJECT rule', blocked)
                invalid_rejected = False
                try:
                    invalid = replacement.replace('proxies: [alternate, DIRECT]', 'proxies: [missing-outbound]')
                    bench.api('/configs?force=true', 'PUT', {'payload': invalid})
                except RuntimeError:
                    invalid_rejected = True
                check(mode + ': invalid policy is rejected before publication', invalid_rejected)
                check(mode + ': failed reload leaves the existing TCP usable', echo(old, b'after-failed-reload'))
                bench.api('/configs?force=true', 'PUT', {'payload': original})
                check(mode + ': restoring the policy keeps the old TCP', echo(old, b'after-restore'))
            after_programs = bench.api('/ebpf').get('direct_offload', {}).get('program_ids')
            if mode == 'rust-direct':
                check(mode + ': kernel TCP programs stay attached during policy reload', before_programs == after_programs)
            burst_wire_queries(mode)
        except Exception as error:
            check(mode + ': execution', False, repr(error))
        finally:
            bench.stop_core()
    work = root / 'route-provider-behavior'
    work.mkdir(exist_ok=True)
    provider = work / 'cidrs.txt'
    provider.write_text('203.0.113.0/24\n')
    config = bench.config('rust-direct').replace('  auto-route: false',
        '  auto-route: false\n  route-address-set: [cidrs]')
    config += f'\nrule-providers:\n  cidrs:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: {provider}\n'
    try:
        original_config = bench.config
        bench.config = lambda mode: config
        bench.start_core('rust-direct', work)
        before = bench.api('/ebpf')['direct_offload']['program_ids']
        bench.api('/configs?force=true', 'PUT', {'payload': config})
        same = bench.api('/ebpf')['direct_offload']['program_ids']
        check('unchanged TUN route provider permits policy reload', before == same)
        provider.write_text('198.51.100.0/24\n')
        bench.api('/configs?force=true', 'PUT', {'payload': config})
        changed = bench.api('/ebpf')['direct_offload']['program_ids']
        check('changed TUN route provider rebuilds the network plan', not set(before) & set(changed))
        with bench.connection(18080) as sock:
            check('traffic works after rebuilding a changed route provider', echo(sock, b'updated-provider'))
    except Exception as error:
        check('TUN provider dependency execution', False, repr(error))
    finally:
        bench.config = original_config
        bench.stop_core()
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
    result = dict(passed=all(row['passed'] for row in checks), checks=checks,
                  core_sha256=hashlib.sha256(pathlib.Path(args.core).read_bytes()).hexdigest())
    (root / 'behavior.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(dict(passed=result['passed'], checks=len(checks))), flush=True)
raise SystemExit(not result['passed'])
