#!/usr/bin/env python3
"""Serial comparisons in one disposable Docker network, with path verification."""
import argparse
import concurrent.futures
import contextlib
import ctypes
import hashlib
import http.client
import json
import os
import pathlib
import platform
import signal
import socket
import statistics
import struct
import subprocess
import threading
import time

P = argparse.ArgumentParser()
P.add_argument('--dae', default='/opt/dae-release/usr/bin/dae')
P.add_argument('--rust', default='/repo/bin/Clash.Core')
P.add_argument('--modes', nargs='+', default=['native', 'dae-direct', 'rust-direct',
               'rust-tun-direct', 'dae-socks', 'rust-tun-socks', 'rust-redir-socks'])
P.add_argument('--seconds', type=int, default=4)
P.add_argument('--repeats', type=int, default=3)
P.add_argument('--output', default='/results/report.json')
P.add_argument('--trace-syscalls', action='store_true')
P.add_argument('--skip-behavior', action='store_true')
P.add_argument('--work-suffix', default='')
A = P.parse_args() if __name__ == "__main__" else P.parse_args([])
ROOT = pathlib.Path('/results')
CLIENT, TARGET, LAN, WAN, TUN = 'cmp-client', 'cmp-target', 'cmp-lan', 'cmp-wan', 'cmp-tun'
HZ = os.sysconf('SC_CLK_TCK')
CORE = None
CHILDREN = []


def run(*args, timeout=15, required=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError(f'{args!r}: {result.stderr or result.stdout}')
    return result


@contextlib.contextmanager
def network(name):
    original = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    new = os.open('/run/netns/' + name, os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if libc.setns(new, 0x40000000):
            raise OSError(ctypes.get_errno(), 'setns')
        yield
    finally:
        libc.setns(original, 0x40000000)
        os.close(original)
        os.close(new)


def connection(port, udp=False):
    with network(CLIENT):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(('203.0.113.30', port))
    return sock


def receive(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError('connection closed')
        data += part
    return data


def api(path, method='GET', body=None):
    conn = http.client.HTTPConnection('127.0.0.1', 19090, timeout=15)
    try:
        conn.request(method, path, None if body is None else json.dumps(body),
                     {'Content-Type': 'application/json'})
        response = conn.getresponse()
        data = response.read()
        if response.status not in (200, 204):
            raise RuntimeError((response.status, data.decode(errors='replace')))
        return json.loads(data) if data else None
    finally:
        conn.close()


def cgroup_cpu():
    values = dict(line.split() for line in pathlib.Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
    return int(values['usage_usec']) / 1e6


def process_stats(pid):
    try:
        raw = pathlib.Path(f'/proc/{pid}/stat').read_text()
        tail = raw[raw.rfind(')') + 2:].split()
        status = {}
        for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith(('VmRSS:', 'VmHWM:', 'Threads:')):
                key, value = line.split(':', 1)
                status[key] = int(value.split()[0])
        status.update(user_seconds=int(tail[11]) / HZ, system_seconds=int(tail[12]) / HZ)
        maps = {}
        for path in pathlib.Path(f'/proc/{pid}/fdinfo').iterdir():
            try:
                fields = dict(line.split(':', 1) for line in path.read_text().splitlines() if ':' in line)
                if 'map_id' in fields and 'memlock' in fields:
                    maps[fields['map_id'].strip()] = int(fields['memlock'].strip())
            except OSError:
                pass
        status['bpf_memlock_bytes'] = sum(maps.values())
        return status
    except (OSError, ValueError):
        return {}


def setup():
    for path in ('/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding'):
        pathlib.Path(path).write_text('1')
    pathlib.Path('/proc/sys/net/ipv4/conf/all/rp_filter').write_text('0')
    for ns, link, local, remote in ((CLIENT, LAN, '192.0.2.1', '192.0.2.2'),
                                   (TARGET, WAN, '203.0.113.1', '203.0.113.30')):
        run('ip', 'netns', 'add', ns)
        run('ip', 'link', 'add', link, 'type', 'veth', 'peer', 'name', link + '-peer')
        run('ip', 'link', 'set', link + '-peer', 'netns', ns)
        run('ip', 'addr', 'add', local + '/24', 'dev', link)
        run('ip', 'link', 'set', link, 'up')
        pathlib.Path(f'/proc/sys/net/ipv4/conf/{link}/rp_filter').write_text('0')
        run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        run('ip', '-n', ns, 'addr', 'add', remote + '/24', 'dev', link + '-peer')
        run('ip', '-n', ns, 'link', 'set', link + '-peer', 'up')
        run('ip', '-n', ns, 'route', 'add', 'default', 'via', local)
    (ROOT / 'dns-answer.txt').write_text('203.0.113.30')
    for name, command in (
        ('fixtures', ['ip', 'netns', 'exec', TARGET, 'python3', '/results/fixtures.py']),
        ('iperf-server', ['ip', 'netns', 'exec', TARGET, 'iperf3', '-s', '-B', '203.0.113.30', '-p', '5201']),
    ):
        log = (ROOT / (name + '.log')).open('w')
        CHILDREN.append(subprocess.Popen(command, stdout=log, stderr=log))
    time.sleep(.4)


def config(mode):
    if mode.startswith('dae'):
        node = "node { 'socks5://203.0.113.30:1080' }\ngroup { bench { policy: fixed(0) } }\n" if mode.endswith('socks') else ''
        return f'''global {{
  lan_interface: {LAN}
  log_level: warn
  disable_waiting_network: true
  auto_config_kernel_parameter: true
  dial_mode: ip
  so_mark_from_dae: 0
  bpf_conn_state_map_size: 4096
  tcp_check_url: 'http://203.0.113.30:18080,203.0.113.30'
  udp_check_dns: '203.0.113.30:53,203.0.113.30'
  check_interval: 1h
}}
{node}dns {{
  optimistic_cache: true
  optimistic_cache_ttl: 3
  upstream {{ local: 'udp://203.0.113.30:53' }}
  routing {{ request {{ fallback: local }} }}
}}
routing {{
  dport(53) -> direct
  fallback: {'bench' if mode.endswith('socks') else 'direct'}
}}
'''
    tun = 'redir' not in mode
    ebpf = f'ebpf:\n  direct-offload: [{LAN}]\n' if mode == 'rust-direct' else f'ebpf:\n  auto-redir: [{LAN}]\n' if not tun else ''
    node = 'proxies:\n  - {name: bench, type: socks5, server: 203.0.113.30, port: 1080, udp: true}\n' if mode.endswith('socks') else ''
    return f'''allow-lan: true
ipv6: false
log-level: warning
external-controller: 127.0.0.1:19090
redir-port: 17892
mode: rule
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: redir-host
  nameserver: [udp://203.0.113.30:53]
tun:
  enable: {str(tun).lower()}
  device: {TUN}
  stack: mixed
  mtu: 1500
  auto-route: false
  auto-redirect: false
  dns-hijack: [any:53]
{ebpf}{node}rules: ['MATCH,{'bench' if mode.endswith('socks') else 'DIRECT'}']
'''


def start_core(mode, work):
    global CORE
    if mode == 'native':
        return
    text = config(mode)
    path = work / ('config.dae' if mode.startswith('dae') else 'config.yaml')
    path.write_text(text)
    path.chmod(0o600)
    log = (work / 'core.log').open('w')
    command = [A.dae, 'run', '-c', str(path)] if mode.startswith('dae') else [A.rust, '-d', str(work), '-f', str(path)]
    CORE = subprocess.Popen(command, stdout=log, stderr=log)
    for _ in range(150):
        if CORE.poll() is not None:
            raise RuntimeError((work / 'core.log').read_text()[-5000:])
        try:
            if mode.startswith('rust'):
                api('/version')
            else:
                # Modern dae attaches TCX links, which do not appear in
                # classic `tc filter show`. A working intercepted DNS query
                # proves the LAN hook and userspace listener are both ready.
                dns_query('ready-' + mode + '.test', timeout=.3)
            break
        except (OSError, RuntimeError, http.client.HTTPException):
            time.sleep(.1)
    else:
        raise TimeoutError('core startup')
    if mode.startswith('rust-tun'):
        run('ip', 'rule', 'add', 'iif', LAN, 'table', '21576', 'priority', '8576')
        run('ip', 'route', 'add', 'table', '21576', 'default', 'dev', TUN)
    time.sleep(.3)


def stop_core():
    global CORE
    if CORE is not None:
        CORE.terminate()
        try:
            CORE.wait(12)
        except subprocess.TimeoutExpired:
            CORE.kill()
            CORE.wait()
        CORE = None
    run('ip', 'rule', 'del', 'iif', LAN, 'table', '21576', 'priority', '8576', required=False)
    run('ip', 'route', 'flush', 'table', '21576', required=False)


def functional(mode):
    with connection(18081) as sock:
        peer = json.loads(sock.recv(256))
    expected = '203.0.113.30' if mode.endswith('socks') else '203.0.113.1' if mode.startswith('rust-tun') else '192.0.2.2'
    payload = bytes(range(256)) * 2048
    with connection(18080) as sock:
        sock.sendall(payload)
        valid = receive(sock, len(payload)) == payload
    result = dict(tcp_512k_integrity=valid, server_observed_peer=peer[0], expected_peer=expected,
                  path_verified=peer[0] == expected)
    latencies = []
    for _ in range(30):
        before = time.perf_counter()
        with connection(18080) as sock:
            sock.sendall(b'ping')
            assert receive(sock, 4) == b'ping'
        latencies.append((time.perf_counter() - before) * 1000)
    result['connect_and_echo_ms'] = dict(median=statistics.median(latencies), p95=sorted(latencies)[28])
    if not mode.endswith('socks'):
        udp = bytes(range(256)) * 4
        with connection(18082, udp=True) as sock:
            sock.send(udp)
            result['udp_integrity'] = sock.recv(65535) == udp
    if mode == 'rust-direct':
        result['ebpf'] = api('/ebpf')
    if CORE:
        result['process'] = process_stats(CORE.pid)
    return result


def benchmark(mode, work, parallel, reverse, repeat):
    name = f'p{parallel}-' + ('download' if reverse else 'upload') + f'-{repeat}'
    command = ['ip', 'netns', 'exec', CLIENT, 'iperf3', '-c', '203.0.113.30', '-p', '5201',
               '-t', str(A.seconds), '-P', str(parallel), '-J'] + (['-R'] if reverse else [])
    samples = []
    done = threading.Event()

    def monitor():
        while not done.wait(.1):
            if CORE:
                samples.append(process_stats(CORE.pid))

    worker = threading.Thread(target=monitor, daemon=True)
    worker.start()
    initial = process_stats(CORE.pid) if CORE else {}
    cpu_initial = cgroup_cpu()
    before = time.monotonic()
    try:
        response = run(*command, timeout=A.seconds + 25, required=False)
    finally:
        done.set()
        worker.join()
    elapsed = time.monotonic() - before
    cpu_final = cgroup_cpu()
    final = process_stats(CORE.pid) if CORE else {}
    (work / (name + '.iperf.json')).write_text(response.stdout)
    data = json.loads(response.stdout)
    result = dict(name=name, repeat=repeat, parallel=parallel, direction='download' if reverse else 'upload',
                  elapsed_seconds=elapsed, returncode=response.returncode, error=data.get('error'))
    if data.get('end', {}).get('sum_received'):
        received = data['end']['sum_received']
        result.update(mbps=received['bits_per_second'] / 1e6, received_bytes=received['bytes'],
                      retransmits=data['end'].get('sum_sent', {}).get('retransmits'))
    core_cpu = sum(final.get(k, 0) - initial.get(k, 0) for k in ('user_seconds', 'system_seconds'))
    result.update(core_cpu_seconds=core_cpu, core_cpu_percent=core_cpu / elapsed * 100,
                  container_cpu_seconds=cpu_final - cpu_initial,
                  container_cpu_percent=(cpu_final - cpu_initial) / elapsed * 100,
                  core_peak_rss_kib=max([s.get('VmRSS', 0) for s in samples] + [final.get('VmRSS', 0)]),
                  core_bpf_memlock_bytes=final.get('bpf_memlock_bytes', 0))
    return result


def dns_query(name, timeout=8):
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    query += b''.join(bytes([len(label)]) + label.encode() for label in name.split('.'))
    query += b'\0' + struct.pack('!HH', 1, 1)
    with network(CLIENT):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with sock:
        sock.settimeout(timeout)
        sock.sendto(query, ('192.0.2.1', 53))
        response = sock.recv(4096)
    if response[3] & 15 or response[6:8] != b'\x00\x01':
        raise RuntimeError('unexpected DNS answer: ' + response.hex())
    return socket.inet_ntoa(response[-4:])


def trace_syscalls(work):
    path = work / 'syscalls.txt'
    trace = subprocess.Popen(['strace', '-f', '-c', '-e',
        'trace=splice,read,write,readv,writev,recvfrom,sendto,sendmsg,recvmsg',
        '-o', str(path), '-p', str(CORE.pid)], stdout=subprocess.DEVNULL,
        stderr=(work / 'strace.log').open('w'))
    try:
        time.sleep(.2)
        if trace.poll() is not None:
            raise RuntimeError('strace attach failed')
        payload = bytes(range(256)) * 1024
        with connection(18080) as sock:
            for _ in range(16):
                sock.sendall(payload)
                assert receive(sock, len(payload)) == payload
    finally:
        trace.send_signal(signal.SIGINT)
        try:
            trace.wait(5)
        except subprocess.TimeoutExpired:
            trace.kill()
            trace.wait()
    calls = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-1] in ('splice', 'read', 'write', 'readv', 'writev', 'recvfrom', 'sendto', 'sendmsg', 'recvmsg'):
            calls[fields[-1]] = int(fields[3])
    return dict(verified_echo_bytes=16 * len(payload), calls=calls, core_alive=CORE.poll() is None)


def dns_checks(mode):
    (ROOT / 'dns-answer.txt').write_text('203.0.113.30')
    name = mode + '-ttl.test'
    first = dns_query(name)
    (ROOT / 'dns-answer.txt').write_text('203.0.113.31')
    time.sleep(1.3)
    after = []
    for _ in range(8):
        after.append(dns_query(name))
        if after[-1] == '203.0.113.31':
            break
        time.sleep(.2)
    (ROOT / 'dns-answer.txt').write_text('203.0.113.30')
    burst = mode + '-burst.test'
    barrier = threading.Barrier(16)

    def query(_):
        barrier.wait(10)
        return dns_query(burst)

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        answers = list(executor.map(query, range(16)))
    counts = json.loads((ROOT / 'dns-counts.json').read_text())
    return dict(initial=first, after_ttl=after, refreshed_after_ttl='203.0.113.31' in after,
                ttl_upstream_requests=counts.get(name, 0), concurrent_clients=16,
                burst_upstream_requests=counts.get(burst, 0), burst_all_correct=all(x == '203.0.113.30' for x in answers))


def reload_check(mode, work):
    with connection(18080) as sock:
        sock.sendall(b'before-reload')
        assert receive(sock, 13) == b'before-reload'
        before = time.monotonic()
        if mode.startswith('dae'):
            path = work / 'config.dae'
            path.write_text(path.read_text().replace('log_level: warn', 'log_level: info'))
            response = run(A.dae, 'reload', str(CORE.pid), timeout=65, required=False)
            command = dict(returncode=response.returncode, stdout=response.stdout, stderr=response.stderr)
        else:
            text = (work / 'config.yaml').read_text().replace('log-level: warning', 'log-level: info')
            api('/configs?force=true', 'PUT', {'payload': text})
            command = dict(returncode=0)
        time.sleep(.2)
        try:
            sock.settimeout(2)
            sock.sendall(b'after-reload')
            preserved = receive(sock, 12) == b'after-reload'
            error = None
        except (OSError, EOFError) as exc:
            preserved, error = False, repr(exc)
    with connection(18080) as fresh:
        fresh.sendall(b'new')
        new_ok = receive(fresh, 3) == b'new'
    return dict(existing_tcp_preserved=preserved, new_tcp_works=new_ok, error=error,
                elapsed_seconds=time.monotonic() - before, command=command)



def main():
    report = dict(environment=dict(kernel=platform.release(), machine=platform.machine(),
                  affinity=sorted(os.sched_getaffinity(0)), cpu_max=pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
                  iperf_version=run('iperf3', '--version').stdout.splitlines()[0]), modes=[])
    report['versions'] = dict(dae=run(A.dae, '--version', required=False).stdout.strip(),
                              rust=run(A.rust, '-v').stdout.strip(),
                              dae_sha256=hashlib.sha256(pathlib.Path(A.dae).read_bytes()).hexdigest(),
                              rust_sha256=hashlib.sha256(pathlib.Path(A.rust).read_bytes()).hexdigest())
    try:
        setup()
        for mode in A.modes:
            print('START', mode, flush=True)
            work = ROOT / (mode + ('-' + A.work_suffix if A.work_suffix else ''))
            work.mkdir(exist_ok=True)
            result = dict(mode=mode, benchmarks=[])
            try:
                start_core(mode, work)
                result['functional'] = functional(mode)
                if not result['functional']['path_verified']:
                    raise RuntimeError('unexpected forwarding path; performance comparison invalid')
                if A.trace_syscalls and CORE:
                    result['syscalls'] = trace_syscalls(work)
                for repeat in range(A.repeats):
                    for parallel, reverse in ((1, True), (8, True), (8, False)):
                        if A.seconds:
                            entry = benchmark(mode, work, parallel, reverse, repeat)
                            result['benchmarks'].append(entry)
                            print(mode, entry['name'], round(entry.get('mbps', 0), 1), 'Mbps', flush=True)
                if mode != 'native' and not A.skip_behavior:
                    result['dns'] = dns_checks(mode)
                    result['reload'] = reload_check(mode, work)
                result['completed'] = True
            except Exception as exc:
                result.update(completed=False, error=repr(exc))
                print('ERROR', mode, repr(exc), flush=True)
            finally:
                stop_core()
            report['modes'].append(result)
            pathlib.Path(A.output).write_text(json.dumps(report, indent=2) + '\n')
            print('DONE', mode, json.dumps({k: v for k, v in result.items() if k not in ('benchmarks', 'functional')}), flush=True)
    finally:
        stop_core()
        for process in CHILDREN:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for ns in (CLIENT, TARGET):
            run('ip', 'netns', 'del', ns, required=False)
        pathlib.Path(A.output).write_text(json.dumps(report, indent=2) + '\n')
    print('RESULT', A.output, flush=True)


if __name__ == "__main__":
    main()
