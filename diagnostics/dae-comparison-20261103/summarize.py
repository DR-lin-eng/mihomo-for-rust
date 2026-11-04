#!/usr/bin/env python3
"""Produce a reviewable report from the completed Docker measurements."""
import json
import pathlib
import statistics

ROOT = pathlib.Path(__file__).resolve().parent
report = json.loads((ROOT / 'report.json').read_text())
provenance = json.loads((ROOT / 'provenance.json').read_text())
names = {
    'native': 'Linux 原生路由',
    'dae-direct': 'dae 内核 DIRECT',
    'rust-direct': 'Rust 内核 DIRECT',
    'rust-tun-direct': 'Rust TUN 用户态 DIRECT',
    'dae-socks': 'dae 透明入口 → SOCKS5',
    'rust-tun-socks': 'Rust TUN → SOCKS5',
    'rust-redir-socks': 'Rust eBPF redir → SOCKS5',
}


def groups(mode):
    out = {}
    for row in mode['benchmarks']:
        if row.get('returncode') == 0 and not row.get('error') and row.get('mbps', 0) > 0:
            out.setdefault((row['parallel'], row['direction']), []).append(row)
    return out


def throughput(rows):
    return '—' if not rows else f"{statistics.median(r['mbps'] for r in rows) / 1000:.2f}"


lines = [
    '# dae 与 Rust Mihomo：Docker 对比测试', '',
    '本报告记录合成网络实验结果；不代表物理网口、OpenWrt 真机或互联网代理节点的实际速率。', '',
    '## 版本与环境', '',
    '```text', report['versions']['dae'], report['versions']['rust'], '```', '',
    f"- Linux {report['environment']['kernel']}，{report['environment']['machine']}。",
    f"- 容器 CPU affinity：{report['environment']['affinity']}；cpu.max：`{report['environment']['cpu_max']}`；内存上限 3 GiB。",
    '- LAN 客户端、路由核心、WAN 目标通过两个 veth 相连。客户端和目标运行在独立网络命名空间；未使用 host 网络。',
    '- dae、Rust 内核 DIRECT 的连接容量均设置为 4096；MTU 为 1500。dae 使用 TCX，Netkit 在本环境不可用，自动回退到 veth。',
    '- 所有目标、DNS 和 SOCKS5 服务均在容器内。SOCKS5 夹具使用 splice 转发；本轮代理负载仅测 TCP，不测 SOCKS5 UDP 或加密代理协议。',
    '- 七种路径串行运行；每种分别测 1 连接下载、8 连接下载、8 连接上传；每项 4 秒，重复 3 次。以下使用接收方有效吞吐的中位数。',
    '- 每种路径先检查 512 KiB 数据完整性，并根据目标端观察到的源地址验证实际路径。Rust DIRECT 另检查 `/ebpf` 的运行状态和计数。',
    '- Rust 使用现有交付文件 `bin/Clash.Core`；其 SHA-256 与交付记录一致，相关 20 个文件的源代码哈希均与交付清单匹配。未重新编译。',
    f"- dae 压缩包 SHA-256：`{provenance['dae_asset']['digest']}`，与官方发布元数据和 `.dgst` 一致。", '',
    '## 吞吐中位数', '',
    '| 路径 | 单连接下载 Gbit/s | 8 连接下载 Gbit/s | 8 连接上传 Gbit/s |',
    '| --- | ---: | ---: | ---: |',
]
valid = 0
for mode in report['modes']:
    g = groups(mode)
    valid += sum(len(rows) for rows in g.values())
    lines.append('| ' + names[mode['mode']] + ' | ' + ' | '.join(
        throughput(g.get(key, [])) for key in ((1, 'download'), (8, 'download'), (8, 'upload'))) + ' |')
lines += ['', f'有效吞吐轮次：{valid}/63。原始 iperf3 JSON 保存在每种路径的子目录中。', '',
          '## 8 连接下载时的资源占用', '',
          '| 路径 | 核心进程 CPU % | 容器总 CPU % | 核心峰值 RSS MiB | BPF memlock MiB |',
          '| --- | ---: | ---: | ---: | ---: |']
for mode in report['modes']:
    rows = groups(mode).get((8, 'download'), [])
    if not rows:
        continue
    values = [statistics.median(r[k] for r in rows) for k in
              ('core_cpu_percent', 'container_cpu_percent', 'core_peak_rss_kib', 'core_bpf_memlock_bytes')]
    lines.append(f"| {names[mode['mode']]} | {values[0]:.1f} | {values[1]:.1f} | {values[2] / 1024:.2f} | {values[3] / 1048576:.2f} |")
lines += ['', 'CPU 100% 表示一个逻辑 CPU。RSS 为约 100 ms 采样到的峰值。容器总 CPU 包括负载生成器、目标、代理夹具和采样器；核心进程 CPU 不含全部 BPF/软中断成本。异步内核工作也不保证全部计入该容器。BPF memlock 单独列出，不包含在 RSS 中，也不等于完整内核占用。', '',
          '## DNS 与重载', '',
          '| 路径 | TTL 到期后更新地址 | 16 个并发查询的上游请求数 | 重载保留已有 TCP | 重载后新连接 |',
          '| --- | --- | ---: | --- | --- |']
for mode in report['modes']:
    if 'dns' not in mode or 'reload' not in mode:
        continue
    dns, reload = mode['dns'], mode['reload']
    yes = lambda value: '是' if value else '否'
    lines.append(f"| {names[mode['mode']]} | {yes(dns['refreshed_after_ttl'])} | {dns['burst_upstream_requests']} | {yes(reload['existing_tcp_preserved'])} | {yes(reload['new_tcp_works'])} |")
lines += ['', '- DNS 夹具返回 TTL=1 秒，并人为延迟 80 ms；到期后更换地址，再查询是否更新。dae 开启 optimistic cache，因此第一次过期查询可返回旧值，并在后台刷新。',
          '- 并发查询使用相同的新域名，16 个客户端经屏障同时发出查询。所有返回地址均单独核对。',
          '- 重载在已有 TCP echo 连接存活时修改日志级别配置，再验证同一 socket 与新 socket。',
          '- 这组实验修正了此前仅依据结构体的推断：Rust 实际 DNS 响应能在 TTL 到期后更新；此次观察到的差距是相同并发查询未合并。', '',
          '## 离散程度与适用范围', '',
          '| 路径 | 项目 | 三次 Gbit/s |', '| --- | --- | --- |']
for mode in report['modes']:
    for (parallel, direction), rows in groups(mode).items():
        values = ', '.join(f"{r['mbps'] / 1000:.2f}" for r in rows)
        lines.append(f"| {names[mode['mode']]} | {parallel} 连接 {direction} | {values} |")
lines += ['', '- Docker Desktop 共享宿主 CPU；短时测量、GSO/GRO、CPU 配额和其他容器负载会影响结果。应结合原始三次结果判断，不将单次峰值作为承诺。',
          '- dae 与 Rust 的入口、协议栈和转发实现不同。吞吐差异不能单独归因于编程语言或 splice；Rust redir 与 TUN 两条路径用于辅助区分入口开销。',
          '- 健康状态分维、进程识别、真实 OpenWrt 内核兼容性、长期运行及加密节点性能均未由本轮对比覆盖。', '',
          '## 额外 Rust 内核回归', '']
for name, filename in [('DIRECT LAN/WAN 与生命周期', 'rust-kernel-regression.json'),
                       ('DIRECT 内核报文', 'rust-direct-packets.json'),
                       ('原 eBPF 内核报文', 'rust-legacy-packets.json')]:
    path = ROOT / filename
    if path.exists():
        result = json.loads(path.read_text())
        checks = result.get('checks', [])
        passed = result.get('passed', all(c['passed'] for c in checks))
        lines.append(f"- {name}：{sum(c['passed'] for c in checks)}/{len(checks)}，passed={passed}。")
trace_path = ROOT / 'syscall-report.json'
if trace_path.exists():
    lines += ['', '## 实际系统调用', '',
              '该检查在吞吐测量结束后独立运行，不将 strace 的开销计入上面的性能数据。每条连接发送并逐字节核对 4 MiB echo 数据。', '']
    for mode in json.loads(trace_path.read_text())['modes']:
        trace = mode.get('syscalls', {})
        lines.append(f"- {names[mode['mode']]}：`{json.dumps(trace.get('calls', {}), ensure_ascii=False)}`。")
    lines += ['', '此处只证明相应 syscall 路径已使用；吞吐差异还包含透明入口、协议栈、分段和流量统计等因素。']
lines += ['', '## 已确认的崩溃恢复问题', '']
for filename in ('auto-route-crash-repro.json', 'manual-route-crash-repro.json'):
    path = ROOT / filename
    if path.exists():
        result = json.loads(path.read_text())
        lines.append(f"- auto-route={result['auto_route']}：第一次启动 ready={result.get('first_start_ready')}；SIGKILL 后同配置重启 ready={result.get('restart_ready')}，退出码={result.get('restart_exit_code')}。")
lines += ['', '额外生命周期回归把 `auto-route`、NAT 和 SIGKILL 恢复组合运行，结果为 65/68；失败发生于崩溃后的再次启动，后续清理断言也未通过。最小场景在全新匿名网络命名空间内复现：遗留的 priority 9000、lookup 2022 规则导致 `RTNETLINK answers: File exists`，核心以退出码 1 结束。当前仅记录并定位问题，产品代码未改动。', '',
          '## 复现与证据', '',
          '- `compare.py`、`fixtures.py`：对比脚本与本地服务。',
          '- `report.json`：环境、路径证明、每轮吞吐、CPU、RSS、DNS 和重载结果。',
          '- `provenance.json`：官方发布元数据、二进制哈希和 Rust 源文件匹配记录。',
          '- `run.log`、各模式 `core.log`、每轮 `*.iperf.json`：运行日志。',
          '- `functional-probe.*` 与 `functional-retry.*`：预检记录；首次预检中发现并修正 TCX 就绪检测和测试节点 UDP 声明，未改变产品代码。', '']
(ROOT / 'REPORT.md').write_text('\n'.join(lines))
print('Wrote', ROOT / 'REPORT.md')
print('Valid performance rounds:', valid)
for mode in report['modes']:
    g = groups(mode)
    print(mode['mode'], {str(k): throughput(v) for k, v in g.items()}, mode.get('error', ''))
