#!/usr/bin/env python3
"""Build a concise final report and immutable source/binary/test manifest."""
import hashlib
import json
import pathlib
import re
import statistics
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(name):
    return json.loads((ROOT / name).read_text())


validation = read('validation.json')
performance = read('performance.json')
traces = read('syscalls-summary.json')
source_changes = read('source-changes.json')
log = (ROOT / 'workspace-tests-final.log').read_text()
test_suites = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored', log)
unit_passed = sum(int(row[1]) for row in test_suites)
unit_failed = sum(int(row[2]) for row in test_suites)
unit_ignored = sum(int(row[3]) for row in test_suites)
assert len(test_suites) >= 17 and unit_failed == 0
assert all(row['passed'] for row in validation['status'])
assert all(row['core_sha256'] == validation['core_sha256'] for row in validation['status'])
assert len(performance['records']) == 63 and not performance.get('error')
assert performance['after_sha256'] == validation['core_sha256'] == digest(ROOT / 'mihomo-after')
assert all(row['returncode'] == 0 and not row.get('error') and row['mbps'] > 0 for row in performance['records'])
assert read('syscalls-after.json')['versions']['rust_sha256'] == validation['core_sha256']
runtime_count = sum(row['checks'] for row in validation['status'])

groups = {}
for row in performance['records']:
    groups.setdefault((row['variant'], row['mode'], row['parallel'], row['direction']), []).append(row)


def median(variant, mode, parallel, direction, key):
    return statistics.median(row[key] for row in groups[(variant, mode, parallel, direction)])


lines = ['# dae 设计吸收：Rust 核心实现与 Docker 验证', '',
    '已独立实现 DNS 并发查询合并、保持连接的策略重载、Linux TCP splice、透明 UDP 持续收发和 TUN 路由归属恢复。实现与行为边界见 [说明](../../docs/rust-rewrite/dae-inspired-improvements.md)。', '',
    '## 交付', '',
    '- 静态 Linux ARM64/musl 核心：`bin/mihomo-rust-openwrt-arm64-dae-improved`；常用文件 `bin/Clash.Core` 同步更新，旧文件保留为 `bin/Clash.Core.before-dae-improvements`。',
    f"- SHA-256：`{validation['core_sha256']}`。本轮未推送代码或部署到路由器。", '',
    '## 验证结果', '',
    f'- Rust 1.88 Docker 完整 workspace：{unit_passed} 项通过，{unit_failed} 项失败，{unit_ignored} 项原有标记忽略；真实 TUN 设备测试另行执行并通过。',
    f'- 最终二进制的真实网络/内核检查：{runtime_count}/{runtime_count}；共 {len(validation["status"])} 组。',
    '- 覆盖新节点和策略组增删、面板选择、新连接 REJECT、老连接保持、连接 ID 和计数、DNS 事务 ID 与 EDNS 隔离、TUN provider 依赖更新。',
    '- 覆盖自动路由 SIGKILL 恢复、启动中途强杀、并发核心互斥、启动失败回滚、大 UID 过滤列表和第三方规则/路由保留。',
    '- 覆盖 IPv4/IPv6、fake-IP、DNS 映射、TLS、QUIC 全数据报、Smart、流量统计和实际内核 BPF_PROG_TEST_RUN。', '',
    '| 检查 | 修改前 | 修改后 |', '| --- | --- | --- |',
    f"| 16 个同时到达的相同 DNS 查询，上游请求数 | {traces['before']['dns']['burst_upstream_requests']} | {traces['after']['dns']['burst_upstream_requests']} |",
    f"| 常规配置重载保留已建立 TCP | {'是' if traces['before']['reload']['existing_tcp_preserved'] else '否'} | {'是' if traces['after']['reload']['existing_tcp_preserved'] else '否'} |",
    f"| 4 MiB echo 路径的 splice 系统调用数 | {traces['before']['calls'].get('splice', 0)} | {traces['after']['calls'].get('splice', 0)} |", '',
    '系统调用跟踪单独运行，不计入性能负载。自动路由崩溃恢复原先在独立命名空间复现失败，本轮恢复、并发与中断启动检查均通过。', '',
    '## 交替性能对比', '',
    f"- Docker Desktop Linux {performance['environment']['kernel']}，ARM64；固定 CPU {performance['environment']['affinity']}，cpu.max=`{performance['environment']['cpu_max']}`，内存上限 3 GiB。",
    '- 每项 4 秒、重复 3 次；按轮交替先运行修改前/修改后核心。所有路径均验证 512 KiB 数据完整性，并根据目标观察到的源地址确认实际入口。',
    '- 基线为现有 `mihomo-rust-openwrt-arm64-kernel-direct`。SOCKS5 夹具、iperf3 服务器和客户端均在容器内，客户端与 WAN 位于独立网络命名空间。', '',
    '| 路径 | 方向/连接数 | 修改前 Gbit/s | 修改后 Gbit/s | 变化 |',
    '| --- | --- | ---: | ---: | ---: |']
names = {'rust-direct': '内核 DIRECT', 'rust-tun-socks': 'TUN → SOCKS5', 'rust-redir-socks': 'redir → SOCKS5'}
for mode, name in names.items():
    for parallel, direction in ((1, 'download'), (8, 'download'), (8, 'upload')):
        before = median('before', mode, parallel, direction, 'mbps')
        after = median('after', mode, parallel, direction, 'mbps')
        lines.append(f"| {name} | {parallel} 连接 {'下载' if direction == 'download' else '上传'} | {before / 1000:.2f} | {after / 1000:.2f} | {(after / before - 1) * 100:+.1f}% |")
lines += ['', '以上均为接收方吞吐的中位数，表示 Docker veth 合成负载，不代表真实网卡、互联网节点或 OpenWrt 的实测速率。', '',
    '| 8 连接下载 | 核心 CPU % 修改前/后 | RSS 峰值 MiB 修改前/后 |', '| --- | ---: | ---: |']
for mode, name in names.items():
    cpu = [median(label, mode, 8, 'download', 'core_cpu_percent') for label in ('before', 'after')]
    rss = [median(label, mode, 8, 'download', 'core_peak_rss_kib') / 1024 for label in ('before', 'after')]
    lines.append(f'| {name} | {cpu[0]:.1f} / {cpu[1]:.1f} | {rss[0]:.2f} / {rss[1]:.2f} |')
lines += ['', 'CPU 100% 表示一个逻辑 CPU。进程 CPU 不包含所有 BPF/软中断成本；RSS 不包含 splice 管道和 BPF map 的内核内存。原始记录同时保留容器总 CPU、BPF memlock 和每轮波动。', '',
    'dae 官方 nightly 作为额外参考，在相同环境下再次运行；入口、协议栈和内存设置不同，不据此把性能差异单独归因于语言或 splice。', '',
    '| dae SOCKS5 参考 | Gbit/s 中位数 |', '| --- | ---: |']
for parallel, direction in ((1, 'download'), (8, 'download'), (8, 'upload')):
    value = median('dae', 'dae-socks', parallel, direction, 'mbps')
    lines.append(f"| {parallel} 连接 {'下载' if direction == 'download' else '上传'} | {value / 1000:.2f} |")
lines += ['', '## 限制', '',
    '- 保持 TCP 的重载只适用于监听器、网络拓扑和 DNS 行为不变的策略更新；其它变更仍走重建。',
    '- 纯 TCP 文件描述符可用时启用 splice；TLS、加密、多路复用包装保留其读写语义。TUN 用户态 TCP 协议栈仍走原路径。',
    '- 旧版本无归属日志的崩溃遗留路由无法安全自动认领；替换旧版本前应正常停止旧进程。',
    '- TCP/UDP/IPv4/IPv6 的独立健康评分、cgroup 进程识别、UDP 批量系统调用和将完整规则编译到 BPF 尚未在本轮实现。',
    '- 未进行真机部署或长期运行验证。Docker Desktop 其它工作负载、GSO/GRO 与虚拟网络调度会影响短时性能。', '',
    '## 证据', '',
    '- `validation.json` 与各测试 JSON：最终核心的检查明细和哈希。',
    '- `workspace-tests-final.log`、`tun-device.log`：工作区与真实 TUN 设备检查。',
    '- `performance.json`、`performance/`：交替基准及每轮原始 iperf3 数据。',
    '- `syscalls-before.json`、`syscalls-after.json`：实际系统调用、DNS、重载对比。',
    '- `source-changes.json`：以本轮开始时的工作区为基线计算的改动，保留此前未提交内容。',
    '- `manifest.json`：二进制、源码和证据校验值。', '']
(ROOT / 'REPORT.md').write_text('\n'.join(lines))
paths = set(row['path'] for row in source_changes)
paths.update(('rust/Cargo.lock', 'rust/README.md', 'docs/rust-rewrite/dae-inspired-improvements.md', 'scripts/domain-routing-smoke.py'))
manifest = dict(core_sha256=validation['core_sha256'], baseline_sha256=performance['before_sha256'],
    core_size=(ROOT / 'mihomo-after').stat().st_size, workspace_passed=unit_passed,
    workspace_failed=unit_failed, workspace_ignored=unit_ignored, runtime_checks=runtime_count,
    source_sha256={path:digest(REPO / path) for path in sorted(paths)},
    evidence_sha256={str(path.relative_to(ROOT)):digest(path) for path in ROOT.iterdir()
        if path.is_file() and path.suffix in ('.json', '.py', '.md') and path.name != 'manifest.json'},
    head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip())
(ROOT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('Report written:', unit_passed, 'workspace tests;', runtime_count, 'runtime checks; 63 performance rounds')
