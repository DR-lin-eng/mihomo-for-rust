# dae 设计吸收：Rust 核心实现与 Docker 验证

已独立实现 DNS 并发查询合并、保持连接的策略重载、Linux TCP splice、透明 UDP 持续收发和 TUN 路由归属恢复。实现与行为边界见 [说明](../../docs/rust-rewrite/dae-inspired-improvements.md)。

## 交付

- 静态 Linux ARM64/musl 核心：`bin/mihomo-rust-openwrt-arm64-dae-improved`；常用文件 `bin/Clash.Core` 同步更新，旧文件保留为 `bin/Clash.Core.before-dae-improvements`。
- SHA-256：`bab3c7a83b169b911afa3856ee9f47ce13e4d5512026dd8ccc2bd26e087c2c15`。本轮未推送代码或部署到路由器。

## 验证结果

- Rust 1.88 Docker 完整 workspace：1582 项通过，0 项失败，6 项原有标记忽略；真实 TUN 设备测试另行执行并通过。
- 最终二进制的真实网络/内核检查：614/614；共 15 组。
- 覆盖新节点和策略组增删、面板选择、新连接 REJECT、老连接保持、连接 ID 和计数、DNS 事务 ID 与 EDNS 隔离、TUN provider 依赖更新。
- 覆盖自动路由 SIGKILL 恢复、启动中途强杀、并发核心互斥、启动失败回滚、大 UID 过滤列表和第三方规则/路由保留。
- 覆盖 IPv4/IPv6、fake-IP、DNS 映射、TLS、QUIC 全数据报、Smart、流量统计和实际内核 BPF_PROG_TEST_RUN。

| 检查 | 修改前 | 修改后 |
| --- | --- | --- |
| 16 个同时到达的相同 DNS 查询，上游请求数 | 16 | 1 |
| 常规配置重载保留已建立 TCP | 否 | 是 |
| 4 MiB echo 路径的 splice 系统调用数 | 0 | 324 |

系统调用跟踪单独运行，不计入性能负载。自动路由崩溃恢复原先在独立命名空间复现失败，本轮恢复、并发与中断启动检查均通过。

## 交替性能对比

- Docker Desktop Linux 6.12.76-linuxkit，ARM64；固定 CPU [4, 5, 6, 7]，cpu.max=`400000 100000`，内存上限 3 GiB。
- 每项 4 秒、重复 3 次；按轮交替先运行修改前/修改后核心。所有路径均验证 512 KiB 数据完整性，并根据目标观察到的源地址确认实际入口。
- 基线为现有 `mihomo-rust-openwrt-arm64-kernel-direct`。SOCKS5 夹具、iperf3 服务器和客户端均在容器内，客户端与 WAN 位于独立网络命名空间。

| 路径 | 方向/连接数 | 修改前 Gbit/s | 修改后 Gbit/s | 变化 |
| --- | --- | ---: | ---: | ---: |
| 内核 DIRECT | 1 连接 下载 | 118.92 | 118.59 | -0.3% |
| 内核 DIRECT | 8 连接 下载 | 93.57 | 82.80 | -11.5% |
| 内核 DIRECT | 8 连接 上传 | 84.79 | 95.53 | +12.7% |
| TUN → SOCKS5 | 1 连接 下载 | 4.35 | 4.38 | +0.6% |
| TUN → SOCKS5 | 8 连接 下载 | 8.45 | 8.62 | +2.1% |
| TUN → SOCKS5 | 8 连接 上传 | 3.85 | 4.09 | +6.4% |
| redir → SOCKS5 | 1 连接 下载 | 41.73 | 93.43 | +123.9% |
| redir → SOCKS5 | 8 连接 下载 | 38.24 | 68.27 | +78.6% |
| redir → SOCKS5 | 8 连接 上传 | 42.50 | 62.34 | +46.7% |

以上均为接收方吞吐的中位数，表示 Docker veth 合成负载，不代表真实网卡、互联网节点或 OpenWrt 的实测速率。

| 8 连接下载 | 核心 CPU % 修改前/后 | RSS 峰值 MiB 修改前/后 |
| --- | ---: | ---: |
| 内核 DIRECT | 0.5 / 0.5 | 9.67 / 9.35 |
| TUN → SOCKS5 | 202.0 / 201.7 | 13.00 / 13.32 |
| redir → SOCKS5 | 124.1 / 55.5 | 11.46 / 10.43 |

CPU 100% 表示一个逻辑 CPU。进程 CPU 不包含所有 BPF/软中断成本；RSS 不包含 splice 管道和 BPF map 的内核内存。原始记录同时保留容器总 CPU、BPF memlock 和每轮波动。

dae 官方 nightly 作为额外参考，在相同环境下再次运行；入口、协议栈和内存设置不同，不据此把性能差异单独归因于语言或 splice。

| dae SOCKS5 参考 | Gbit/s 中位数 |
| --- | ---: |
| 1 连接 下载 | 71.18 |
| 8 连接 下载 | 48.97 |
| 8 连接 上传 | 51.83 |

## 限制

- 保持 TCP 的重载只适用于监听器、网络拓扑和 DNS 行为不变的策略更新；其它变更仍走重建。
- 纯 TCP 文件描述符可用时启用 splice；TLS、加密、多路复用包装保留其读写语义。TUN 用户态 TCP 协议栈仍走原路径。
- 旧版本无归属日志的崩溃遗留路由无法安全自动认领；替换旧版本前应正常停止旧进程。
- TCP/UDP/IPv4/IPv6 的独立健康评分、cgroup 进程识别、UDP 批量系统调用和将完整规则编译到 BPF 尚未在本轮实现。
- 未进行真机部署或长期运行验证。Docker Desktop 其它工作负载、GSO/GRO 与虚拟网络调度会影响短时性能。

## 证据

- `validation.json` 与各测试 JSON：最终核心的检查明细和哈希。
- `workspace-tests-final.log`、`tun-device.log`：工作区与真实 TUN 设备检查。
- `performance.json`、`performance/`：交替基准及每轮原始 iperf3 数据。
- `syscalls-before.json`、`syscalls-after.json`：实际系统调用、DNS、重载对比。
- `source-changes.json`：以本轮开始时的工作区为基线计算的改动，保留此前未提交内容。
- `manifest.json`：二进制、源码和证据校验值。
