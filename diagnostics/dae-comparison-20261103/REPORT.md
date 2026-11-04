# dae 与 Rust Mihomo：Docker 对比测试

本报告记录合成网络实验结果；不代表物理网口、OpenWrt 真机或互联网代理节点的实际速率。

## 版本与环境

```text
dae version 0.0.0.nightly.20261031.r865.29a702
go runtime go1.27.3-X:heapminimum512kib,newinliner,simd linux/arm64
Copyright (c) 2022-2026 @daeuniverse
License GNU AGPLv3 <https://github.com/daeuniverse/dae/blob/main/LICENSE>
Mihomo Meta 0.1.0 linux aarch64 with rustc 1.88.0 (6b00bc388 2025-06-23) unknown time variants=standard,zero-copy-tcp,zero-copy-tcp-udp,openwrt-software-offload,openwrt-hardware-offload smart ebpf
```

- Linux 6.12.76-linuxkit，aarch64。
- 容器 CPU affinity：[4, 5, 6, 7]；cpu.max：`400000 100000`；内存上限 3 GiB。
- LAN 客户端、路由核心、WAN 目标通过两个 veth 相连。客户端和目标运行在独立网络命名空间；未使用 host 网络。
- dae、Rust 内核 DIRECT 的连接容量均设置为 4096；MTU 为 1500。dae 使用 TCX，Netkit 在本环境不可用，自动回退到 veth。
- 所有目标、DNS 和 SOCKS5 服务均在容器内。SOCKS5 夹具使用 splice 转发；本轮代理负载仅测 TCP，不测 SOCKS5 UDP 或加密代理协议。
- 七种路径串行运行；每种分别测 1 连接下载、8 连接下载、8 连接上传；每项 4 秒，重复 3 次。以下使用接收方有效吞吐的中位数。
- 每种路径先检查 512 KiB 数据完整性，并根据目标端观察到的源地址验证实际路径。Rust DIRECT 另检查 `/ebpf` 的运行状态和计数。
- Rust 使用现有交付文件 `bin/Clash.Core`；其 SHA-256 与交付记录一致，相关 20 个文件的源代码哈希均与交付清单匹配。未重新编译。
- dae 压缩包 SHA-256：`sha256:ddef354f4d73a7e75ff4a7df338376a1e81d26ffceeddac6cf0dfa4381b72d58`，与官方发布元数据和 `.dgst` 一致。

## 吞吐中位数

| 路径 | 单连接下载 Gbit/s | 8 连接下载 Gbit/s | 8 连接上传 Gbit/s |
| --- | ---: | ---: | ---: |
| Linux 原生路由 | 130.29 | 118.15 | 114.97 |
| dae 内核 DIRECT | 27.94 | 27.86 | 29.26 |
| Rust 内核 DIRECT | 69.07 | 62.98 | 73.23 |
| Rust TUN 用户态 DIRECT | 4.87 | 7.71 | 4.10 |
| dae 透明入口 → SOCKS5 | 100.11 | 70.58 | 66.77 |
| Rust TUN → SOCKS5 | 3.25 | 6.39 | 4.03 |
| Rust eBPF redir → SOCKS5 | 50.83 | 50.79 | 52.71 |

有效吞吐轮次：63/63。原始 iperf3 JSON 保存在每种路径的子目录中。

## 8 连接下载时的资源占用

| 路径 | 核心进程 CPU % | 容器总 CPU % | 核心峰值 RSS MiB | BPF memlock MiB |
| --- | ---: | ---: | ---: | ---: |
| Linux 原生路由 | 0.0 | 187.1 | 0.00 | 0.00 |
| dae 内核 DIRECT | 0.0 | 149.4 | 39.01 | 5.42 |
| Rust 内核 DIRECT | 0.7 | 170.1 | 9.66 | 3.92 |
| Rust TUN 用户态 DIRECT | 205.7 | 262.2 | 15.28 | 0.00 |
| dae 透明入口 → SOCKS5 | 48.2 | 244.4 | 48.96 | 5.42 |
| Rust TUN → SOCKS5 | 194.5 | 258.9 | 12.92 | 0.00 |
| Rust eBPF redir → SOCKS5 | 129.4 | 305.0 | 7.54 | 8.01 |

CPU 100% 表示一个逻辑 CPU。RSS 为约 100 ms 采样到的峰值。容器总 CPU 包括负载生成器、目标、代理夹具和采样器；核心进程 CPU 不含全部 BPF/软中断成本。异步内核工作也不保证全部计入该容器。BPF memlock 单独列出，不包含在 RSS 中，也不等于完整内核占用。

## DNS 与重载

| 路径 | TTL 到期后更新地址 | 16 个并发查询的上游请求数 | 重载保留已有 TCP | 重载后新连接 |
| --- | --- | ---: | --- | --- |
| dae 内核 DIRECT | 是 | 1 | 是 | 是 |
| Rust 内核 DIRECT | 是 | 16 | 否 | 是 |
| Rust TUN 用户态 DIRECT | 是 | 16 | 否 | 是 |
| dae 透明入口 → SOCKS5 | 是 | 1 | 是 | 是 |
| Rust TUN → SOCKS5 | 是 | 16 | 否 | 是 |
| Rust eBPF redir → SOCKS5 | 是 | 16 | 否 | 是 |

- DNS 夹具返回 TTL=1 秒，并人为延迟 80 ms；到期后更换地址，再查询是否更新。dae 开启 optimistic cache，因此第一次过期查询可返回旧值，并在后台刷新。
- 并发查询使用相同的新域名，16 个客户端经屏障同时发出查询。所有返回地址均单独核对。
- 重载在已有 TCP echo 连接存活时修改日志级别配置，再验证同一 socket 与新 socket。
- 这组实验修正了此前仅依据结构体的推断：Rust 实际 DNS 响应能在 TTL 到期后更新；此次观察到的差距是相同并发查询未合并。

## 离散程度与适用范围

| 路径 | 项目 | 三次 Gbit/s |
| --- | --- | --- |
| Linux 原生路由 | 1 连接 download | 143.14, 114.39, 130.29 |
| Linux 原生路由 | 8 连接 download | 160.28, 58.69, 118.15 |
| Linux 原生路由 | 8 连接 upload | 121.08, 78.76, 114.97 |
| dae 内核 DIRECT | 1 连接 download | 27.94, 21.81, 38.98 |
| dae 内核 DIRECT | 8 连接 download | 23.16, 27.86, 56.23 |
| dae 内核 DIRECT | 8 连接 upload | 24.15, 29.26, 67.88 |
| Rust 内核 DIRECT | 1 连接 download | 59.43, 69.07, 99.85 |
| Rust 内核 DIRECT | 8 连接 download | 62.98, 62.98, 75.19 |
| Rust 内核 DIRECT | 8 连接 upload | 59.39, 82.79, 73.23 |
| Rust TUN 用户态 DIRECT | 1 连接 download | 4.70, 4.91, 4.87 |
| Rust TUN 用户态 DIRECT | 8 连接 download | 7.25, 8.61, 7.71 |
| Rust TUN 用户态 DIRECT | 8 连接 upload | 4.31, 4.10, 1.16 |
| dae 透明入口 → SOCKS5 | 1 连接 download | 100.11, 123.10, 60.10 |
| dae 透明入口 → SOCKS5 | 8 连接 download | 71.15, 70.58, 56.02 |
| dae 透明入口 → SOCKS5 | 8 连接 upload | 92.56, 66.77, 55.58 |
| Rust TUN → SOCKS5 | 1 连接 download | 2.34, 3.25, 4.46 |
| Rust TUN → SOCKS5 | 8 连接 download | 4.48, 6.39, 9.17 |
| Rust TUN → SOCKS5 | 8 连接 upload | 2.24, 4.03, 4.13 |
| Rust eBPF redir → SOCKS5 | 1 连接 download | 53.87, 48.63, 50.83 |
| Rust eBPF redir → SOCKS5 | 8 连接 download | 50.79, 57.16, 30.63 |
| Rust eBPF redir → SOCKS5 | 8 连接 upload | 52.71, 58.57, 27.44 |

- Docker Desktop 共享宿主 CPU；短时测量、GSO/GRO、CPU 配额和其他容器负载会影响结果。应结合原始三次结果判断，不将单次峰值作为承诺。
- dae 与 Rust 的入口、协议栈和转发实现不同。吞吐差异不能单独归因于编程语言或 splice；Rust redir 与 TUN 两条路径用于辅助区分入口开销。
- 健康状态分维、进程识别、真实 OpenWrt 内核兼容性、长期运行及加密节点性能均未由本轮对比覆盖。

## 额外 Rust 内核回归

- DIRECT LAN/WAN 与生命周期：65/68，passed=False。
- DIRECT 内核报文：35/35，passed=True。
- 原 eBPF 内核报文：33/33，passed=True。

## 实际系统调用

该检查在吞吐测量结束后独立运行，不将 strace 的开销计入上面的性能数据。每条连接发送并逐字节核对 4 MiB echo 数据。

- dae 透明入口 → SOCKS5：`{"splice": 139, "read": 5, "write": 3}`。
- Rust eBPF redir → SOCKS5：`{"recvfrom": 153, "sendto": 137, "recvmsg": 2}`。

此处只证明相应 syscall 路径已使用；吞吐差异还包含透明入口、协议栈、分段和流量统计等因素。

## 已确认的崩溃恢复问题

- auto-route=True：第一次启动 ready=True；SIGKILL 后同配置重启 ready=False，退出码=1。
- auto-route=False：第一次启动 ready=True；SIGKILL 后同配置重启 ready=True，退出码=None。

额外生命周期回归把 `auto-route`、NAT 和 SIGKILL 恢复组合运行，结果为 65/68；失败发生于崩溃后的再次启动，后续清理断言也未通过。最小场景在全新匿名网络命名空间内复现：遗留的 priority 9000、lookup 2022 规则导致 `RTNETLINK answers: File exists`，核心以退出码 1 结束。当前仅记录并定位问题，产品代码未改动。

## 复现与证据

- `compare.py`、`fixtures.py`：对比脚本与本地服务。
- `report.json`：环境、路径证明、每轮吞吐、CPU、RSS、DNS 和重载结果。
- `provenance.json`：官方发布元数据、二进制哈希和 Rust 源文件匹配记录。
- `run.log`、各模式 `core.log`、每轮 `*.iperf.json`：运行日志。
- `functional-probe.*` 与 `functional-retry.*`：预检记录；首次预检中发现并修正 TCX 就绪检测和测试节点 UDP 声明，未改变产品代码。
