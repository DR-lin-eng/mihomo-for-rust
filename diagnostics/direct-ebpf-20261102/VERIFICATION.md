# DIRECT 与 eBPF 数据路径核对

核对对象：当前 `bin/Clash.Core`，SHA-256 为 `0702d75a8ddbc31cb6f33133c97df10b7da05a11f91e66bea25d8ca9a2e2888e`。本次检查没有修改生产代码或重新构建内核。

## 结论

**进入核心并命中 DIRECT 的连接仍由 Rust 用户态转发，尚未实现根据 DIRECT 规则结果进行内核快速转发。** 当前 eBPF 提供流量捕获、重定向和核心出站防回环。

| 路径 | 实际行为 |
| --- | --- |
| `ebpf.redirect-to-tun` | TC egress 将选定接口的 TCP/UDP 流量送入 TUN，随后由 Rust 分流和转发 |
| `ebpf.auto-redir` | TC 改写符合条件的 TCP 目标到 redir listener，并恢复回包源地址；Rust 仍负责连接与转发 |
| 命中 DIRECT 的 TCP | 创建普通目标 TCP socket，使用 Rust `read/write` 双向搬运数据 |
| 命中 DIRECT 的 UDP | Rust 解析目标后调用 UDP socket `send_to/recv_from`，再恢复客户端看到的来源 |
| eBPF 的 `bypassed` | 包可能因核心 socket 的 SO_MARK、TUN 回写、本地/私网目的地址或不支持的协议而跳过捕获；这个计数不代表 DIRECT 规则已卸载到内核 |

没有进入捕获路径的局域网等流量可继续走普通内核路由，但它没有经过核心的 DIRECT 规则判定，不能算成核心 DIRECT 规则加速。

## 源码证据

- `mihomo-ebpf/bpf/mihomo.c:69`：TUN TC 程序按 bypass mark、来源接口、地址与协议决定是否 `bpf_redirect`；不读取 Clash 规则结果。
- 同文件 `:94`：auto-redir 只维护原始目标、TCP 关闭状态和地址改写。map 包含 config、origins、本机地址和 stats，没有规则动作或 DIRECT 放行流表。
- `mihomo-ebpf/src/linux.rs:100` 与 `mihomo-config/src/document.rs:178`：只有 `redirect-to-tun` 或 `auto-redir` 非空才安装 eBPF；二进制具备能力不会自动启用。
- `mihomo-runtime/src/execution.rs:1566` → `mihomo-transport/src/executor.rs:641`：DIRECT 变成直接拨号目标 socket。
- `mihomo-runtime/src/tcp.rs:82`、`:181`：relay 的 `_strategy` 没有切换执行分支，实际为 64 KiB 缓冲区的 `reader.read`、`writer.write`。
- `mihomo-app/src/listener_udp_session_ops.rs:141`：DIRECT UDP 调用普通 `socket.send_to`。
- `mihomo-core/src/socket_mark.rs:13`、`:21` 及 `mihomo-transport/src/transport_types.rs:841`：出站 socket 在发送或连接前设置绕环标记，避免重新进入透明代理。

还确认了一处能力描述缺口：启动/版本中的 `zero-copy-tcp`、`zero-copy-tcp-udp`、`openwrt-software-offload`、`openwrt-hardware-offload` 来自 `mihomo-platform/src/optimization.rs` 的候选标签；capability 部分仅按编译操作系统判断。当前 TCP relay 没有实际 `splice/sendfile` 分支，也没有对应的 nft flowtable、硬件卸载或 BPF sockmap 接入。这些标签不能作为已启用加速的证据。

## 当前交付文件的 Docker 实测

| 检查 | 结果 |
| --- | --- |
| 真实 TC 挂载、TUN/redir 流量、DIRECT TCP/UDP/DNS、防回环与生命周期 | 39/39 |
| 真实 verifier 与 `BPF_PROG_TEST_RUN` 报文检查 | 33/33 |
| 未配置 `ebpf:` 时的实际运行状态 | `supported: true, running: false, interfaces: []` |

DIRECT 出站夹具的实际计数为 `processed: 15, redirected: 7, bypassed: 8, dropped: 0`：原客户端流量先被重定向，核心发出的目标连接包随后绕过捕获。不能把这 8 个 bypass 包解释为该客户端连接已经脱离 Rust 用户态。

此前用户贴出的配置没有 `ebpf:` 段；按那份配置不会挂载本核心的 TC 程序。移动 WiFi 当前实际运行配置和系统规则未被远程读取，设备也可能由插件另行安装规则，不能据此断言真机系统完全没有使用 eBPF。

本次没有测量 eBPF 与 iptables/nftables 的性能差异，因此不声称仅开启现有 eBPF 捕获就会提升 DIRECT 吞吐。原始结果及源码、内核校验值见 `raw/` 与 `manifest.json`。

## 后续实现边界

实现 DIRECT 快速转发，需要明确加速层：普通真实 TCP socket 可单独评估 Linux `splice`；希望让 LAN 直连流量完全留在内核，则需在流量进入用户态 TCP 终结前完成可靠分类，并处理双向路由/NAT、连接状态、规则重载与统计。

fake-IP 流量还需将 `198.18.0.0/16` 的目标映射到真实地址并恢复回包。用户态 TCP 桥两侧已是独立连接，不能在命中 DIRECT 后简单把后续包改为 TC 放行。当前核对没有把这项尚未实现的能力自动宣称为已具备。
