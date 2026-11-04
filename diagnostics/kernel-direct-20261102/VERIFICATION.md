# eBPF 内核 DIRECT 加速交付验证

交付：`bin/Clash.Core`，OpenWrt/Linux aarch64 musl 静态 ELF，已 strip。SHA-256：

`428f40ba519b9eee1cd00c9588d351d5eaa48d5ed059ad6d871e82b63ad55562`

压缩版为 `bin/Clash.Core.gz`，校验文件为 `bin/Clash.Core.sha256`。旧版保存在 `bin/Clash.Core.before-kernel-direct`，SHA-256 为 `0702d75a8ddbc31cb6f33133c97df10b7da05a11f91e66bea25d8ca9a2e2888e`。

## 实现结果

新增 `ebpf.direct-offload`。对于列出的 LAN 接口，首个 TCP SYN/UDP 包进入 Rust 完成规则和 DNS 判定；确认可以 DIRECT 后，原首包注回内核，后续报文走 TC + Linux 路由、防火墙及现有 NAT。没有创建用户态 TCP 桥或逐包 UDP relay。

- IPv4/IPv6 TCP 与 UDP，双向 fake-IP 地址恢复。
- 有界流表、元组冲突回退、UDP 空闲超时和关闭记录清理。
- TCP ACK 序列计数，重传/重复 ACK 不重复计费；UDP 数据报和分片只统计一次有效负载。
- ICMP 错误引用中的真实目标恢复为 fake-IP，并保持校验和。
- 需要嗅探、自动/未固定组、额外 socket 选项或无法安全映射的流保留用户态路径；固定 select 组选择 DIRECT 可以卸载。
- 规则、模式和选择组变化使 UDP 记录失效，新流重新判定；已建立 TCP 保持原选择。
- `/connections` 增加 `kernelOffload`；`/traffic`、每连接计数和关闭 API 接入内核记录。
- 正常退出、失败回滚、SIGKILL 恢复，只清理自己的 TC 程序和路由归属，保留外部 filter/clsact。

源码与对象：`rust/crates/mihomo-ebpf/bpf/direct.c`、`src/linux/direct.rs`、`src/direct_types.rs`；运行时判定位于 `mihomo-runtime/src/kernel_direct.rs`，TUN 首包接入位于 `mihomo-app/src/tun_kernel_direct.rs`。BPF 大小端对象已编译并内嵌，测试执行的是 little-endian 对象。

## 最终 ARM64 文件的运行证据

隔离 Docker 内建立独立 LAN/WAN 网络命名空间。客户端为 `192.0.2.2` / `2001:db8:1::2`，目标为 `203.0.113.30` / `2001:db8:3::30`，另使用 fake-IP 地址。目标服务器直接与客户端建立端到端 TCP/UDP 流；核心不通过本地代理伪造成功响应。

| 检查 | 结果 |
| --- | --- |
| 内核 DIRECT、fake-IP、分片、关闭、超时、规则、嗅探、selector 与完整生命周期 | 69/69 |
| `tun.auto-route: true` | 59/59 |
| 自动路由 + WAN IPv4 MASQUERADE | 59/59 |
| 新 DIRECT 程序真实 verifier 与 `BPF_PROG_TEST_RUN` | 35/35 |
| 原 eBPF 内核报文回归 | 33/33 |
| 原 eBPF 实际挂载、捕获与生命周期 | 39/39 |
| TLS 大文件、并发和实际丢包重传 | 11/11 |
| 两台独立 LAN 客户端 | 13/13 |
| OpenClash TUN | 21/21 |
| 域名分流 | 93/93 |
| 规则/provider API | 30/30 |
| 定量流量速度、连接计数、WebSocket/HTTP 面板数据 | 110/110 |
| fake-IP 首访、DoH、并发映射保护 | 20/20 |
| fake-IP 游戏 UDP 连续回包与主动推送 | 10/10 |

新 DIRECT 路径实测覆盖 256 KiB TCP 内容校验、16 KiB UDP 分片、首个数据报已分片、显式关闭现有 TCP、UDP 超时后的新 ID、IP-CIDR 在 fake-IP 解析后的最终决策，以及 DIRECT 选择组改成 REJECT 后不再继续卸载。

关闭已卸载 TCP 的效果是禁止该流继续转发，客户端可能等待自身超时并重连；没有伪造 TCP RST。IPv6 加速要求系统 IPv6 forwarding 已启用。

Rust 检查：API 66、config 25、eBPF 2、rules 32、runtime 400 项通过，runtime 1 项依赖外部 MMDB 的测试忽略；应用 TUN 46、controller 13 项通过。日志见本目录。没有把这些定向验证称为完整工作区或全内核版本覆盖。

## DIRECT 性能对照

固定 Docker CPU affinity 为 `0-3`，无 CPU 时间配额。8 条 IPv4 TCP 下载流，每轮 6 秒，逐块校验全部内容；旧版与最终版本交替测试两轮。网络拓扑与测速负载相同：旧版通过用户态 TUN DIRECT，新版通过内核 DIRECT。

| 指标，两轮平均 | 旧版用户态 | 本次内核路径 |
| --- | --- | --- |
| 吞吐 | 6.291 Gbps | 6.534 Gbps |
| 6 秒内核心进程 CPU 时间 | 7.275 秒 | 约 0.005 秒 |

本地内容生成/校验也消耗资源，吞吐已受夹具约束，因此这组数据主要证明 Rust 不再搬运这些 DIRECT 负载。CPU 栏只统计核心进程，Linux 网络栈、TC/eBPF、softirq 仍有开销，不能解读为系统转发不消耗 CPU，也不是移动 WiFi 真机或公网测速承诺。

旧版性能对照仅检查其支持的 IPv4 UDP 数据报大小；不把旧版的 IPv6 UDP/分片限制混入 TCP 性能结论。新的 IPv6/分片能力由上面的独立内核路径检查验证。

## 启用方式

把下面的段合入现有配置，将 `br-lan` 改为实际接收 WiFi/LAN 客户端流量的接口：

```yaml
ebpf:
  direct-offload:
    - br-lan
```

还需要 `allow-lan: true`、启用并明确命名的 TUN、`tun.auto-redirect: false`。`stack: system` / `mixed` 和自动路由开关均沿用现有配置；当前测试主要使用 mixed。设备需已开启转发并具有正常 LAN→WAN 路由、防火墙和必要 NAT。本功能不自动开启 sysctl 或改写防火墙。

重启后检查 `GET /ebpf` 的 `direct_offload.running`、program ID 和 `/connections` 的 `kernelOffload: true`。默认不开启；现有 eBPF `auto-redir`/`redirect-to-tun` 的 `bypassed` 计数仍不代表此 DIRECT 加速。

完整使用说明见 `docs/rust-rewrite/kernel-direct-offload.md`。当前容量为 4096 个流，内核/权限不支持时明确报错；这不是硬件 offload。实际移动 WiFi/OpenWrt 设备尚未访问，需替换后复测。

## 复查与回退

`scripts/kernel-direct-smoke.py` 重现独立 LAN/WAN 运行路径，`--auto-route --masquerade` 覆盖 NAT，`--lifecycle` 覆盖重载/退出/崩溃恢复；`scripts/kernel-direct-packet-tests.py` 使用真实内核执行受控报文。构建使用 Rust 1.88.0、aarch64 musl、静态 CRT；BPF 对象通过 `scripts/build-ebpf.sh` 生成。

`raw/` 保存成功的原始运行结果，`manifest.json` 记录源文件、BPF 对象、二进制与证据校验值。中途调试结果不计为最终通过项。

回退时移除 `ebpf.direct-offload`，正常重启即可恢复原用户态路径；也可换回 `Clash.Core.before-kernel-direct`。正常重启负责卸载自己挂载的程序，不需要清空系统 TC。
