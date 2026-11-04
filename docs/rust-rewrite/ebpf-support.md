# Linux eBPF 支持（Rust，2026-11-01）

后续版本增加了独立的 `ebpf.direct-offload` 内核 DIRECT 路径，配置、行为与限制见 [内核 DIRECT 转发](kernel-direct-offload.md)。下文对 `auto-redir` 和 `redirect-to-tun` 的捕获语义继续有效。

Rust 核心新增了 TC eBPF 加载器，支持 Clash 历史配置中的 `ebpf.redirect-to-tun` 和 `ebpf.auto-redir`。这两项能力曾存在于 Go v1.17.0，当前 MetaCubeX 文档与源码已没有原先的 eBPF 模块；本轮按历史数据路径恢复配置兼容，并复用了现有 Rust TUN / redir 运行时。

这里的 eBPF 用于内核流量捕获和重定向。代理协议、TLS、Smart 选路及数据转发仍由 Rust 核心执行；它不是 OpenWrt 的硬件流量卸载，也不证明吞吐一定高于 nftables / iptables。


交付文件为 `bin/mihomo-rust-openwrt-arm64-ebpf`（26,381,096 字节，静态 AArch64 ELF），另提供 `.gz` 和 `.sha256`。SHA-256：`53955985bebc2a7a2c41e0067e572f8ab165b20533b389b188562e767c9e9be8`。同一文件已通过 39 项 eBPF 端到端检查、33 项内核报文检查、39 项 Smart 与 55 项 UI / API / DNS 回归；另有 502 项子系统单元测试及 34 项应用协议测试通过。
## 配置

TCP 透明重定向，用于路由器 LAN 入口：

```yaml
allow-lan: true
ipv6: true
redir-port: 7892

ebpf:
  auto-redir:
    - br-lan
```

`auto-redir` 将选定接口 ingress 上的非局域网 TCP 流量改写到该接口的本机地址与 redir 端口，在 egress 恢复真实源地址与端口。核心通过 BPF map 查询真实目标地址，不依赖 iptables 的 `SO_ORIGINAL_DST`。未指定 `redir-port` 时使用历史 Go 内部端口 29810。设置 `ipv6: true` 且接口有可用的非链路本地 IPv6 地址时，支持 IPv6 TCP；IPv6 未启用时不改写 IPv6 流量。绑定地址必须允许选定接口的本机地址；使用默认通配绑定即可。

这一路径只捕获 TCP，绕过 TCP 53、私有 / 本地 / 组播目的地址、接口自身地址、分片及不能安全解析的协议。UDP / ICMP 继续走系统原有路径。它不自动替代 DNS 的代理上游配置。

将选定接口的 egress 流量送入核心 TUN：

```yaml
tun:
  enable: true
  stack: system
  device: mihomo
  auto-route: false
  auto-redirect: false
  inet4-address:
    - 198.19.0.1/30
  inet6-address:
    - fdfe:dcba::1/126

ebpf:
  redirect-to-tun:
    - eth1
```

`redirect-to-tun` 保持历史 Go 的 **TC egress** 语义：流量先由 Linux 路由到列出的网卡，然后被送入 TUN。请按实际路由选择接口；这项配置本身不安装默认路由，也不等同于 ingress 的 LAN 捕获。已在真实内核中验证 IPv4 / IPv6 TCP 和 IPv4 UDP 进入 TUN 后经代理转发。IPv6 UDP 报文解析沿用同一实现，尚未在本轮端到端夹具中单独验证。

不能同时启用 `tun.auto-redirect`，也不能把同一接口放进两个列表或把 TUN 设备自身作为源接口。当前源接口要求 Ethernet 类型（物理 Ethernet、veth、bridge）；PPPoE、raw-IP、loopback 等链路类型不会被静默当作 Ethernet 处理。

## 运行依赖与生命周期

- 仅 Linux。测试内核为 Docker Linux VM 的 `6.12.76-linuxkit`，具备 BPF JIT、`CONFIG_BPF_SYSCALL`、`CONFIG_NET_CLS_BPF`、`CONFIG_NET_SCH_INGRESS`。未对全部 OpenWrt LTS 内核逐一实测。
- 需要加载 BPF 的权限（`CAP_BPF` 或较旧内核的 `CAP_SYS_ADMIN`）及 `CAP_NET_ADMIN`。TUN 模式还需要 `/dev/net/tun`。OpenWrt 通常由 root 运行，并需安装内核对应的 BPF / TC 支持模块；具体模块名随固件而异。
- 运行时使用纯 Rust Aya 加载器（本地固定版本新增无需内核 BTF 的构造入口），内嵌大小端 BPF 对象；不需要 clang、LLVM、bpftool、libbpf 动态库或 bpffs 挂载。`ip` 仍由现有 TUN 设备 / 路由管理使用。
- BPF 程序只使用稳定的 UAPI、TC 和 helper，没有 CO-RE / BTF 结构重定位依赖。内核能力不符、接口缺失或权限不足会明确失败，不能把失败当作已启用。
- 配置先检查全部接口，再加载程序；应用失败释放已经创建的程序 / map / filter。重新配置失败时应用层恢复旧配置。
- 正常重载 / 退出只卸载本核心的 filter。仅在本核心创建且已经没有任何 filter 的情况下删除 clsact；原有过滤器和原有空 clsact 均保持保留。
- 每个网络命名空间 / 接口使用进程锁，阻止两个活跃核心争抢接口。SIGKILL 后的遗留程序以保留名称 `mihomo_rs_*` 识别，下次持锁启动时回收并重新挂载。锁文件位于 `/tmp/mihomo-ebpf-<netns>-<ifindex>.lock`；不依赖清空整个 TC 或 BPF 目录。
- 默认绕环标记为 `0x636c746d`；可用 `ebpf.bypass-mark` 修改。全局与代理的显式 `routing-mark` 需要与之相同，避免不一致的标记造成环路。BPF 绕过核心出站及来自 TUN 的回写流量。
- TCP、UDP、DNS 和 QUIC 出站在首个包发出前带上绕环标记。WireGuard 库未提供外层 SO_MARK 接口，因此有标记时使用带标记的本地 UDP 中继；TCP / UDP 专项测试通过。

内核 LRU map 有界，auto-redir 最多保留 65,536 个流条目。为保证目的地址正确，客户端对多个不同目标同时复用同一个源端口、并被压缩到相同代理元组时，新冲突连接会丢弃，已有连接映射保持不变；当前没有实现源端口 NAT 扩展。FIN 状态允许关闭后复用，RST 删除映射。接口地址列表是加载时的快照，DHCP / IPv6 地址变化后需重载配置。

## API 与检查

- `GET /configs` 新增 `ebpf` 配置字段。
- `GET /ebpf` 是 Rust 诊断扩展，返回 supported、running、各接口模式、TC 方向、实际 program ID，以及内核 processed / redirected / bypassed / dropped 计数。沿用控制器鉴权和 CORS。
- `-t` 校验配置关系，不会加载 BPF 或证明运行权限可用。运行状态应以正常启动成功和 `/ebpf` 为准。
- Linux 版 `-v` 显示 `ebpf` 能力标识；Windows / macOS 版本不显示这一标识。

## 验证

`scripts/ebpf-smoke.py` 在独立的特权 Docker 容器和网络命名空间内测试真实 TC 挂载与流量，不使用宿主网络。覆盖 IPv4 / IPv6 原始目的地址恢复、TUN TCP / UDP、配置重载与失败回滚、外部 TC 配置保留、SIGKILL 恢复、并发核心互斥、权限不足、核心直连 TCP / UDP / DNS 绕环。

`scripts/ebpf-packet-tests.py` 使用内核 `BPF_PROG_TEST_RUN`，验证 VLAN、IPv4 选项、IPv6 扩展头、双向 IP / TCP 校验和、片段 / ICMP / ARP / 私有地址绕过，以及连接元组冲突不会覆盖现有目标。

BPF 对象可在具备 clang、LLVM 和 libbpf 头文件的 Linux 环境中，用 `sh scripts/build-ebpf.sh` 重新生成；普通核心构建直接包含已保存的对象。Docker 中完成 verifier 验证和报文测试，测试结果及对象校验值见 `diagnostics/ebpf-20261101/`。

本轮不包括 XDP、cgroup socket 重定向、任意用户 BPF 程序加载、硬件 offload，或旧 Rust TUN 实现尚未解决的 ICMP / gVisor / 路由兼容问题。上游 eBPF 历史源码仅作为行为参照；当前 Go 核心没有可用的同接口实现供同版本运行比较。真实 OpenWrt 设备、固件模块组合和长期性能仍需设备侧验证。

后续内存优化版本及其 BTF 读取修复、map 内存实测见 [内存优化记录](memory-optimization.md)。
