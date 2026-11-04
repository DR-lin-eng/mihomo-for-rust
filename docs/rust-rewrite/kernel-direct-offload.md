# eBPF 内核 DIRECT 转发

Linux ARM64 核心新增可选的 `ebpf.direct-offload`。它在 LAN 首包进入用户态 TCP 终结之前完成规则判定，将确认直连的流下发到 TC eBPF。后续 TCP/UDP 数据包由 Linux 路由、连接跟踪和现有防火墙转发，Rust 不再逐包搬运这部分数据。

现有 `ebpf.auto-redir` 和 `ebpf.redirect-to-tun` 仍提供原来的捕获行为。它们单独启用时不会自动开启 DIRECT 加速。

## 启用

把下面的 `ebpf` 段合入现有配置，将 `br-lan` 改成实际接收 WiFi/LAN 客户端流量的接口。不要填写 TUN 设备或蜂窝 WAN 接口。

```yaml
allow-lan: true

tun:
  enable: true
  device: Meta
  stack: mixed
  auto-route: true
  auto-redirect: false

ebpf:
  direct-offload:
    - br-lan
```

保留原来的 DNS、节点和规则配置。`auto-route: false` 也可以使用；DIRECT 捕获本身会将待分类流量交给指定 TUN。接口名必须明确，不能重复，也不能与同一接口的 `auto-redir`/`redirect-to-tun` 同时使用。

这个选项面向路由设备：需要已开启 IPv4 转发、已有 LAN 到 WAN 的路由、防火墙放行和必要的 NAT。程序不更改系统防火墙或开启转发 sysctl。IPv6 只有在全局 `ipv6` 和 IPv6 转发均启用时才卸载，否则继续用户态处理。

内核需要支持 TC、BPF hash map 中的 spin lock，以及带 `BPF_F_LOCK` 的 map 读取；实际验证使用 LinuxKit 6.12。需要 root 或相应 BPF/NET_ADMIN 权限。旧内核不支持时明确报错，不能把 `-v` 的能力标记当成已运行。LAN 源接口要求 Ethernet 链路，包括常见 veth、bridge 和 WiFi 接口；raw-IP/PPPoE 不是此入口。

## 数据路径

1. TC 将未分类的 LAN TCP SYN/UDP 首包送到 TUN，并记录来源接口与原始四元组。
2. Rust 使用当前规则、DNS 映射和选择结果判定。需要嗅探、动态组选择、DNS 劫持、代理封装或额外 socket 选项的流量继续走原用户态路径。
3. 确认为 DIRECT 的流建立有界内核记录，再将原首包注回内核。TCP 保持客户端与目标服务器之间的同一条连接，不经过用户态 TCP 桥。
4. 后续包按流记录转发；fake-IP 的目的地址转换为同地址族的真实地址，回包来源恢复为原 fake-IP。分片映射和 ICMP 错误中的引用地址也相应恢复。

默认 DIRECT、自定义普通 direct 节点以及显式固定到 DIRECT 的 select 组可以进入加速；自动选择、Smart、负载均衡或未固定的组保留用户态行为。新流按最新规则判定。已建立 TCP 和原运行时一样维持当前选择；模式、规则或选择组变化会使 UDP 加速记录失效。完整配置重载会重建程序和流记录。

跨地址族的 fake-IP 映射、内核表容量耗尽或真实目标元组冲突会回退用户态，不把包错误地发往其他目标。内核表最多 4096 个流，关闭记录短暂保留用于阻止旧包误入新路径，并最终回收。没有启用硬件 offload。

## 面板与关闭

`GET /ebpf` 增加 `direct_offload`，包含运行状态、LAN 接口、实际 program ID、容量与当前表内流量。

`GET /connections` 的对应记录增加 `kernelOffload: true`。原有 `chains`、规则与域名字段保留，`/traffic` 和全局累计流量同步包含内核转发字节。TCP 按已确认的有效序列数据计数，重传和重复 ACK 不会重复累加；UDP 按数据报有效载荷计数。同步周期约 100 毫秒。

`DELETE /connections/{id}` 会关闭对应内核转发权限，阻止该 TCP 流继续收发；客户端通常表现为连接被阻断并自行重连。UDP 后续数据包会作为新会话重新判定。

不要将 legacy eBPF 的 `bypassed` 与这个加速状态混淆。`direct_offload.upload/download` 是当前内核表内诊断值，可能随流记录回收而减少；累计值以 `/traffic` 为准。

## 生命周期

加载失败回收已创建程序与路由；正常退出和配置重载移除本核心拥有的 TC filter。共享 clsact 和外部 filter 保留。接口和路由标记采用带网络命名空间标识的进程锁，异常退出后的下一次启动会清理遗留程序及自己记录的路由规则。

若 SIGKILL 后不重启，TC 链接可能仍留在接口。恢复时应启动同配置核心并正常停止；不要清空整个系统的 TC 配置。

验证记录与性能对照见 `diagnostics/kernel-direct-20261102/VERIFICATION.md`。
