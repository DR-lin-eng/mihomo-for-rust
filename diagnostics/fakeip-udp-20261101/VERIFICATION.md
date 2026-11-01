# fake-IP UDP 游戏连接修复

交付文件：`bin/Clash.Core`，Linux/OpenWrt aarch64 musl 静态 ELF，已 strip。压缩版为 `bin/Clash.Core.gz`。

SHA-256：`1f68e801f17b7abfe2cee57df4b37133d020f9d1e3e494f41256968df8fc1f46`。

旧版已保存在 `bin/Clash.Core.before-fakeip-udp`，SHA-256 为 `a755451af893d892adbbc7834c8b6e444d8e4f8688f5cadc5680780ca4a754e9`。

## 已复现的问题

隔离 Docker 网络命名空间模拟了独立 WiFi 客户端、真实 TUN 接口、fake-IP DNS 和游戏服务器。客户端从 `192.0.2.44:49152` 发起流量；DNS 为两个测试域名分配不同的 `198.18.0.0/16` 地址，上游游戏服务器实际位于另外两个地址。

旧版在 DIRECT 和 SOCKS5 两条路径均能完成普通单包 echo，但三包登录只能收到一个响应，1.3 秒后的服务端主动推送无法送达。两组基线各通过 5/8 项，失败项一致。原始证据为 `raw/baseline-game-*.json.gz`。

故障在 UDP 会话收发阶段：旧 TUN worker 发送一个数据包后，只调用一次接收，并在等待期间持有会话锁。游戏需要先连续发送多个登录包、再接收一批响应时，这会阻塞后续发送；服务端连续回包和主动推送也缺少独立接收者。

另有两个相关问题：UDP 经流式代理时反复创建连接，破坏登录会话的连续性；controller 对 UDP 使用固定 30 秒回收条件，可能早于用户配置的 `tun.udp-timeout: 300`。

## 修复内容

- TUN UDP 发送与持续接收分开，接收网络数据时不占用发送会话锁，所有响应可直接写回 TUN。通过目标映射和既有 NAT 恢复，让客户端看到原来的 fake-IP 来源地址。
- 保留原始协议流用于读取，克隆流用于发送，兼容 VLESS/VMess 等只提供写入克隆的实现；复用有效的流式 UDP 会话。
- 路由变化时先停止旧接收者，再切换传输和解码器；过期、controller 关闭、缓存淘汰和 TUN 停止均会清理接收者。协议帧分段到达时保留已读取的前缀。
- TUN 会话及 controller 使用配置的 UDP 空闲超时；接收活动也刷新活跃时间。
- 直接发送的路径不再重复入队并长期保留原始数据包。接收者随既有会话缓存限制在 256 个以内，每个线程栈设为 256 KiB，目标映射也有上限；本次没有进行内存性能基准测试。

主要代码位于 `tun_packet.rs`、新增的 `tun_udp_receiver.rs`、`tun_worker.rs`、`listener_udp_session*.rs`、`listener_udp_prepare.rs` 和 runtime 的 `tunnel_runtime.rs`。源文件哈希见 `manifest.json`。

## 最终 ARM64 文件的 Docker 结果

所有下列运行测试均使用 SHA-256 为 `1f68e801…8fc1f46` 的候选文件；交付名 `Clash.Core` 与其逐字节一致。

| 场景 | 结果 |
| --- | --- |
| DIRECT、SOCKS5、Shadowsocks、VLESS TLS、Hysteria2 | 各 10/10 |
| DIRECT、SOCKS5 显式启用 endpoint-independent-nat | 各 10/10 |
| 同一源端口在 SOCKS5 与 DIRECT 路由间切换 | 10/10 |
| Hysteria2 交错访问两台服务器并接收原服务器延迟推送 | 11/11 |
| 32 秒后主动推送，同时持续轮询 `/connections` | 8/8 |
| 游戏 UDP 模拟合计 | **99/99** |
| 两台 LAN 客户端、fake-IP、TCP/UDP、TLS 下载 | 13/13 |
| OpenClash TUN | 21/21 |
| 域名分流 | 93/93 |
| 规则及 provider API | 30/30 |
| eBPF | 39/39 |

游戏测试核对了不同 fake-IP 目标、真实上游地址、三包登录、全部回包的 fake-IP 来源、无额外客户端发送的服务端推送，以及 controller 关闭后的重新登录。三包登录耗时约 0.5–48 毫秒，32 秒推送正常送达。

Shadowsocks、VLESS、Hysteria2 使用 Go Mihomo v1.19.33 作为本地真实协议服务端。VLESS/Hysteria2 的自签名证书和 `skip-cert-verify` 仅用于隔离夹具。

Rust 检查结果：TUN 45、UDP session 2、controller 13、VLESS UDP 21、VMess UDP 20、Hysteria2 13 项通过；API/config/core/DNS/runtime/TUN 库分别为 66/24/6/53/397/9 项通过，runtime 有 1 项依赖外部 MMDB 的测试被忽略。日志已保存在本目录。这些是针对本次改动的检查，不代表完整工作区测试或与 Go 全协议等价。

## 复测与交付核对

替换设备实际启动的核心文件，保留可执行权限，然后重启核心并重新连接游戏。校验命令：

```sh
sha256sum Clash.Core
./Clash.Core -v
```

版本行应包含 `linux aarch64` 和 `with rustc 1.88.0`；版本号仍为 `0.1.0`，请以 SHA-256 区分本次构建。

复现脚本为 `scripts/fakeip-udp-smoke.py`，可在具有 TUN、NET_ADMIN 和网络命名空间权限的隔离 Linux 容器运行。例如：

```sh
python3 /repo/scripts/fakeip-udp-smoke.py \
  --core /repo/bin/Clash.Core \
  --outbound hy2 --reference-core /tmp/go-mihomo \
  --interleave --output /results/hy2.json
```

这里验证的是 IPv4 fake-IP TUN 游戏模拟和本地协议互通。移动 WiFi 真机及实际公网游戏尚未访问，需要使用新版文件复测。构建日志、原始结果及校验清单均保存在本目录。
