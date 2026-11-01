# TUN HTTPS 传输中断修复（2026-11-01）

交付：`bin/Clash.Core`，aarch64 Linux musl 静态、stripped ELF，28,216,104 字节。压缩包 `bin/Clash.Core.gz` 为 12,696,719 字节；校验文件为 `bin/Clash.Core.sha256`。

SHA-256：`d5ec21f7903f75a62c18cd93cff618afd2b61947d2868ff850521a39c0958416`。

## 已确认的故障

使用此前实际交付的 ARM64 核心（SHA `34ebff007f5863c4fa3dbaf4ca92e3e1f90cad7e6d88a2a84512721805cf4338`）在 Docker 中复现：普通 mixed 入口经 SOCKS5 或 Shadowsocks 完成 HTTPS 传输；相同代理出口经 system TUN 时，TLS 1.3 握手和小响应成功，随后 4 MiB 下载停住，客户端读超时。核心跟踪出现：

```text
bridge-error TCP relay write returned zero (proxy=fixture chain=fixture target=tun.test:...)
```

`smoltcp::Socket::send_slice()` 在 128 KiB 发送缓冲区满时允许返回 0。原 `TunTcpStreamHandle::write()` 将其直接返回给 relay，relay 按 WriteZero 错误结束该方向，因此证书、小响应等短报文测试通过仍不能保证实际网页和持续下载正常。

## 修改

- TUN 的非空写入在缓冲区满时释放栈锁，使用已有条件变量等待 ACK 腾出空间，继续返回实际写入的字节数；不再把暂时无空间报告为 0，也不通过反复重试忙轮询。
- 消费接收缓冲区后触发 TCP poll 并输出窗口更新，避免上传端等待窗口、接收端等待新数据。
- 原有 TUN worker 按 TCP 下一次到期时间推进延迟 ACK、重传和关闭状态，即使没有新入站报文也能输出到期数据；没有新增每连接计时线程。
- 对端 FIN 只关闭接收方向。转发结束后保留尚未关闭的 TCP 栈，等待已排队的数据和 FIN 完成确认或重传。
- 支持写超时和完整关闭。完整关闭中止栈并唤醒等待空间的写者，避免控制器关闭连接后仍卡在条件变量上。

主要代码为 `tun_tcp_stack/handle.rs`、`tun_tcp_stack/stack.rs`、`tun_worker_tcp.rs` 和 `tun_worker_loop.rs`。新增三项单元回归，检查等待 ACK、关闭唤醒和写超时。

## Docker 验证

夹具使用真实 TLS 服务、证书校验、本地 SOCKS5 转发代理和本地 AES-128-GCM Shadowsocks 服务。TUN 为真实 Linux 设备，客户端通过 SO_MARK 和策略路由进入接口；普通入口作为对照。每条连接校验 4 MiB 下载、4 MiB 上传的内容哈希，并复用 TLS 连接继续请求，再同时运行四个客户端。

| 检查 | 结果 |
| --- | --- |
| 修复前 mixed → SOCKS5，真实 HTTPS | 10 / 10 |
| 修复前 mixed → Shadowsocks，真实 HTTPS | 10 / 10 |
| 修复前 TUN → SOCKS5 | TLS/小响应成功，4 MiB 下载超时 |
| 修复前 TUN → Shadowsocks | TLS/小响应成功，4 MiB 下载超时 |
| 修复后 TUN → SOCKS5 | 10 / 10 |
| 修复后 TUN → Shadowsocks | 10 / 10 |
| 修复后 TUN → SOCKS5，真实丢弃一次 TLS 回包 | 11 / 11，iptables 确认丢包计数为 1 |
| TUN 库和应用定向回归 | 41 / 41 |
| controller 定向回归 | 13 / 13 |
| 最终 Clash.Core：OpenClash TUN 回归 | 21 / 21 |
| 最终 Clash.Core：域名分流回归 | 93 / 93 |
| 最终 Clash.Core：真实 TC eBPF 回归 | 39 / 39 |

修复后大文件、慢读、保持连接和并发检查全部通过。故障前夹具在下载阶段停止，上传与后续复用未执行，不把这些阶段算作独立复现。`summary.json` 保存逐项结果；`raw/*.json.gz` 保存包含完整 TCP 跟踪的原始输出，未压缩源数据共数十 MiB，因此以 gzip 保存。构建、定向测试日志及完整源文件/产物哈希在相邻日志和 `manifest.json` 中。

## 设备日志与验证边界

用户说明故障发生在移动 WiFi，确认运行此前交付的 Rust 核心。提供日志有 `rmnet_data0` 蜂窝接口及大量到 `192.168.1.1:50016` 的连接，同时包含可在 Go 源码找到的 `*gcm.GCM`、Vision 等日志格式；尚未核实这些行具体来自哪个进程或是否为混合历史日志，不能仅凭该日志将内网地址现象归因于这次修复。

本次修复依据的是对实际交付二进制的确定性复现、对应源码和相同条件下的前后验证。未连接移动 WiFi 真机或真实订阅节点，也没有验证所有远端代理协议。需要使用新版在原设备复测，才能确认用户现场问题是否已全部消除。

原版本仍保存在 `bin/mihomo-rust-openwrt-arm64-traffic-connections-fix`。本次没有覆盖原有重构工作，也没有部署设备或发布远端版本。
