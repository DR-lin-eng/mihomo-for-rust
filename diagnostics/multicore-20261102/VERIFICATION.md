# 多核转发与测速性能优化

交付：`bin/Clash.Core`，OpenWrt/Linux aarch64 musl 静态 ELF，已 strip；压缩版为 `bin/Clash.Core.gz`。

SHA-256：`0702d75a8ddbc31cb6f33133c97df10b7da05a11f91e66bea25d8ca9a2e2888e`。

旧版保存在 `bin/Clash.Core.before-multicore`，SHA-256 为 `5ac7183cc097eeda2ccc88ea383a34d2db7df980b38f710dbf83a290d1dae446`。

## 定位与实现

原 TUN 收包线程在每个 TCP 包到来前，遍历全部 TCP flow，处理定时器和清理状态，然后在同一线程执行对应连接的协议栈和 ACK 处理。这使并行测速的成本随连接数量增加，集中在一个收包线程。全局流量统计还在每次记录字节时竞争同一把锁。

本次修改：

- TCP 连接按四元组固定分配到 worker，同一连接保持顺序，不同连接可同时处理。worker 数按可用 CPU 自动选择 1–8，每个 worker 队列最多 128 个包，线程栈 512 KiB。
- 定时器与关闭清理按约 20 毫秒的周期执行，移除每包遍历全部连接的操作。无连接的 worker 等待消息，避免忙轮询。透明 TCP 路径不额外创建被动协议栈 worker。
- 初始单连接直接处理，减少跨线程分发成本；出现另一连接时，将已有协议栈和状态先移交到对应 worker，再处理后续包。迁移后保持并行模式到该 TUN worker 停止，避免反复迁移。
- TUN 批量回包一次获取写锁，减少每个 ACK/数据包重复争用共享写锁。
- 流量统计按记录线程分散到多个独立缓存行的统计分片。API 采样时固定顺序锁住全部分片，在读取连接计数期间保持冻结，继续保证全局总量与每连接计数一致。
- 停止时关闭队列、终止协议栈并回收 worker；晚到的非 SYN 包不创建孤立连接，已结束的同四元组可重新建连。

主要代码：`tun_worker_tcp_dispatch.rs`、`tun_worker_loop.rs`、`tun_worker_tcp.rs`、`tun_worker_io.rs` 与 `mihomo-runtime/src/traffic.rs`。源文件哈希见 `manifest.json`。

## 最终构建的性能对照

使用隔离 Docker Linux/arm64 环境，主机为 Apple M4。主对照固定 CPU affinity 为 `0-7`，无 CPU 时间配额。客户端通过真实 TUN 和本地 SOCKS5 源站并行传输可验证字节流，每轮 8 秒。

采样由独立 Python 进程完成，每约 100 毫秒读取核心线程 CPU 时间和 `/connections`，避免负载生成器自身的 GIL 影响采样。上传与 64 路下载各重复两轮，下表使用平均值。

| 场景 | 旧版 | 本次版本 | 比值 |
| --- | --- | --- | --- |
| 16 路 TUN 上传 | 1.758 Gbps | 3.755 Gbps | 2.14 倍 |
| 64 路 TUN 下载 | 2.482 Gbps | 5.699 Gbps | 2.30 倍 |
| 初始单连接 TUN 下载 | 6.424 Gbps | 6.414 Gbps | 约相同 |
| 16 路 mixed 显式代理下载 | 6.186 Gbps | 6.258 Gbps | 约相同 |

16 路上传中，最忙线程的 CPU 占用从单个逻辑核的约 **77.6% 降至 43.1%**；最终结果中 8 个 `tun-tcp-*` worker 均参与工作，处理量分散到多个核。64 路下载中最忙线程的占用从约 63.2% 降至 10.4%。两轮最终上传期间的 API 最大响应约 13.4 毫秒，下载约 10.0 毫秒。

上传时核心进程总 CPU 从平均约 1.23 核增至 3.30 核，同时吞吐增加；这是并行执行带来的速度收益。下载场景的进程 CPU 时间也有下降，具体每线程采样保存在原始结果中。

另将容器限制到 4 核做一次同场景上传对照：旧版 1.686 Gbps，本次 5.439 Gbps。4 核与 8 核是不同的主机调度条件，这组数据不能用于证明核数线性伸缩。只分配 1 核时，4 路并发传输内容校验和 API 检查也通过，worker 自动适配为 1 个。

启用 TUN、无业务流量的独立 5 秒观察中，8 个 TCP worker 的核心进程累计 CPU 时间为 0.03 秒，约为单核的 0.6%，没有出现空闲忙轮询。

这些是本地受控吞吐结果。实际路由器的 CPU、网卡驱动、加密协议与公网链路可能给出不同结果；单个 TCP/QUIC 加密流仍有协议顺序约束。此次没有进行真机测速或整体内存基准。

## 兼容性与正确性

以下 **298 项运行检查全部通过**，原始结果记录的 SHA-256 与交付文件一致。

| 检查 | 结果 |
| --- | --- |
| TLS 大文件上传/下载、慢读、keepalive、并行连接 | 10/10 |
| 实际丢弃一个 TUN 回包后的 TLS 重传恢复 | 11/11 |
| Shadowsocks 出站下的 TLS 与大文件 | 10/10 |
| 两台独立 LAN 客户端 TCP/UDP/TLS | 13/13 |
| OpenClash TUN | 21/21 |
| 域名分流 | 93/93 |
| 流量速度、每连接计数、HTTP/WebSocket 订阅及关闭 | 110/110 |
| fake-IP 首访、AAAA 超时、DoH、映射并发保护 | 20/20 |
| fake-IP 游戏 UDP 连续回包与主动推送 | 10/10 |

Rust 检查：TUN 46、runtime 399、controller 13 项通过；runtime 的 1 项外部 MMDB 测试忽略。新增的多线程流量统计一致性测试和按流分配检查通过。另单独复测的 5 项 traffic 测试包含在 runtime 检查范围内。完整日志在本目录；未把这些定向检查称为完整工作区测试。

## 使用与复现

替换设备实际运行的 `Clash.Core`，保留可执行权限并重启。无需修改现有配置。校验：

```sh
sha256sum Clash.Core
./Clash.Core -v
```

版本行应包含 `linux aarch64` 和 `with rustc 1.88.0`；版本号仍为 `0.1.0`，请用 SHA-256 区分构建。

测速夹具为 `scripts/multicore-smoke.py` 和独立采样器 `scripts/multicore-monitor.py`。仅在具有 TUN、NET_ADMIN 与隔离网络的 Linux 容器中运行，例如：

```sh
python3 /repo/scripts/multicore-smoke.py \
  --core /repo/bin/Clash.Core --clients 16 --direction upload \
  --seconds 8 --output /results/upload.json
```

`raw/` 保存旧版与最终版本的性能、CPU、API 和回归原始结果；`manifest.json` 记录构建、源文件与证据校验值。移动 WiFi 真机仍需替换后复测。
