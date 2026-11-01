# Smart 高级能力迁移验证（2026-11-01）

交付文件：`bin/mihomo-rust-openwrt-arm64-smart-advanced`，静态、stripped AArch64 Linux ELF，28,019,496 字节；`.gz` 为 12,573,793 字节。

SHA-256：`58fcaf91b04514df2f012eee688a9a3bd7e6e330eda75d21311c1ce5092876de`。

参照 [vernesong/mihomo Alpha 77af4804](https://github.com/vernesong/mihomo/tree/77af4804d091d89b871c99b52d50915f4a600d81)，使用 Docker / Rust 1.88.0 构建。精确构建命令、依赖锁和工作区源码 SHA-256 清单见 `manifest.json`。本轮没有提交或推送 Git，保留工作区此前的重构改动。

## 已实现

- 自动拨号采用前三个顺序尝试、随后最多五个并行的批次，最多十个候选；只有成功返回的出站传输作为赢家。赢家计划与统计一致，取消其他 underlay，迟到的成功连接关闭，不复制业务数据、不把取消记为失败。手动固定只尝试指定出口；稳定赢家缓存、失败失效及顺序回退均已接入。额外竞速线程最多十六个，满额回到原顺序路径。
- 非内部 TCP 域名连接、443 端口、低下载量时，经该节点和实际代理链请求 HTTPS robots.txt，不跟随跳转。区分地区拒绝、验证码、限流、配额、普通重定向、HTTP 错误、TLS 验证及超时，并有界限流和大小/时间限制。
- 全局出口 trace 及目标专属 trace，六小时缓存、失败十五分钟重试；保存地区、ASN 和出口 IP 哈希。地区/ASN 排除要求两个独立出口的拒绝及另一个已知地区/ASN 的成功对照；别名去重，未知地区不能充当跨地区对照。
- 公共后缀、随机子域名折叠、服务规则身份、原始 GEOSITE/GEOIP、规则条目数和 ASN 多样性归并；共享 ASN 和所有权冲突不认领。热目标缓存、探测结果和反馈驱动重新学习。
- Linux TCP_INFO 发送段/重传增量采样、64 段窗口、累计损失率和 EMA；不足样本保持未知，高损失排除要求重复有效证据。TLS/REALITY/VLESS/Vision/VMess 可透传计数；不可观测的封装及 QUIC 保持未知。
- 所有探测通过有界队列执行，清缓存、重载和关闭取消旧任务；旧结果不能写回已清状态。Rust 旧 JSON 状态可升级读取。新增 `GET /group/:name/smart` 诊断接口，沿用鉴权和 CORS。

## 验证结果

| 检查 | 结果 |
| --- | --- |
| 运行时、API、规则、核心及出站单元测试 | 490 通过，1 项外部 MMDB 夹具测试保持 ignored |
| 完整传输层测试 | 245 通过 |
| 应用 DNS / 重载 / UDP | 11 / 2 / 2 通过 |
| **最终 ARM64 文件**：真实 CONNECT / TLS 高级 Smart | 62 / 62 |
| **最终 ARM64 文件**：原有 Smart | 39 / 39 |
| **最终 ARM64 文件**：Clash UI/API/DNS | 55 / 55 |
| **最终 ARM64 文件**：隔离 Linux eBPF | 39 / 39 |
| 固定 Go 源码原函数与 Rust 响应分类 | 1,980 组，0 差异 |
| 独立 LightGBM 4.6.0 数值比较 | 160 组，最大误差 0 |

高级夹具使用自己签发、仅由测试子进程信任的 CA 和真实 CONNECT/TLS socket，验证快慢握手、24 并发连接、十候选上限、失败方关闭、取消不污染统计、手动固定、独立出口/同 IP 别名、JSON trace 回退、证书校验、4 KiB 体积限制、一秒响应体等待、重启恢复及进行中探测的 flush。最终测试的 `smart-advanced-arm64.json` 包含交付文件 SHA-256，已与本文件、压缩包解压结果核对。

Go 对照的函数体从固定源文件原样提取，仅将 Header/状态常量依赖绑定到标准 net/http；夹具、原函数、源文件 SHA-256、两侧结果及逐项比较位于 `response/`。两侧解析器使用同一批 1,980 组输入，包含 Retry-After 的 HTTP 日期与整数溢出边界。

## 内存影响

与上一版 `mihomo-rust-openwrt-arm64-memory`（`0ac1a41eaa47eccb81c1b566d109a638b1749c5b7c249dc37586b10d2fcf0e8c`）在同一 Docker 容器、CPUs=2、相同 557 棵树模型下比较，每场景三轮取中位数。最终内存采样在其他核心测试结束后顺序执行，单位 KiB。

| 场景 | 空闲 RSS（旧 → 新） | 32 次 API 后 RSS（旧 → 新） | API 后匿名内存（旧 → 新） |
| --- | --- | --- | --- |
| idle | 7640 → 8312 | 7820 → 8468 | 1096 → 1136 |
| rules-40000 | 24420 → 24788 | 24856 → 25200 | 18140 → 17868 |
| smart-18-groups | 12032 → 12768 | 12212 → 12924 | 5392 → 5444 |

原始采样及峰值见 `smart-advanced-memory-before.json`、`smart-advanced-memory-after.json` 和 `memory-comparison.json`。新增探测线程与代码会增加部分驻留内存；大规则表通过复用统计结构空隙保存来源标记、共享不可变 MRS 集合，避免逐规则对象膨胀。该基准测量空闲和 API 轮询，不代表长时间满表学习或所有业务负载的峰值。

## 范围

默认 `type: smart` 即启用这些行为，原有配置和 API 继续适用。详细选路条件、容量和 TTL 见 `docs/rust-rewrite/smart-support.md`。

未迁移 Go Smart 的 BoltDB 格式及其整套数据库预取后台；Rust 使用自己的有界状态、热目标缓存和 JSON 持久化。探测并发/表容量取适合路由器的较小默认值，不宣称全部调度时序与 Go 逐项相同。延迟发送协议的传输建立成功不等于特定网站可达；后续流量与响应探测承担应用可达性反馈。

以上为 Docker 内受控本地网络、真实 socket 和 Linux 内核测试；未代替 OpenWrt 真机、公开受限网站、长期调优收益或 Windows 实机测试。
