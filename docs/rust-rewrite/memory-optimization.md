# 内存优化与实测（2026-11-01）

本轮减少了大规则配置的常驻内存和 API 轮询峰值，也降低了 eBPF 启动时的瞬时内存。保留 Smart、eBPF、REALITY / Vision 与面板兼容能力。

交付文件：`bin/mihomo-rust-openwrt-arm64-memory`，26,250,024 字节，静态 AArch64 ELF，附 `.gz` 与 `.sha256`。SHA-256：`0ac1a41eaa47eccb81c1b566d109a638b1749c5b7c249dc37586b10d2fcf0e8c`。

## 同配置测量

在同一 Docker Linux ARM64 环境、2 CPU 配额下，将上轮 eBPF 静态版本与本轮静态版本对比。每个场景均有 67 个配置节点、18 个策略组、控制器、DNS 与 mixed 入口；启动后进行 32 次 API 请求（`/version`、`/proxies`、`/configs`、`/rules` 各 8 次）。每种场景独立启动三次，以下为中位数。

| 场景 | 原峰值 RSS | 优化后峰值 RSS | 峰值下降 | 原轮询后 RSS | 优化后轮询后 RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 基础配置 | 8.50 MiB | 8.27 MiB | 2.7% | 8.11 MiB | 8.04 MiB |
| 40,000 条域名规则 | 72.96 MiB | 44.50 MiB | 39.0% | 34.57 MiB | 24.68 MiB |
| 120,000 条记录的 GeoSite 数据库，引用其中 5,000 条 | 12.00 MiB | 11.03 MiB | 8.1% | 10.80 MiB | 10.71 MiB |
| 18 个 Smart 组与真实 Model.bin | 19.61 MiB | 18.50 MiB | 5.7% | 13.77 MiB | 12.36 MiB |
| eBPF auto-redir 已加载 | 25.52 MiB | 9.42 MiB | 63.1% | 9.21 MiB | 9.15 MiB |

4 万规则场景空闲 RSS 另从 34,932 KiB 降到 24,864 KiB，降低 28.8%；Smart 的匿名内存从 6,840 KiB 降到 5,392 KiB，降低 21.2%。基础配置的收益较小，不能把大规则场景的比例套用于所有配置。

eBPF 内核 map 的 memlock **单独计算，不包含在进程 RSS 中**。测试网卡布局下，该值从 8,574,480 字节降到 8,394,704 字节，降低约 2.1%；auto-redir 的 65,536 流容量保持不变。没有为了压低占用缩减 eBPF 流容量或关闭功能。

峰值使用 `/proc/<pid>/status` 的 VmHWM 加上采样 RSS，包含启动和上述 API 轮询；常驻数据来自轮询结束后 `/proc/<pid>/status` 与 `smaps_rollup`。RSS 包括可执行文件 / 共享页面，因此日志也记录了 PSS、Anonymous、Private_Dirty。结果不等同于 OpenWrt 真机内存，也不代表高并发转发的性能或峰值承诺。

基线二进制 SHA-256 为 `53955985bebc2a7a2c41e0067e572f8ab165b20533b389b188562e767c9e9be8`。模型使用此前验证的同一份公开 Model.bin；GeoSite 是脚本生成的固定 24 类、每类 5,000 条记录的 protobuf 数据，不包含用户配置或节点凭据。原始记录和逐场景结果见 `diagnostics/memory-20261101/comparison.json`。

## 改动

1. **共享只读 API 快照。** 控制器的 HTTP / WebSocket 工作线程不再复制整张快照；运行态控制器共用应用的配置状态。`/version` 和已运行的 `/rules` 直接从正确的状态源响应，不再先重建无关的规则 / provider 快照；其他 API 的快照构建也跳过后续不会使用的规则列表。
2. **规则与 DNS 快照共享。** 编译后的规则表、hosts、DNS 过滤 / 策略表使用 Arc。DNS 地址缓存和 fake-IP 双向映射采用写时复制：读操作和克隆共用存储，修改时仍保持各快照的原有隔离。清缓存直接释放引用，不先复制整张表；相同缓存快照不重复合并。
3. **GeoSite / GeoIP 借用解析。** protobuf 长度字段指向原始字节切片，避免复制整库的字段内容；先读取类别名，只有命中的类别才生成域名 / CIDR 对象。同时校验 varint 溢出。保留原有 geodata 的支持范围，没有宣称补齐 MMDB 规则或复杂 geodata 引用。
4. **紧凑 Smart 模型。** 已校验范围内的特征索引、分支标记和类别边界分别采用 u16 / u8 / u32，浮点阈值和叶子分数保持 f64。保存统计时借用现有状态序列化，避免先复制全部学习记录。真实模型 160 组预测与 LightGBM 4.6.0 完全一致。
5. **限制持续增长。** DNS 地址缓存默认最多 4,096 条，可通过 `dns.cache-size` 设置（当前实现为插入顺序淘汰）；UDP 待处理队列最多 256 个任务，满载时丢弃新任务，关闭时立即释放等待任务。正常负载行为已回归；这项过载处理会在持续积压时丢包，不能视为无成本的内存降低。fake-IP 原有容量不变。
6. **eBPF 避免加载整份内核 BTF。** Aya 0.13.1 的 `EbpfLoader::new().btf(None)` 会先读取 / 解析整份内核 BTF 再丢弃；本轮固定了一份带许可证的 Aya 源码，只增加 `new_without_btf()` 公开构造入口，TC 程序不需要的 BTF 不再读取。原 `new()` 行为保持；补丁见 `diagnostics/memory-20261101/aya-without-btf.patch` 和 `rust/third-party/aya/PATCHES.md`。本机地址 map 按实际地址数分配。正常加载仅取简要 verifier 统计，失败时重试详细诊断；实测主要峰值收益来自跳过 BTF，不能归因于日志策略本身。

## 验证

- API、DNS、规则、运行时及 eBPF 共 507 项单元测试通过，文档测试通过；最后的 DNS 缓存释放 / eBPF 接线另复测 48 项。
- UDP 队列上限 / 关闭测试 1 项，应用 DNS 11 项，配置重载 2 项通过。
- 最终 ARM64 文件通过 39 项 eBPF、39 项 Smart、55 项 UI / API / DNS 运行检查。
- 紧凑模型：160 组真实 Model.bin 预测与独立 LightGBM 实现最大绝对误差为 0。
- 内存测试：优化前、后每个场景三次，所有启动与 API 检查通过。脚本为 `scripts/memory-benchmark.py`；默认测量四类用户态场景，另加 `--scenarios ... ebpf-auto-redir` 可测内核 map。

固定的源码校验和、最终文件校验和、构建日志、回归结果与内存原始数据在 `diagnostics/memory-20261101/`。OpenWrt 真机、持续大流量与高并发内存尚未代测。本轮未提交、推送或部署到路由器。
