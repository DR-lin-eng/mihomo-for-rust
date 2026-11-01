# eBPF 验证记录（2026-11-01）

最终文件：`bin/mihomo-rust-openwrt-arm64-ebpf`，26,381,096 字节，静态 AArch64 ELF，SHA-256 `53955985bebc2a7a2c41e0067e572f8ab165b20533b389b188562e767c9e9be8`。包含此前 Smart、REALITY / Vision 与控制器兼容修复。

- 最终 ARM64 交付文件：`ebpf-smoke.py` 39 项通过；实际挂载 Linux TC eBPF，IPv4 / IPv6 原始目标地址与双向 TCP 正常，TUN TCP / UDP 正常。
- `ebpf-packet-tests.py`：33 项内核 BPF_PROG_TEST_RUN 检查通过，程序均经过实际 verifier 加载。
- 同一交付文件：39 项 Smart、55 项 UI / API / DNS 运行检查通过。
- 单元测试：core 6、config 23、ebpf 1、API 65、runtime 362、DNS 45，共 502 项；文档测试通过。原 Smart 的真实 MMDB 夹具测试仍是显式 external-fixture 用例，不计为本轮再次运行。
- 应用测试：DNS 11、重载 2、带 SO_MARK 的 WireGuard TCP / UDP 专项 1、Hysteria2 / Realm 12、TUIC 8，均通过。
- Hysteria2 外层 SOCKS5 测试发现原夹具把服务端目标流量再次路由回自身，补充目标端口 DIRECT 规则后通过；未把超时运行计为通过。
- 错误路径覆盖：缺失网卡、权限不足、第二个活跃实例争抢、配置应用失败回滚、SIGKILL 后重启、foreign filter / foreign empty clsact 保留。
- 核心出站标记覆盖：实际 direct TCP / UDP、DNS UDP 均未被再次捕获；内核 bypassed 计数已验证。
- 测试后 `bpftool prog show` 未发现遗留 `mihomo_*` 程序。

构建使用 Rust 1.88.0、`CC_aarch64_unknown_linux_musl=musl-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --locked --target aarch64-unknown-linux-musl -p mihomo-app --bin mihomo`，随后 strip。BPF 对象重建命令为 `sh scripts/build-ebpf.sh`。

原始日志、运行结果、源码及产物校验值在此目录。历史 Go 对照文件位于 `go-v1.17-reference/`，`.go.txt` 保留原内容而不参与 Go 包发现。测试网络与 `ebpf-fixture` 密钥均属本地夹具，未使用用户真实节点或修改路由器。配置、运行依赖和限制见 `docs/rust-rewrite/ebpf-support.md`。
