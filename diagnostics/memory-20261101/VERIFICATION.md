# 内存优化验证（2026-11-01）

交付文件：`bin/mihomo-rust-openwrt-arm64-memory`，26,250,024 字节，SHA-256 `0ac1a41eaa47eccb81c1b566d109a638b1749c5b7c249dc37586b10d2fcf0e8c`，静态 AArch64 ELF。压缩包已解压核对字节一致。

基线为上轮 eBPF 静态版本 SHA-256 `53955985bebc2a7a2c41e0067e572f8ab165b20533b389b188562e767c9e9be8`。同一 Docker 容器、2 CPU 配额、同一模型和规则生成器，每场景独立启动三次；前后各 15 次，全部通过。中位数计算与原始采样分别在 `comparison.json`、`memory-before.json`、`memory-ebpf-before.json`、`memory-after.json`。

- `cargo test --locked -p mihomo-ebpf -p mihomo-api -p mihomo-dns -p mihomo-rules -p mihomo-runtime`：507 项单元测试通过，文档测试通过。
- 最后 DNS / eBPF 单测复查 48 项通过，包含写时复制和缓存上限。应用 DNS 11、配置重载 2、UDP 队列边界 1 项通过。
- 最终二进制：eBPF 39、Smart 39、UI/API/DNS 55 项运行验收通过。
- `scripts/smart-model-verify.py`：真实 Model.bin 的 160 组预测与独立 LightGBM 4.6.0 完全一致。
- eBPF verifier 仍实际验证所有加载程序；正常加载简要日志，发生 LoadError 时才重试详细诊断。
- `aya-without-btf.patch` 是本地 Aya 0.13.1 相对 crates.io 源码的唯一运行时代码差异，添加一个构造入口。源码和两份许可证在 `rust/third-party/aya/`。

构建仍使用 Rust 1.88.0 与 `aarch64-unknown-linux-musl`，`CC_aarch64_unknown_linux_musl=musl-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --locked --target aarch64-unknown-linux-musl -p mihomo-app --bin mihomo` 后 strip。配置与限制见 `docs/rust-rewrite/memory-optimization.md`。
