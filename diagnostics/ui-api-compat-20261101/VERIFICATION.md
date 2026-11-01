# 验证记录

- 单元测试：`cargo test -p mihomo-api -p mihomo-config -p mihomo-dns`，65 + 20 + 45 项通过，文档测试通过。
- 应用 DNS：`cargo test -p mihomo-app --lib dns -- --test-threads=1`，11 项通过。
- 同配置对照：`python3 scripts/ui-api-conformance.py --core <binary> --label <rust|official-go> --output <result.json>`。官方 Go、Rust 调试构建和最终 ARM64 文件各 55 项通过。
- 应用重载：`cargo test -p mihomo-app --lib reload_ -- --test-threads=1`，2 项通过；运行验收另外验证 fake-IP 映射在重载后保留。
- 最终 CLI：`final-cli-checks.json`，6 项通过。
- ARM64：Rust 1.88.0，`CC_aarch64_unknown_linux_musl=musl-gcc CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target aarch64-unknown-linux-musl -p mihomo-app --bin mihomo`，静态 ELF。
- 浏览器：MetaCubeXD 1.273.1，独立来源的面板与 API，连接、实时数据、中文选择组、模式修改、最终产物配置重载通过。

`manifest.json` 固定源码与交付文件校验值。所有配置与密钥均为本地测试夹具，未使用用户节点凭据。兼容范围与剩余差异见 `docs/rust-rewrite/ui-api-openclash-audit.md`。
