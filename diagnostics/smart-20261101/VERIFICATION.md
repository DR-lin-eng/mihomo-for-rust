# Smart 验证记录（2026-11-01）

最终文件：`bin/mihomo-rust-openwrt-arm64-smart`，25,594,640 字节，静态 AArch64 ELF，SHA-256 `8a799f3f70b9d142ba9e0665c74f5a822e7a9edb4db7ff6eb1948bdb0d34cb1a`。

- `cargo test --locked -p mihomo-runtime -p mihomo-api -p mihomo-config -p mihomo-outbound`：362 + 65 + 21 + 10 = 458 项单元测试通过，文档测试通过。Smart 专项再次通过 10 项。
- MaxMind 真实测试数据库：单独运行被标记为需要外部夹具的测试，1 项通过；使用 `SMART_MMDB_FIXTURES=/tmp/smart-mmdb-fixtures cargo test --locked -p mihomo-runtime smart_enriches_metadata_from_real_mmdb_files -- --ignored --nocapture`。
- 应用 DNS 11 项、配置重载 2 项、UDP 会话复用 2 项通过。
- 最终 ARM64 文件：`scripts/smart-smoke.py` 39 项通过，`scripts/ui-api-conformance.py` 55 项通过。
- 真实模型：`scripts/smart-model-verify.py`，LightGBM 4.6.0 与 Rust 160 组预测完全一致。参照 Go 源码 160 组特征向量及自适应公式结果在浮点舍入误差内一致。
- 模型推理参考工具为 `cargo run -p mihomo-runtime --example smart-model -- <Model.bin> <inputs.json>`；诊断目录保留原始输入和结果。
- Go 对照函数固定自 Alpha `77af4804d091d89b871c99b52d50915f4a600d81`，文件 `go-reference.go.txt`。复制为临时 `.go` 文件后可运行；对应输入 / 结果为 `go-reference-inputs.json` 和 `go-reference-results.json`。

真实 MetaCubeXD v1.273.1 展示 Smart 组和自动模式，并成功手动固定 DIRECT；API 的 type / now / fixed 分别返回 Smart / DIRECT / DIRECT。测试进程 SHA-256 与交付文件相同。截图为 `output/playwright/smart-20261101/smart-group.png`。

全部网络测试使用隔离的本地代理、HTTP、TLS / DNS 及 UDP 服务，没有用户节点凭据。`smart-fixture` 是测试控制器密钥。`manifest.json` 固定源码与产物校验值。实现范围及已知差异见 `docs/rust-rewrite/smart-support.md`。
