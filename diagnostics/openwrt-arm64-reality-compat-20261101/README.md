OpenWrt ARM64 内核构建与验证

本次产物包含当前 REALITY / Vision / sing-box 兼容修复，与上一份 Windows 兼容版本的关键源码一致。编译目标为 aarch64-unknown-linux-musl，使用 Rust 1.88.0，静态链接并移除了不需要的符号，不需要 glibc 或共享库。

验证包括 ELF64/AArch64 文件头、无 PT_INTERP/DT_NEEDED、Alpine 3.20 ARM64 中的版本输出与配置校验，以及实际产物对 Xray、sing-box 的 12 项 REALITY/Vision 互通场景。场景校验双向各 512 KiB HTTP/TLS 流量、服务端先发、UDP 和 XUDP。OpenWrt 路由器实机与用户节点待用户测试。

原始可执行文件和 gzip 包位于 bin/mihomo-rust-openwrt-arm64-reality-compat[.gz]。解压后可按所用管理程序要求命名为 mihomo 或 Clash.Core，并使用 chmod +x 赋予执行权限。未自动部署或替换路由器上的内核。
