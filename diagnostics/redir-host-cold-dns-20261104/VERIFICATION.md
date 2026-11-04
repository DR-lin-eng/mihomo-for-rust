# redir-host 域名冷访问 DNS 排查

日期：2026-11-04。用户现象：redir-host 模式首次访问提示域名查不到 IP，刷新恢复；示例域名为 `www.hacg.me`。

本次在 ARM64 Docker 中复现并修复了两处 DNS 转发逻辑缺陷。真实域名经 Cloudflare DoH 的首次查询也通过，但尚无路由器的 DNS 配置和现场日志，不能将模拟复现直接认定为设备故障的唯一原因。

## 已复现的代码缺陷

1. DNS listener 经 `relay_shared_query_packet` 调用 `DnsRuntime::exchange_query_packet`。此路径仅在上游传输失败或返回的 IP 命中 fallback-filter 时查询 fallback；主上游返回空 A/AAAA 或 NXDOMAIN 时，直接向浏览器返回无地址答复。内部地址解析和 Go `dns/resolver.go::ipExchange` 会在这种情况下尝试 fallback，两条路径行为不一致。
2. `fallback-filter.domain` 在 `nameserver-policy` 之前生效，命中的域名可能绕过指定 DNS。修复后优先使用匹配策略；策略答复和显式 `rcode://` 不被通用 fallback 覆盖。

修复保留 fallback 的原始 DNS 报文、事务 ID、TTL、标志及域名到 IP 的映射。非地址记录（HTTPS/SVCB/TXT 等）的空 IP 列表不触发本次新增的 fallback 条件。未配置 fallback 时，保留上游原始空答复或 NXDOMAIN；fallback 自身失败则返回错误，由 listener 发送 SERVFAIL。

主要变更：`rust/crates/mihomo-dns/src/runtime.rs`。新增 5 个回归测试，覆盖 A/AAAA、NXDOMAIN、无 fallback、非地址记录、策略优先级、显式 rcode 和 fallback 失败。

## Docker 对照

镜像 `rust:1.88`，平台 `linux/arm64`。`scripts/redir-host-cold-dns-smoke.py` 启动真实核心、UDP DNS 上游与 HTTP 服务，均在容器 loopback 上通信；模拟上游对某个域名第一次返回空答复/NXDOMAIN，第二次返回地址。不依赖公网和用户代理节点。

| 验证 | 现有 bin/Clash.Core | 修复后候选 |
| --- | --- | --- |
| 主 DNS 首次空 A，配置健康 fallback | UDP/TCP 均无 IP，刷新恢复 | 首次解析及 HTTP 访问成功 |
| 主 DNS 首次 NXDOMAIN，配置健康 fallback | UDP/TCP 均无 IP，刷新恢复 | 首次解析及 HTTP 访问成功 |
| 主 DNS 首次空 AAAA，启用 IPv6 | 首查无地址，刷新恢复 | 首次返回 fallback IPv6 |
| 策略与 fallback 域名过滤同时命中 | 查询 fallback，跳过策略 | 使用指定策略 |
| 无 fallback 的空答复/NXDOMAIN、健康主 DNS、空 HTTPS 记录、rcode 策略 | 通过对应检查 | 通过对应检查 |
| 端到端检查合计 | 26/42 | 42/42 |
| DNS 库测试 | 初始 62/62 | 最终 67/67 |

Docker release 构建成功，`git diff --check` 和脚本语法检查通过。构建中的既有 unused/dead_code 警告不是本次新增的编译错误。`leader_panic_releases_the_key_and_notifies_followers` 的 panic 输出是其故障恢复夹具的一部分，该测试通过。

## www.hacg.me 实际查询

在 Docker 中分别查询 A、AAAA、HTTPS，每种类型重复查询，并通过候选核心启动三个全新进程复测。

- Cloudflare DoH `https://cloudflare-dns.com/dns-query` 返回 A `104.21.62.119`、`172.67.223.131`，AAAA 和 HTTPS 记录也成功。候选核心 18/18 次查询有答复且 RCODE=0，首次与重复查询约 74–104 ms；这只验证解析，没有验证网站 HTTP/TLS 访问或客户端浏览器。
- AliDNS DoH 返回另一组且多次变化的地址（例如 A `31.13.84.34`、`108.160.170.26`，AAAA `2001::...`），HTTPS 地址提示也与 Cloudflare 不同。该结果表明上游存在明显差异，不能据此承诺切换核心即可消除该域名的所有问题。核心层不通过域名硬编码猜测正确 IP。
- 指向 `223.5.5.5`、`119.29.29.29`、`1.1.1.1`、`8.8.8.8` 的普通 UDP/53 查询均返回相同的 `198.18.16.32`、TTL=1，AAAA/HTTPS 为空，符合宿主代理 fake-IP 拦截特征；它们不能作为四家公共 DNS 的独立真实答复。设备使用 redir-host 与 Docker 宿主存在 fake-IP 拦截并不矛盾。

路由器 DNS 配置尚未提供，设备实际采用哪个上游、是否配置 fallback、是否因上游不一致或传输超时而失败，仍需现场验证。公网查询结果也可能随时间和网络变化。

## 产物与复现

候选是用于 Docker 测试的 GNU Linux ARM64 ELF：`bin/mihomo-dns-cold-linux-arm64-20261104`。它不是 OpenWrt musl 交付物。本次未替换 `bin/Clash.Core`，未部署或重启路由器。

| 文件 | SHA-256 |
| --- | --- |
| 现有 bin/Clash.Core | `0dd44a427402f135d50a866cc678cb2c54a2c9475cea21d2689e6c9c9574635c` |
| Docker 候选核心 | `99df65724f4879451bbcaf4913a548184c3fefa035a168d52b8d96d89e6012a8` |

从仓库根目录复现已构建候选：

```sh
docker run --rm --platform linux/arm64 \
  -v "$PWD":/repo -w /repo rust:1.88 \
  python3 scripts/redir-host-cold-dns-smoke.py \
  --core /repo/bin/mihomo-dns-cold-linux-arm64-20261104 \
  --output /repo/diagnostics/redir-host-cold-dns-20261104/raw/recheck.json
```

重新构建可使用独立 target 目录：

```sh
docker run --rm --platform linux/arm64 \
  -v "$PWD/rust":/work -w /work rust:1.88 \
  sh -lc 'export PATH=/usr/local/cargo/bin:$PATH; \
    CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/work/target-docker-dns-recheck \
    cargo build --locked --release -p mihomo-app --bin mihomo'
```

本地 `raw/` 保存 `baseline.json`、`final.json`、`dns-tests.log`、`build.log`、`public-upstreams.json`、`domain-final.json` 和实际域名探测脚本。`manifest.json` 记录源文件、产物和证据哈希。原始日志、二进制、构建缓存按现有仓库规则忽略，报告、manifest 和回归脚本可纳入版本管理。
