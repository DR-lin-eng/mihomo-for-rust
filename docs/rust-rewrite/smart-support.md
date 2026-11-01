# Smart 支持（Rust，2026-11-01）

`type: smart` 使用独立的自适应策略，支持 LightGBM 推理、TCP/UDP 统计、并行拨号竞速、HTTPS 响应分类、地区/ASN 出口限制确认及持久化。OpenClash 可通过 `-v | grep smart` 识别构建。

参照为 [vernesong/mihomo Alpha 77af4804](https://github.com/vernesong/mihomo/tree/77af4804d091d89b871c99b52d50915f4a600d81) 的 `adapter/outboundgroup/smart.go`、`component/smart/` 和 Smart API。Smart 属于该扩展核心；这份迁移说明不代表 MetaCubeX 标准 Go 核心具备同一扩展。

当前 OpenWrt ARM64 交付文件为 `bin/mihomo-rust-openwrt-arm64-yacd-rules-fix`，附 `.gz` 和 `.sha256`。yacd 规则页修复见 `docs/rust-rewrite/yacd-rules-compatibility.md`；实时速度修复见 `docs/rust-rewrite/traffic-statistics.md`；域名映射及嗅探修复见 `docs/rust-rewrite/domain-routing.md` 和 `diagnostics/domain-routing-20261101/`；TUN / Huber 修复证据见 `diagnostics/openclash-tun-huber-20261101/`；高级能力迁移证据见 `diagnostics/smart-advanced-20261101/`。

## 配置与模型

现有代理节点及 provider 定义不需要改写。策略组可使用：

```yaml
proxy-groups:
  - name: 智能选择
    type: smart
    proxies: [节点A, 节点B]
    uselightgbm: true
    collectdata: false
    sample-rate: 1.0
    policy-priority: '节点A:1.2;节点B:1.0'
    prefer-asn: true
    tolerance: 20
    url: https://www.gstatic.com/generate_204
    interval: 300
    lazy: true

profile:
  store-selected: true
  smart-collector-size: 100

lgbm-auto-update: false
lgbm-update-interval: 72
lgbm-url: https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model.bin
```

`proxies` / `use` / `include-all` 等成员来源仍走现有组装逻辑。`policy-priority` 以分号分隔，按配置顺序匹配节点名，支持正则与字符串匹配。因子须大于零。`sample-rate` 有效区间为 `(0, 1]`，其他值采用上游默认 1；`collectdata` 为 true 才写采集文件。

核心在 `-d` 指定的数据目录中查找不区分大小写的 `Model.bin`，可以直接使用 OpenClash 下载的模型。该文件实际为 LightGBM 文本，并非需要 C 库加载的专有二进制格式。Rust 支持数值 / 类别分裂、缺失值分支，以及模型尾部的 StandardScaler / RobustScaler 参数。模型缺失或损坏时使用自适应公式继续选路，并尝试从配置的 URL 下载；下载支持重定向、核心路由及 TLS 证书验证。更新先完成解析校验，再替换文件和内存模型，失败保留已加载模型。

支持 `regression` 和 `huber` 目标。Huber 使用回归树叶值求和；包含参数的目标名称和附带缩放配置均可加载。原生 LightGBM 4.6.0 对两种 Huber 夹具共 320 组输入的比较最大误差为零。

本轮验证的发布模型 SHA-256 为 `23633022a815fb34e510befe1c176ba50af3ced48f08b172454f4cd6b8327788`，9,345,218 字节，557 棵树、30 个特征。特征提取还计算了新版本预留的 32 个槽位。

## 选路与反馈

- 未形成目标历史时，结合存活状态、健康检查延迟、优先因子和 tolerance 选择候选。
- 按目标与 TCP / UDP 分别记录连接结果、连接耗时、首字节延迟、流量、速率和持续时间；收集到足够样本后采用模型分数，模型不可用时采用自适应公式。
- 同一目标最近失败的节点进入冷却；TCP 最多选择十个候选，前三个顺序尝试，其余每批最多五个并行拨号。手动固定节点保持单一出口。
- UDP 排除不支持 UDP 的候选，记录实际数据收发；无回包的 UDP 会话不计为成功。会话结束后归并统计，长时间存活的会话不会每个包都生成一个训练样本。
- 后台健康检查遵守 interval / lazy；学习状态定期及正常关闭时保存到 `storage/smart-<配置名哈希>.json`。配置重载和进程重启可恢复统计。清缓存会同时更新磁盘状态。
- `collectdata: true` 的本地 CSV 为 `smart_weight_data.csv`，字段顺序兼容参考模型的 32 特征格式，并记录组、节点、原始目标、权重、来源及时间。文件受 `profile.smart-collector-size`（MiB）限制。

存在本地 `ASN.mmdb` / `Country.mmdb`（及常见 GeoLite2 文件名）时，从已有目标 IP、IP 字面量和 DNS 缓存提取 ASN / 国家特征，不为学习额外绕过 DNS 路由。`prefer-asn` 区分服务规则和广泛集合：保留实际匹配规则的身份及条目数，包含子规则、禁用规则和原始 GEOSITE/GEOIP 类型；国家、category、超过一万条或涉及至少六个非共享 ASN 的集合使用 ASN/站点键。公共后缀用于站点归并，共享云/CDN ASN 保留站点边界。服务认领要求至少两个网络或单个网络四次成功证据；所有权冲突不认领。TCP 与 UDP 分开保存。

## 竞速、响应与出口探测

- 自动模式使用前三个顺序拨号、随后每批最多五个的调度，最多十个候选。以出站传输建立结果为准，赢家的计划、统计及连接链一致。未发送的业务数据不会复制给其他候选；已失败的真实尝试正常反馈，取消的失败方不记为节点故障。稳定赢家缓存十分钟，失效后重新选择；缓存路径使用顺序回退。额外竞速线程最多十六个，预算用满时保留原有顺序拨号路径。
- VLESS 等延迟发送协议仍按自身传输语义发送首包，应用是否可达由真实流量和后续响应探测反馈。竞速完成不证明某个网站一定可访问。
- TCP 域名目标、端口 443、非内部连接且下载少于 0.03 MiB 时，后台通过同一节点及其代理链请求 `https://目标/robots.txt`，验证 TLS，不跟随重定向。验证码、限流、配额耗尽、地区拒绝、403/451、TLS 证书错误、超时及源站/边缘错误分别处理。普通跳转、405/501、421 不用于清除或制造可用证据；只有 2xx 是正向对照。
- 响应头限制 32 KiB、响应体限制 4096 字节、等待响应体一秒、整个任务八秒。每节点/目标通常间隔 120 秒，最近失败后 30 秒，每目标六次/分钟，全局 120 次/分钟、突发十次。三个拒绝且没有成功对照时暂停该主机探测三十分钟。
- 全局出口探测依次尝试 Cloudflare trace、ip.sb、ipwho.is；另尝试目标自己的 `/cdn-cgi/trace`。后者可识别 CDN/分流造成的目标专属出口。探测经已选择节点，出口元数据有效六小时，失败十五分钟后重试，体积限制 2048 字节。地区或 ASN 无法确认时保持未知。
- 地区/ASN 排除需要同一地区/ASN 的两个独立出口拒绝，以及另一个已知地区/ASN 的成功对照。同一出口 IP 的别名只计一次，普通跳转和验证码不形成地区证据。成功、到期和单节点半开尝试可恢复，手动固定优先于自动排除。
- 使用出口 IP 的 SHA-256 前六字节标识去重，仅保存哈希、地区和 ASN，不保存探测得到的原始出口 IP。规则/目标统计仍按原有设计保存目标信息。
- Linux `TCP_INFO` 采样物理 socket 的发送段数、重传数及 RTT，兼容字段长度检查。克隆流共享采样器，每满 64 段才释放一个增量窗口，一次消费；样本不足、计数重置、QUIC/不暴露物理 socket 的封装不会产生虚构的丢包证据。损失率、累计值和 EMA 进入权重；达到门槛后还需五分钟内第二次有效高损失证据才排除目标节点。TLS、REALITY、VLESS、Vision、VMess 等 TCP 封装可传递底层统计。
- 待处理探测最多 128 个，最多两个探测 I/O 任务并行；各类学习表最多 2048 项、规则证据每条最多 32 个网络，热目标候选缓存最多 128 项、六十秒。流量反馈、探测和模型变化会使候选缓存失效。清缓存、重载及关闭会取消旧探测，旧结果不能重新写回已清状态。

这些默认行为由 `type: smart` 启用，无需新增用户配置。`url` 仍是普通节点健康检查地址，不是上述网站内容探测地址。后台探测与健康检查、模型更新独立执行。

## API

所有 HTTP 写入及权重查询沿用控制器鉴权与 CORS 机制。

| 接口 | 行为 |
| --- | --- |
| `GET /proxies`、`GET /group` | 类型为 `Smart`；含 `useLightGBM`、`collectData`、`sampleRate`、`preferASN`、`policy-priority`、`tolerance` |
| `PUT /proxies/:name` | `{"name":"节点A"}` 手动固定节点 |
| `DELETE /proxies/:name` | 清除固定；自动模式 `now` 为 `Smart - Select` |
| `GET /group/:name/smart` | Rust 扩展诊断，展示探测、出口、地区/ASN 排除、竞速计数与队列状态；遵守控制器鉴权 |
| `GET /group/:name/weights` | `{"weights":[{"Name":"节点A","Rank":"MostUsed","Weight":100.0}]}`；冷启动无样本时数组为空 |
| `GET /group/weights` | 按组名返回权重表 |
| `POST /cache/smart/flush` | 清除内存状态及数据目录内所有配置的 Rust Smart 统计，返回 204 |
| `POST /cache/smart/flush/:config` | 按配置文件名（不含扩展名）清除，返回 204 |
| `POST /upgrade/lgbm` | 从配置的 lgbm-url 获取、校验并应用新模型，成功返回 204 |

权重接口保持原有字段和类型；新增诊断接口不替换 Clash 接口。模型更新间隔单位为小时，学习状态和采集文件保存在本地。

## 验证与范围

证据见 `diagnostics/smart-advanced-20261101/`；主要入口为 `scripts/smart-advanced-smoke.py`、`scripts/smart-response-fixtures.py`、`scripts/smart-model-verify.py` 和既有 UI/API、Smart、eBPF 回归脚本。

- 从固定 Go 版本提取原始分类函数，1,980 组状态码、限流头、HTTP 日期、地区内容及重定向输入与 Rust 分类结果一致。
- 本地真实 CONNECT/TLS 夹具验证快慢竞速、失败方回收、24 并发连接、候选上限、手动固定、地区独立证据、出口 trace 回退、证书校验、响应大小/时间限制、重启恢复及进行中探测的清除。
- 单元测试验证公共后缀、GEOSITE/GEOIP 原始身份、共享/冲突 ASN、过期恢复、探测节流、TCP_INFO 真 socket 和重传窗口门槛。既有 DNS、传输、重载、UDP、UI/API 及 eBPF 检查另行回归，结果以最终验证报告为准。
- 模型推理继续用独立 LightGBM 4.6.0 比较 160 组输入；保留上一轮数值提取与自适应公式证据。

Rust 使用有界内存状态和 JSON 持久化，没有迁移 Go Smart 的 BoltDB 文件格式及其整套后台数据库预取实现；现有 Rust 统计可升级读取，Go 缓存需要重新学习。探测并发、表容量和热目标缓存选择较小的路由器默认值，不声称逐项复刻 Go 的调度时序。Windows 不提供 Linux TCP_INFO；不暴露底层计数的协议保持未知。

Docker 夹具证明所列行为及回归结果；OpenWrt 真机、真实受限网站、长期选路收益和 Windows 实机仍需实际网络测试。
