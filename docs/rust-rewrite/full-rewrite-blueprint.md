# Rust Full Rewrite Blueprint

## Goal

Rebuild mihomo in Rust without changing the external surface area that users depend on today:

- Keep CLI flags and subcommands compatible with `main.go`.
- Keep config grammar and runtime behavior compatible with the current Go core.
- Keep listener, tunnel, DNS, rule, controller, and provider capabilities available across supported platforms.
- Shift the data plane toward zero-copy friendly primitives and platform-specific fast paths where the target OS allows it.

## Source Audit

The current Go tree is a full proxy core, not an API wrapper. The main evidence is:

- `main.go`: boot flags, config loading, version flow, `convert-ruleset`, `generate`, signal reload.
- `hub/` and `hub/executor/`: runtime assembly and controller integration.
- `listener/`: inbound listeners for HTTP, SOCKS, Mixed, Redir, TProxy, TUN, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria2, Sudoku, TrustTunnel, AnyTLS, and more.
- `tunnel/`: TCP and UDP dispatch, NAT, sniffing, statistics, process lookup hooks.
- `adapter/outbound*` and `transport/`: outbound proxy families and transport stacks.
- `.github/workflows/build.yml`: release coverage across Linux, Android, macOS, Windows, FreeBSD, plus legacy OS compatibility variants.

## Non-Negotiable Compatibility Contracts

- CLI contract:
  - `-d`, `-f`, `-config`, `-ext-ui`, `-ext-ctl`, `-ext-ctl-unix`, `-ext-ctl-pipe`, `-secret`, `-post-up`, `-post-down`, `-m`, `-v`, `-t`
  - subcommands `convert-ruleset` and `generate`
- Runtime contract:
  - config reload on `SIGHUP`
  - controller and external UI behavior
  - rule/provider update flow
  - DNS resolver and fake-IP semantics
  - statistics, NAT lifecycle, process attribution, sniffing
- Listener contract:
  - keep the existing inbound families and their metadata semantics
- Outbound contract:
  - keep proxy groups, outbound transports, and packet write-back behavior
- Platform contract:
  - Linux, Android, macOS, Windows, FreeBSD stay in scope
  - Linux low-end/OpenWrt style targets remain first-class, not afterthoughts

## Rewrite Workspace Shape

The new Rust workspace lives under `rust/` and mirrors the Go core by subsystem instead of by transport hot spot:

- `mihomo-app`: CLI compatibility layer
- `mihomo-runtime`: boot graph and subsystem assembly
- `mihomo-core`: compatibility manifest and subsystem inventory
- `mihomo-config`: boot/config entry contract
- `mihomo-api`: external controller and UI surface
- `mihomo-dns`: DNS, resolver, fake-IP, hosts integration
- `mihomo-inbound`: listener-facing contract
- `mihomo-outbound`: outbound adapter and group contract
- `mihomo-rules`: rules, providers, policy selection contract
- `mihomo-transport`: transport stack contract
- `mihomo-tun`: TUN, Redir, TProxy, transparent interception contract
- `mihomo-platform`: OS and target capability matrix
- `mihomo-buf`: zero-copy oriented buffer primitives

## Platform Notes

The Go release matrix is unusually wide. That creates two hard Rust-rewrite constraints:

1. CPU-profile variants such as `amd64-v1/v2/v3` are part of the shipping contract.
2. Several Linux/OpenWrt style outputs do not map cleanly to a single off-the-shelf Rust target triple.

Because of that, the Rust track must separate:

- public distribution outputs
- Rust target triples
- runtime CPU feature profiles
- optional fast-path features

This is why the first Rust platform crate stores named release profiles instead of pretending every Go output already has a one-to-one Rust target.

## Data Plane Direction

The current Go core already hints at the rewrite priorities:

- `common/net/sing.go` and `tunnel/connection.go` concentrate TCP and UDP relay behavior.
- `common/net/packet/*` and `WaitReadFrom()` expose packet-buffer lifetimes explicitly.
- Linux-specific interception depends on socket options, marks, transparent proxying, and process lookup.

The Rust rewrite should therefore standardize around:

- shared immutable packet payload storage
- slice/view based parsing instead of eager copies
- vectored IO where possible
- optional OS-specific accelerators behind capability gates

## Immediate Gaps Still Open

- The Rust workspace currently needs a newer stable toolchain baseline than the original scaffold assumed; cutover docs and CI must track the real MSRV instead of stale placeholders.
- The default runtime, CI, and development entrypoints have started moving toward Rust, but the full release matrix and Docker publishing path still retain a large Go compatibility lane.
- The repository still carries a legacy Go runtime path for compatibility and comparison; the cutover is not complete until release and runtime truth no longer depend on it by default.
- The default Rust mainline still needs a clear policy for heavyweight native dependencies such as vendored OpenSSL-backed SSH transport support; today those are better treated as explicit opt-in until the default build burden is acceptable.
- Legacy OS floors from the Go build matrix may require a separate Rust compatibility policy or custom toolchains.
