# TUN Implementation Audit

This note audits the current Rust TUN path in `metacubex-mihomo` against the upstream Go
`sing-tun` implementation, with selective structural references to
[`madeye/meow-rs`](https://github.com/madeye/meow-rs) only where it helps reduce trial-and-error.

It is intentionally scoped to the current repository state. This is not a design document and
not a promise of feature parity. It is a current-state evidence map.

## Scope

The audit covers four layers:

1. Config ingestion
2. TUN device and routing setup
3. TUN data plane
4. Native-support gating

It also classifies the main tun-related config fields into:

- `implemented`
- `partially implemented`
- `parsed but not implemented`
- `accepted but semantically not 1:1 with Go`

## Current verdict

The Rust TUN implementation is real and no longer limited to a minimal parser-only scaffold.
Several important Linux/OpenWrt-facing features are wired through and have Docker-backed proof:

- base Linux TUN device lifecycle
- `auto-route`
- `auto-detect-interface` at transport binding level
- `strict-route` rule generation
- `auto-redirect`
- `route-address-set`
- `route-exclude-address-set`

However, the implementation is still not 1:1 with upstream Go `sing-tun`.

The most important currently proven mismatch is now narrower than before:

- Rust `stack: system` can pass the current Linux Docker smokes, but it is still not Go
  `system` semantics

Go `system` stack does not run a user-space passive TCP stack for inbound TUN TCP. It rewrites
packets toward kernel TCP listeners. The current Rust implementation still uses the passive
smoltcp bridge in `tun_tcp_stack`, so even when the Linux smoke passes, the runtime model remains
different from Go.

The practical conclusion after the latest fixes is:

- the previous full-smoke failure was not caused by the TUN TCP bridge itself
- it was caused by a Rust config default mismatch: missing `mode` fell back to `COMPATIBLE`
- after restoring the upstream default `mode: rule`, the focused real-socket bridge regression and
  the full Docker Linux TUN smoke both pass
- semantic mismatch still remains for `stack: mixed`, Android package/user filters, and several
  Linux/OpenWrt-specific options listed below

## Evidence-backed runtime status

### Verified by Docker or focused runtime tests

- `mihomo-tun` Linux device smoke passes
  - opens `/dev/net/tun`
  - configures named device
  - configures addresses and link state

- `mihomo-app` Linux TUN app smoke passes
  - `start_with_linux_named_tun_device_smoke`
  - `tun_device_proxies_tcp_via_http_outbound_end_to_end`

- Docker smokes added in this branch family previously proved:
  - base TUN path via SOCKS5
  - `auto-redirect`
  - `route-address-set`
  - provider-backed TUN routing after controller-triggered healthcheck

- stronger Docker/runtime proofs now also exist for:
  - LAN-side `auto-redirect` through the `PREROUTING` path via a simulated client namespace
  - provider-backed TUN traffic after controller-triggered healthcheck
  - fake-ip allocation plus reverse lookup back into a domain-based TUN rule path
  - a combined router-style path where provider healthcheck, LAN fake-ip DNS allocation, and LAN
    fake-ip TCP traffic all succeed together

- focused regression passes:
  - `single_bridge_dispatches_tun_tcp_stream_through_real_http_proxy_socket`

### Verified by trace during current audit

Current `MIHOMO_TUN_TCP_TRACE=1` traces were used to prove two stages:

- before the mode fix, full Linux smoke selected `COMPATIBLE` instead of the configured `edge-http`
- after the mode fix, full Linux smoke selected `edge-http`, executed HTTP CONNECT, and completed

This is strong evidence that the most recent integrated failure was caused by config-default drift,
not by a fundamental break in the current Linux smoke path.

## Current Rust TUN structure

### 1. Config ingestion

Relevant files:

- `rust/crates/mihomo-inbound/src/models.rs`
- `rust/crates/mihomo-runtime/src/tun_surface.rs`

Current behavior:

- `TunInboundConfig` parses most upstream sing-tun fields, including:
  - `stack`
  - `dns-hijack`
  - `auto-route`
  - `auto-detect-interface`
  - `strict-route`
  - `auto-redirect`
  - `route-address-set`
  - `route-exclude-address-set`
  - interface / UID / port / package / MAC filter families
- `build_tun_runtime_specs()` constructs top-level and listener-level tun specs from
  `RuntimeConfigDocument`

Important limitation:

- parser coverage is broad
- runtime coverage is uneven
- several parsed fields are either Linux-only, Android-only, or still accepted without Go-equivalent
  semantics

### 2. TUN device and routing setup

Relevant files:

- `rust/crates/mihomo-tun/src/linux.rs`
- `rust/crates/mihomo-app/src/listener_service_runner.rs`
- `rust/crates/mihomo-transport/src/transport_types.rs`

Currently implemented:

- open `/dev/net/tun`
- configure interface name
- set MTU
- add IPv4 / IPv6 interface addresses
- bring link up
- install `auto-route` routes and policy rules
- apply Linux rule filters for:
  - `include-interface`
  - `exclude-interface`
  - `include-uid`
  - `include-uid-range`
  - `exclude-uid`
  - `exclude-uid-range`
  - `exclude-src-port`
  - `exclude-dst-port`
- install `strict-route` related rules
- detect default egress interface when `auto-detect-interface` is enabled
- bind transport sockets to the detected interface with `SO_BINDTODEVICE`
- apply routing marks via transport socket `SO_MARK`

Current caveats:

- `route-address-set` / `route-exclude-address-set` are implemented at the auto-redirect layer,
  not at the core route-table builder level
- Android package and user filters are not wired through the Rust side yet
- the current Linux route generation is materially closer to Go than before, but still not audited
  as byte-for-byte or rule-for-rule identical

### 3. TUN data plane

Relevant files:

- `rust/crates/mihomo-app/src/tun_worker.rs`
- `rust/crates/mihomo-app/src/tun_worker_loop.rs`
- `rust/crates/mihomo-app/src/tun_packet.rs`
- `rust/crates/mihomo-app/src/tun_tcp_stack.rs`
- `rust/crates/mihomo-runtime/src/tun_surface.rs`
- `rust/crates/mihomo-runtime/src/tcp.rs`
- `rust/crates/mihomo-runtime/src/tunnel_runtime.rs`

Currently implemented:

- spawn Linux TUN workers from runtime specs
- read raw IP frames from TUN fd
- parse UDP packets and relay them through `RuntimeTunnel`
- parse TCP packets and bridge them through a passive smoltcp TCP stack
- apply DNS hijack mapping to UDP metadata
- recover hostname from fake-ip reverse lookup before routing

Important current reality:

- there is only one real TCP interception engine in the Rust TUN path today
- that engine is the passive user-space TCP bridge in `tun_tcp_stack`
- there is no separate runtime implementation for Go `system`, Go `mixed`, and Go `gvisor`

That means:

- `TunStack::System` is accepted and now smoke-verified on Linux, but the semantics are still not
  the Go `system` stack
- `TunStack::Mixed` is parsed but is no longer treated as native-supported on Linux after the gate
  was restored to an honest state

Two current runtime caveats are especially important for reducing trial-and-error:

- non-Linux runtimes without `file-descriptor > 0` still do not open a native TUN device at all;
  `open_tun_reader_writer()` returns `Ok(None)` outside Linux unless an external fd is supplied
- UDP relay no longer blocks the TUN read loop directly; each parsed UDP packet is now handed to
  a separate blocking task that performs the `SystemUdpSession::recv_once()` round trip
- this removes the worst whole-device head-of-line stall, but the execution model is still not Go
  `gvisor`/`mixed` semantics and still pays per-packet blocking-task overhead

### 4. Native-support gating

Relevant files:

- `rust/crates/mihomo-app/src/native_support/listener_surface/protocols.rs`
- `rust/crates/mihomo-app/src/main_tests/support_and_surfaces_native_support.rs`

Current behavior:

- Linux native-support now accepts the subset that has at least code-path support and smoke proof:
  - `stack: system`
  - `auto-detect-interface`
  - `strict-route`
  - `auto-redirect`
  - `route-address-set`
- Linux native-support again rejects `stack: mixed`

Current caveat:

- `stack: system` being accepted means “current Rust Linux smoke path works”, not “Go-equivalent
  semantics are proven”

## Config field status map

### Field evidence matrix

| Field | Current status | Primary code path | Strongest current proof | Main remaining caveat |
| --- | --- | --- | --- | --- |
| `mode` default | implemented and aligned with Go | `mihomo-config/src/document.rs` | `runtime_config_document_defaults_mode_to_rule`; full `linux_tun_smoke` now selects `edge-http` instead of `COMPATIBLE` | none for the default itself |
| `stack: system` | implemented, smoke-verified, not Go-identical | `mihomo-app/src/tun_worker.rs`, `mihomo-app/src/tun_tcp_stack`, `mihomo-runtime/src/tun_surface.rs` | full Docker `linux_tun_smoke`; focused `single_bridge_dispatches_tun_tcp_stream_through_real_http_proxy_socket` | runtime model is still passive smoltcp TCP bridge, not Go kernel-listener rewrite |
| `stack: mixed` | parsed, honestly gated, not implemented | `mihomo-inbound/src/models.rs`; `mihomo-app/src/native_support/listener_surface/protocols.rs` | `tests::top_level_tun_mixed_stack_still_triggers_native_support_gap` | no distinct mixed runtime exists |
| `auto-route` | implemented | `mihomo-tun/src/linux.rs` | `linux_tun_setup_commands_include_auto_route_rules`; Linux TUN Docker smokes | not audited as rule-for-rule identical to Go |
| `auto-detect-interface` | implemented on Linux transport path | `mihomo-app/src/listener_service_runner.rs`; `mihomo-transport/src/transport_types.rs` | native-support test no longer flags it; socket default interface binding code exists | behavior is Linux-only and not fully parity-audited on all platforms |
| `strict-route` | implemented on Linux rule path | `mihomo-tun/src/linux.rs` | `linux_tun_setup_commands_include_linux_rule_filters`; native-support test no longer flags it | still not proven byte-for-byte equivalent to Go rule installation |
| `auto-redirect` | implemented on Linux | `mihomo-app/src/tun_auto_redirect.rs` | Docker `linux_tun_smoke`; `docker_auto_redirect_smoke=ok`; `docker_auto_redirect_native_smoke=ok`; `docker_auto_redirect_lan_smoke=ok` | output-mark/fallback-rule semantics remain incomplete and the accepted `system` stack is still not Go-identical |
| `route-address-set` | implemented, restart-based dynamic update | `mihomo-app/src/tun_auto_redirect.rs`; `mihomo-api/src/server.rs` | `docker_route_address_set_smoke=ok`; route-set unit tests; provider update restart hook | provider updates trigger restart, not in-place rule refresh |
| `route-exclude-address-set` | implemented at static load path | `mihomo-app/src/tun_auto_redirect.rs`; `mihomo-api/src/server.rs` | code path mirrors route-address-set and restart detection covers it | lacks dedicated Docker proof comparable to route-address-set |
| `include-interface` / `exclude-interface` | implemented on Linux | `mihomo-tun/src/linux.rs` | `linux_tun_setup_commands_include_linux_rule_filters` | current proof is rule-generation level, not dedicated end-to-end smoke |
| `include-uid` / `exclude-uid` | implemented on Linux | `mihomo-tun/src/linux.rs` | `linux_tun_setup_commands_include_linux_rule_filters` | no dedicated end-to-end UID routing smoke |
| `exclude-src-port` / `exclude-dst-port` | implemented on Linux | `mihomo-tun/src/linux.rs` | `linux_tun_setup_commands_include_linux_rule_filters` | no dedicated end-to-end port-filter smoke |
| `include-package` / `exclude-package` | parsed only | `mihomo-inbound/src/models.rs`; helper in `mihomo-tun/src/runtime_spec.rs` | no runtime integration proof | Android package-manager resolution path is still missing on Rust side |
| `include-android-user` | parsed only | `mihomo-inbound/src/models.rs` | no runtime integration proof | Android-specific UID expansion is not wired through |
| `include-mac-address` / `exclude-mac-address` | parsed only | `mihomo-inbound/src/models.rs` | no runtime integration proof | Linux nftables/mac filtering path is absent |
| `endpoint-independent-nat` | parsed only | `mihomo-inbound/src/models.rs` | no runtime integration proof | no Rust mixed/gvisor UDP NAT equivalent exists |
| `auto-redirect-output-mark` | partially implemented | `mihomo-app/src/tun_auto_redirect.rs`; `mihomo-transport/src/transport_types.rs` | `auto_redirect_mark_mode_options_translate_to_runtime_commands`; global/default routing mark support is now applied during install/uninstall | still lacks Go-equivalent nftables output routing and loopback reroute behavior |
| `auto-redirect-iproute2-fallback-rule-index` | partially implemented | `mihomo-app/src/tun_auto_redirect.rs` | `auto_redirect_mark_mode_options_translate_to_runtime_commands` | Linux fallback `ip rule` is emitted, but the surrounding Go mark-mode model is still incomplete |
| `loopback-address` | partially implemented | `mihomo-app/src/tun_worker_loop.rs`; `mihomo-app/src/tun_tcp_packet.rs`; `mihomo-app/src/tun_auto_redirect.rs` | `tun_fd_loop_rewrites_loopback_address_tcp_packets_back_to_source`; `auto_redirect_loopback_address_generates_output_mark_rules` | a minimal post-ingress TCP bounce plus an iptables-flavored output/prerouting/connmark command layer exist; upstream nftables reroute semantics and full Go `system` parity are still missing |
| `gso` / `gso-max-size` | parsed only | `mihomo-inbound/src/models.rs` | no runtime integration proof | no Linux TUN data-plane GSO handling exists in Rust |
| `recvmsgx` / `sendmsgx` | parsed only | `mihomo-inbound/src/models.rs` | no runtime integration proof | platform-specific fast path not wired in |

### Implemented

- `enable`
- `device`
- `dns-hijack`
- `udp-timeout`
- `auto-route`
- `mtu`
- `inet4-address`
- `inet6-address`
- `route-address`
- `route-exclude-address`
- `inet4-route-address`
- `inet6-route-address`
- `inet4-route-exclude-address`
- `inet6-route-exclude-address`
- `iproute2-table-index`
- `iproute2-rule-index`
- `include-interface`
- `exclude-interface`
- `include-uid`
- `include-uid-range`
- `exclude-uid`
- `exclude-uid-range`
- `exclude-src-port`
- `exclude-src-port-range`
- `exclude-dst-port`
- `exclude-dst-port-range`
- `auto-detect-interface`
- `strict-route`
- `auto-redirect`
- `route-address-set`
- `route-exclude-address-set`

### Partially implemented

- `fake-ip` interaction
  - reverse lookup and DNS mapping are implemented
  - Docker `docker_tun_fakeip_smoke=ok` proves the integrated local TUN TCP path recovers the
    original host and routes it through a domain-based rule
  - Docker `docker_openwrt_like_provider_fakeip_lan_smoke=ok` now also proves the stronger
    router-style combination: LAN fake-ip DNS query plus LAN fake-ip TCP traffic through
    provider-backed `tun auto-redirect`

- `auto-redirect-input-mark`
  - applied in iptables mark rules
  - integrated output-mark/fallback semantics are still incomplete compared with Go

- `auto-redirect-output-mark`
  - Linux iptables/ip-rule command generation is wired through
  - install/uninstall also applies and clears the default transport routing mark
  - nftables output-routing parity and loopback reroute behavior are still missing

- `auto-redirect-iproute2-fallback-rule-index`
  - Linux fallback `ip rule` command generation is wired through
  - still depends on the incomplete Rust mark-mode model above

- `loopback-address`
  - a minimal TCP-only loopback bounce now exists after TUN ingress
  - Linux `auto-redirect` now also emits `mangle/OUTPUT`, `CONNMARK --save-mark`, and `mangle/PREROUTING` rules for configured loopback targets
  - this is still not the upstream Go `system` model, because the Rust path does not yet match the nftables loopback reroute model or the full listener/NAT interaction

- `stack: system`
  - accepted and operational in limited scenarios
  - not Go `system` semantics

- `stack: mixed`
  - parsed
  - not a distinct mixed runtime implementation
  - honestly gated again on Linux native-support

### Parsed but not implemented or not wired through

- `stack: gvisor`
- `include-package`
- `exclude-package`
- `include-android-user`
- `include-mac-address`
- `exclude-mac-address`
- `endpoint-independent-nat`
- `disable-icmp-forwarding`
- `gso`
- `gso-max-size`
- `recvmsgx`
- `sendmsgx`

### `meow-rs` note

[`madeye/meow-rs`](https://github.com/madeye/meow-rs) remains useful as a structural reference for:

- splitting device lifecycle from packet processing
- documenting implementation gaps explicitly
- keeping routing setup and data-plane code separated

It is not a direct compatibility reference for Clash `tun.stack` semantics.
The authoritative behavioral target for `system` / `mixed` / `gvisor` remains upstream
`github.com/metacubex/sing-tun`.

### Accepted but semantically not 1:1 with Go

- `stack: system`
- `stack: mixed`
- dynamic `route-address-set` updates

Current dynamic `route-address-set` behavior:

- provider updates trigger `ApiControlCommand::Restart`
- this is a restart-based correctness path
- it is not Go’s in-place auto-redirect rule-set update behavior

## Why `stack: mixed` is again the clearest unsupported gap

The latest Linux smoke work removed one large source of confusion:

- the full Rust Linux TUN smoke now passes after restoring the upstream default `mode: rule`

That means the clearest remaining unsupported TUN runtime gap is once again:

- `stack: mixed`

Upstream Go `mixed` is not a config alias. It is a distinct runtime mode that combines system TCP
behavior with a gVisor-driven UDP path. The current Rust tree still has no separate mixed-stack
engine.

So the current `mixed` status is:

- parsed
- recognized
- honestly gated on Linux native-support
- not implemented as a distinct runtime

The native-support reporting behavior is also now more honest and more useful for config triage:

- Rust no longer needs a “fix one field, rerun, discover the next field” loop for top-level TUN
  support checks
- when one TUN config contains multiple unsupported fields, native-support now reports all current
  TUN gaps together instead of stopping at the first one
- Docker-backed proof exists via
  `top_level_tun_multiple_native_support_gaps_are_reported_together`
- the `-t` config-test path can now carry the native-support notice as part of the success output,
  so syntax validation no longer hides the fact that normal startup would still hit a TUN fallback
  or abort path
- the `-t` path now also emits a field-level top-level TUN audit for enabled TUN configs,
  marking the currently used TUN fields as `supported`, `supported-but-not-go-1:1`,
  `supported-restart-based`, or `gap` before listing the active native-support gaps

### Upstream `sing-tun` stack split, in concrete terms

Reading the current upstream Go dependency `github.com/metacubex/sing-tun@v0.4.18` removes a
common source of confusion around `stack`.

The upstream split is not:

- `system`, `mixed`, and `gvisor` all meaning roughly the same thing

The upstream split is:

- `system`
  - rewrites TCP packets toward kernel TCP listeners
  - relays UDP through direct packet handlers
  - handles ICMP echo forwarding explicitly and can disable that forwarding

- `gvisor`
  - runs TCP, UDP, and ICMP through a gVisor-backed netstack

- `mixed`
  - starts the `system` stack first
  - keeps the `system` TCP interception model
  - replaces only the UDP path with a gVisor/channel-backed UDP stack

Relevant upstream files:

- `stack.go`
- `stack_system.go`
- `stack_mixed.go`
- `stack_gvisor.go`

That means upstream Go `mixed` is specifically:

- system-style TCP
- gVisor UDP

It is not:

- a parser alias for `system`
- a no-op compatibility mode
- a fully separate TCP engine from `system`

This distinction matters for the Rust rewrite because the current Rust app still has:

- one passive smoltcp TCP bridge for TUN TCP
- one direct packet relay path for TUN UDP
- no gVisor-backed UDP path
- no kernel-listener rewrite TCP path

So the current Rust gap is not just “`mixed` missing by name”.
It is specifically missing the upstream `mixed` data-plane split.

## What can be borrowed from `meow-rs`

### Useful to borrow

1. Route and tunnel layering

Files:

- `crates/meow-tunnel/src/tunnel.rs`
- `crates/meow-listener/src/tproxy/mod.rs`

Useful ideas:

- isolate route-table and metadata normalization logic into a narrow tunnel core
- centralize fake-ip and DNS reverse mapping ahead of routing
- keep transparent listener entrypoints small and metadata-focused

2. Gap documentation discipline

File:

- `docs/gap-analysis.md`

Useful idea:

- maintain a live gap register with proof links instead of relying on chat history

### Not useful to borrow directly

`meow-rs` excludes tun inbound / tun VPN from scope, so it is not a drop-in answer for:

- tun device lifecycle
- `stack: system/mixed/gvisor`
- `auto-route`
- `strict-route`
- `auto-redirect`
- OpenWrt router semantics

Use `meow-rs` for structure, not for direct TUN semantics.

## Lowest-risk implementation order from current state

To reduce trial-and-error from the current real evidence, the recommended order is now:

1. Implement a distinct `mixed` runtime path or keep the restored honest gate
2. Upgrade restart-based `route-address-set` updates to in-place refresh
3. Wire Android package / user filter support
4. Revisit Linux/OpenWrt parity for `auto-redirect-output-mark`, fallback rules, and related marks

Rationale:

- the current Linux smoke path is no longer blocked on the previous default-mode bug
- `mixed` remains the clearest large semantic hole
- dynamic rule-set updates and Android filtering are still real feature-parity gaps

## Current recommendation for Rust-only configs

For low-risk Rust-only experiments today, the best evidence-backed statement is:

- Linux base TUN bring-up works
- current Linux `stack: system` smoke path works
- full Go-equivalent TUN semantics are still not proven

So avoid claiming parity for:

- `stack: mixed`
- Android package / user filtered TUN behavior
- full Go semantic equivalence for accepted `stack: system`

## Summary

- Current Rust TUN is real, non-trivial, and meaningfully implemented.
- Several important tun-related config fields are no longer parser-only.
- Docker-backed evidence shows device bring-up and some narrow relay paths work.
- Current Rust TUN is still not feature-parity with upstream Go `sing-tun`.
- The latest full Linux TUN smoke passes after restoring upstream-compatible default `mode: rule`.
- The clearest remaining large runtime gap is `stack: mixed`.
- `meow-rs` remains useful as a structural reference and not as a direct tun implementation guide.
