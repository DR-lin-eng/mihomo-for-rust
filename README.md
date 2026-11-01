<h1 align="center">
  <img src="Meta.png" alt="Meta Kennel" width="200">
  <br>Meta Kernel<br>
</h1>

<h3 align="center">Another Mihomo Kernel.</h3>

<p align="center">
  <a href="https://github.com/MetaCubeX/mihomo/actions/workflows/build.yml">
    <img src="https://github.com/MetaCubeX/mihomo/actions/workflows/build.yml/badge.svg?branch=Alpha&style=flat-square" alt="Rust build workflow">
  </a>
  <a href="https://github.com/MetaCubeX/mihomo/actions/workflows/test.yml">
    <img src="https://github.com/MetaCubeX/mihomo/actions/workflows/test.yml/badge.svg?branch=Alpha&style=flat-square" alt="Rust test workflow">
  </a>
  <img src="https://img.shields.io/badge/rust-1.88%2B-cf6c3c?style=flat-square" alt="Rust 1.88+">
  <a href="https://github.com/MetaCubeX/mihomo/releases">
    <img src="https://img.shields.io/github/release/MetaCubeX/mihomo/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/MetaCubeX/mihomo">
    <img src="https://img.shields.io/badge/release-Meta-00b4f0?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, VLESS, Shadowsocks, Trojan, Snell, TUIC, Hysteria protocol support
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node
  based off latency
- Remote providers, allowing users to get node lists remotely instead of hard-coding in config
- Netfilter TCP redirecting. Deploy Mihomo on your Internet gateway with `iptables`.
- Comprehensive HTTP RESTful API controller

## Dashboard

A web dashboard with first-class support for this project has been created; it can be checked out at [metacubexd](https://github.com/MetaCubeX/metacubexd).

## Configration example

Configuration example is located at [/docs/config.yaml](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml).

## Docs

Documentation can be found in [mihomo Docs](https://wiki.metacubex.one/).

## For development

Requirements:
[Rust 1.88 or newer](https://www.rust-lang.org/tools/install)

Build mihomo:

```shell
git clone https://github.com/MetaCubeX/mihomo.git
cd mihomo
make build
```

Run the Rust workspace test suite:

```shell
make test
```

Build the Rust release matrix that matches the current Rust CI packaging names:

```shell
make rust-releases
```

This produces Rust artifacts such as `mihomo-linux-arm64-<version>.gz`, `mihomo-openwrt-arm64-<version>.gz`, `mihomo-darwin-arm64-<version>.gz`, and `mihomo-windows-amd64-v1-<version>.zip` under `bin/`.

To smoke-test the OpenWrt ARM64 package with a local config while forcing `tun: enable: false` in a temporary copy:

```shell
make openwrt-arm64-smoke CONFIG=/abs/path/to/config.yaml
```

To smoke-test the packaged OpenWrt ARM64 binary with a real TUN device and `NET_ADMIN` in Docker:

```shell
make openwrt-arm64-tun-smoke CONFIG=/abs/path/to/config.yaml
```

This requires the host Docker runtime to expose `/dev/net/tun`; otherwise the TUN-enabled startup path cannot be exercised.

To verify the packaged OpenWrt ARM64 binary fails with an actionable diagnostic when `/dev/net/tun` is unavailable:

```shell
make openwrt-arm64-missing-tun-smoke CONFIG=/abs/path/to/config.yaml
```

To perform a preflight check for a real OpenWrt deployment:

```shell
make openwrt-arm64-device-check CONFIG=/abs/path/to/config.yaml
```

To validate the copied OpenWrt core on a real device:

```shell
make openwrt-device-smoke CORE=/path/to/Clash.Core CONFIG=/path/to/config.yaml ARGS='--start'
```

This runs `-v`, `-t`, checks `/dev/net/tun` when `tun.enable: true`, optionally starts the core, verifies listeners from the real config, probes the mixed port through HTTP and SOCKS5, and fetches `/traffic` when the controller and secret are configured.

To upload a new package to a real device, validate it remotely, then atomically switch the live core with rollback support:

```shell
make openwrt-device-deploy HOST=root@192.168.1.1 ARGS='--activate --stop-cmd "/data/kano_plugins/clash/Proxy/Clash.Service stop" --start-cmd "/data/kano_plugins/clash/Proxy/Clash.Service start" --smoke-args "--start" --live-smoke-args "--running-service"'
```

If `PACKAGE` is omitted, the target uses `bin/mihomo-openwrt-arm64-<version>.gz` from the current checkout. A minimal example env template is included at [scripts/openwrt-device-deploy-example.env](scripts/openwrt-device-deploy-example.env).
For safety, `--stop-cmd` requires `--start-cmd`. If `--start-cmd` is set and `--live-smoke-args` is omitted, the deploy helper defaults the live verification pass to `--running-service`.

If SSH upload is unavailable, put `Clash.Core`, `scripts/openwrt-device-smoke.sh`, and `scripts/openwrt-device-install-local.sh` on the device, then run the installer from the device shell:

```shell
sh openwrt-device-install-local.sh --core ./Clash.Core
```

By default this uses `/data/kano_plugins/clash/Proxy/Clash.Core`, `/data/kano_plugins/clash/Proxy/config.yaml`, and `/data/kano_plugins/clash/Proxy/Clash.Service`. It validates the candidate, stops the service, smoke-tests the candidate, backs up the live core, activates the candidate, restarts the service, smoke-tests the running service, and rolls back on failure.

To locally validate the deploy helper without a real router, run the fake-remote integration test:

```shell
make openwrt-device-deploy-local-test
make openwrt-device-install-local-test
```

If `cargo` is not installed locally, `make build` and `make test` will fall back to Docker with the pinned minimal Rust 1.88 toolchain and isolated Docker target directories, so they do not contend with a local or concurrent Rust build for the same `target/` lock.
The `docker-*smoke` targets now depend on that build step as well, so `/work/bin/Clash.Core`
is refreshed from the current Rust sources before each smoke instead of silently reusing a stale
artifact.

For Linux TUN and transparent-routing verification, the repo now keeps the runtime checks split by scope:

```shell
make linux-tun-smoke
make docker-auto-redirect-smoke
make docker-auto-redirect-native-smoke
make docker-auto-redirect-lan-smoke
make docker-mixed-auto-redirect-lan-smoke
make docker-route-address-set-smoke
make docker-provider-tun-healthcheck-smoke
make docker-tun-fakeip-smoke
make docker-openwrt-like-provider-fakeip-lan-smoke
make docker-mixed-openwrt-like-provider-fakeip-lan-smoke
make docker-openwrt-like-tun-suite
make docker-mixed-openwrt-like-tun-suite
```

`docker-auto-redirect-smoke` verifies host-local `OUTPUT` redirection into `redir-port` with one
manual REDIRECT rule inserted by the smoke itself.
`docker-auto-redirect-native-smoke` is the stronger host-local variant: it skips that manual rule
and checks whether the core's own `tun auto-redirect` wiring is sufficient for host traffic.
`docker-auto-redirect-lan-smoke` is the stronger router-style check: it uses a simulated LAN client
namespace and verifies traffic from the `PREROUTING` path is actually redirected and proxied.
`docker-mixed-auto-redirect-lan-smoke` runs the same router-style check with `tun.stack: mixed`.
This validates the current Rust-only Linux `mixed` path, which still depends on
`auto-route + auto-redirect` and is not yet Go-equivalent `mixed` parity.
`docker-route-address-set-smoke` further narrows that to route-address-set coverage on the LAN side.
`docker-provider-tun-healthcheck-smoke` covers provider loading, controller-triggered healthcheck,
and TUN traffic through a provider-backed group.
`docker-tun-fakeip-smoke` covers fake-ip allocation, reverse lookup back to the original host, and
TUN TCP routing through a domain-based rule after the fake IP is assigned.
`docker-openwrt-like-provider-fakeip-lan-smoke` is the strongest single router-style check in the
repo right now: provider healthcheck, LAN-side fake-ip DNS allocation, and LAN-side fake-ip TCP
traffic through `tun auto-redirect` are exercised together.
`docker-mixed-openwrt-like-provider-fakeip-lan-smoke` runs that same combined smoke with
`tun.stack: mixed`, so the current Rust `mixed` runtime path is checked with provider healthcheck,
LAN DNS hijack, fake-ip recovery, and LAN-side TCP interception in one containerized flow.
`docker-openwrt-like-tun-suite` chains the stronger router-style checks together:
LAN `auto-redirect`, `route-address-set`, provider healthcheck + provider-backed TUN traffic, and
fake-ip domain-rule recovery through TUN, plus the combined provider+fake-ip+LAN smoke.
`docker-mixed-openwrt-like-tun-suite` is the smaller mixed-specific suite for the current Rust
`mixed` runtime path: it replays the LAN `auto-redirect` and provider+fake-ip+LAN combined checks
with `tun.stack: mixed` so mixed regressions can be exercised without claiming Go-parity.

The legacy Go implementation is still present for compatibility work and comparison, but it is no longer the default build path.

If a connection to GitHub is not possible when fetching Rust crates, set a cargo mirror or proxy appropriate for your environment.

To build the legacy Go entrypoint explicitly:

```shell
go mod download
go build -tags "legacy_go_runtime with_gvisor"
```

### IPTABLES configuration

Work on Linux OS which supported `iptables`

```yaml
# Enable the TPROXY listener
tproxy-port: 9898

iptables:
  enable: true # default is false
  inbound-interface: eth0 # detect the inbound interface, default is 'lo'
```

## Debugging

Check [wiki](https://wiki.metacubex.one/api/#debug) to get an instruction on using debug
API.

## Credits

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the GPL-3.0 license.

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**
