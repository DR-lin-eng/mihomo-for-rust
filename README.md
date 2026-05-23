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

If `cargo` is not installed locally, `make build` and `make test` will fall back to Docker with the pinned minimal Rust 1.88 toolchain and isolated Docker target directories, so they do not contend with a local or concurrent Rust build for the same `target/` lock.

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
