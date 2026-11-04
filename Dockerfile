FROM rust:1.88 AS rust-builder
ARG TARGETARCH
WORKDIR /work
COPY rust/ rust/
RUN apt-get update && \
    apt-get install -y --no-install-recommends musl-tools && \
    rm -rf /var/lib/apt/lists/* && \
    case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-musl; linker_var=CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER ;; \
      arm64) rust_target=aarch64-unknown-linux-musl; linker_var=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER ;; \
      *) echo "unsupported Docker architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup target add "$rust_target" && \
    export "$linker_var=musl-gcc" && \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static" cargo build \
      --manifest-path rust/Cargo.toml -p mihomo-app --bin mihomo \
      --release --locked --target "$rust_target" && \
    cp "rust/target/$rust_target/release/mihomo" /mihomo

FROM alpine:latest AS assets
RUN apk add --no-cache wget && \
    mkdir /mihomo-config && \
    wget -O /mihomo-config/geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    wget -O /mihomo-config/geosite.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat && \
    wget -O /mihomo-config/geoip.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/MetaCubeX/mihomo"

RUN apk add --no-cache ca-certificates tzdata iptables

VOLUME ["/root/.config/mihomo/"]

COPY --from=assets /mihomo-config/ /root/.config/mihomo/
COPY --from=rust-builder /mihomo /mihomo
ENTRYPOINT [ "/mihomo" ]
