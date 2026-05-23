FROM rust:1.88 as rust-builder
WORKDIR /work
COPY rust/ rust/
RUN cargo build --manifest-path rust/Cargo.toml -p mihomo-app --bin mihomo --release

FROM alpine:latest as assets
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
COPY --from=rust-builder /work/rust/target/release/mihomo /mihomo
ENTRYPOINT [ "/mihomo" ]
