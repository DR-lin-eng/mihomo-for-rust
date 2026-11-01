FROM rust:1.88
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm libbpf-dev bpftool iproute2 iptables python3 util-linux \
    && rm -rf /var/lib/apt/lists/*
