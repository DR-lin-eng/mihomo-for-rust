NAME=mihomo
BINDIR=bin
RUST_WORKDIR=rust
RUST_BIN=$(RUST_WORKDIR)/target-docker-build/release/$(NAME)
RUST_PACKAGE_TARGET_DIR=$(RUST_WORKDIR)/target-packages
RUST_PACKAGE_TARGET_DIR_ABS=$(CURDIR)/$(RUST_PACKAGE_TARGET_DIR)
RUSTFLAGS_BUILD_TIME=
BRANCH=$(shell git branch --show-current)
ifeq ($(BRANCH),Alpha)
VERSION=alpha-$(shell git rev-parse --short HEAD)
else ifeq ($(BRANCH),Beta)
VERSION=beta-$(shell git rev-parse --short HEAD)
else ifeq ($(BRANCH),)
VERSION=$(shell git describe --tags)
else
VERSION=$(shell git rev-parse --short HEAD)
endif

BUILDTIME=$(shell date -u)
LEGACY_GOBUILD=CGO_ENABLED=0 go build -tags "legacy_go_runtime with_gvisor" -trimpath -ldflags '-X "github.com/metacubex/mihomo/constant.Version=$(VERSION)" \
		-X "github.com/metacubex/mihomo/constant.BuildTime=$(BUILDTIME)" \
		-w -s -buildid='
CARGO_BUILD=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-codex-make-build --cargo-home .cargo-home-make-build -- cargo build -p mihomo-app --bin $(NAME) --release
CARGO_TEST=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-codex-make-test -- cargo test --workspace
RUST_RELEASE_TARGET=x86_64-unknown-linux-gnu
RUST_RELEASE_BIN=$(RUST_WORKDIR)/target-docker-release/$(RUST_RELEASE_TARGET)/release/$(NAME)
CARGO_RELEASE_BUILD=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-codex-make-release --cargo-home .cargo-home-make-release -- cargo build -p mihomo-app --bin $(NAME) --release --target $(RUST_RELEASE_TARGET)
RUST_PACKAGE_OUTPUTS = \
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-arm64 \
	openwrt-arm64 \
	darwin-amd64-v1 \
	darwin-amd64-v2 \
	darwin-amd64-v3 \
	darwin-arm64 \
	windows-amd64-v1 \
	windows-amd64-v2 \
	windows-amd64-v3
RUST_GZ_OUTPUTS=\
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-arm64 \
	openwrt-arm64 \
	darwin-amd64-v1 \
	darwin-amd64-v2 \
	darwin-amd64-v3 \
	darwin-arm64
RUST_ZIP_OUTPUTS=\
	windows-amd64-v1 \
	windows-amd64-v2 \
	windows-amd64-v3
DOCKER_RUST=rust:1.88
DOCKER_BUILD_TARGET_DIR=/work/target-docker-build
DOCKER_TEST_TARGET_DIR=/work/target-docker-test
DOCKER_RELEASE_TARGET_DIR=/work/target-docker-release
DOCKER_CARGO_BUILD=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-docker-build --cargo-home .cargo-home-docker-build -- cargo build -p mihomo-app --bin $(NAME) --release
DOCKER_CARGO_TEST=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-docker-test -- cargo test --workspace
DOCKER_CARGO_RELEASE_BUILD=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-docker-release --cargo-home .cargo-home-docker-release -- cargo build -p mihomo-app --bin $(NAME) --release --target $(RUST_RELEASE_TARGET)
DOCKER_OPENWRT_TARGET_DIR=/work/target-openwrt-docker
DOCKER_OPENWRT_TARGET_DIR_HOST=$$(pwd)/$(RUST_WORKDIR)/target-openwrt-docker
DOCKER_CARGO_OPENWRT_BUILD=sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-openwrt-docker --cargo-home .cargo-home-openwrt -- cargo build -p mihomo-app --bin $(NAME) --release --target aarch64-unknown-linux-musl
DOCKER_OPENWRT_SMOKE_IMAGE=alpine:latest
DOCKER_RUNTIME_SMOKE_IMAGE=rust:1.88
DOCKER_RUNTIME_SMOKE_INSTALL=apt-get update >/dev/null && apt-get install -y --no-install-recommends iproute2 iptables python3 util-linux curl >/dev/null
DOCKER_RUNTIME_SMOKE_RUN=docker run --rm --privileged -v "$$(pwd)":/work -w /work $(DOCKER_RUNTIME_SMOKE_IMAGE) /bin/bash -lc
DOCKER_LINUX_TUN_SMOKE_TARGET_DIR=/work/target-docker-linux-tun-smoke
DOCKER_LINUX_TUN_SMOKE_CARGO_HOME=/cargo-home
DOCKER_LINUX_TUN_SMOKE_CARGO_HOME_HOST=$$(pwd)/$(RUST_WORKDIR)/.cargo-home-linux-tun-smoke
DOCKER_LINUX_TUN_SMOKE_IMAGE=mihomo-linux-tun-smoke:local
DOCKER_CARGO_LINUX_TUN_SMOKE=docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun -v "$$(pwd)/$(RUST_WORKDIR):/work" -v "$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME_HOST):$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME)" -w /work $(DOCKER_LINUX_TUN_SMOKE_IMAGE) sh -lc 'export PATH=/usr/local/cargo/bin:$$PATH; CARGO_HOME=$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME) CARGO_TARGET_DIR=$(DOCKER_LINUX_TUN_SMOKE_TARGET_DIR) cargo test -p mihomo-app --test linux_tun_smoke -- --ignored --nocapture --test-threads=1'
DOCKER_CARGO_LINUX_TUN_SMOKE_FALLBACK=docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun -v "$$(pwd)/$(RUST_WORKDIR):/work" -v "$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME_HOST):$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME)" -w /work $(DOCKER_RUST) sh -lc 'export PATH=/usr/local/cargo/bin:$$PATH; apt-get update >/dev/null && apt-get install -y iproute2 >/dev/null && CARGO_HOME=$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME) CARGO_TARGET_DIR=$(DOCKER_LINUX_TUN_SMOKE_TARGET_DIR) cargo test -p mihomo-app --test linux_tun_smoke -- --ignored --nocapture --test-threads=1'
DOCKER_LINUX_TUN_CRATE_SMOKE_TARGET_DIR=/work/target-docker-linux-tun-crate-smoke
DOCKER_LINUX_TUN_CRATE_SMOKE_CARGO_HOME_HOST=$$(pwd)/$(RUST_WORKDIR)/.cargo-home-linux-tun-crate-smoke
DOCKER_CARGO_LINUX_TUN_CRATE_SMOKE=docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun -v "$$(pwd)/$(RUST_WORKDIR):/work" -v "$(DOCKER_LINUX_TUN_CRATE_SMOKE_CARGO_HOME_HOST):$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME)" -w /work $(DOCKER_LINUX_TUN_SMOKE_IMAGE) sh -lc 'export PATH=/usr/local/cargo/bin:$$PATH; CARGO_HOME=$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME) CARGO_TARGET_DIR=$(DOCKER_LINUX_TUN_CRATE_SMOKE_TARGET_DIR) cargo test -p mihomo-tun --test linux_device_smoke -- --ignored --nocapture --test-threads=1'
DOCKER_CARGO_LINUX_TUN_CRATE_SMOKE_FALLBACK=docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun -v "$$(pwd)/$(RUST_WORKDIR):/work" -v "$(DOCKER_LINUX_TUN_CRATE_SMOKE_CARGO_HOME_HOST):$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME)" -w /work $(DOCKER_RUST) sh -lc 'export PATH=/usr/local/cargo/bin:$$PATH; apt-get update >/dev/null && apt-get install -y iproute2 >/dev/null && CARGO_HOME=$(DOCKER_LINUX_TUN_SMOKE_CARGO_HOME) CARGO_TARGET_DIR=$(DOCKER_LINUX_TUN_CRATE_SMOKE_TARGET_DIR) cargo test -p mihomo-tun --test linux_device_smoke -- --ignored --nocapture --test-threads=1'

PLATFORM_LIST = \
	darwin-386 \
	darwin-amd64-compatible \
	darwin-amd64 \
	darwin-amd64-v1 \
	darwin-amd64-v2 \
	darwin-amd64-v3 \
	darwin-arm64 \
	linux-386 \
	linux-amd64-compatible \
	linux-amd64 \
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-armv5 \
	linux-armv6 \
	linux-armv7 \
	linux-arm64 \
	linux-mips64 \
	linux-mips64le \
	linux-mips-softfloat \
	linux-mips-hardfloat \
	linux-mipsle-softfloat \
	linux-mipsle-hardfloat \
	linux-riscv64 \
	linux-loong64 \
	android-arm64 \
	freebsd-386 \
	freebsd-amd64 \
	freebsd-arm64

WINDOWS_ARCH_LIST = \
	windows-386 \
	windows-amd64-compatible \
	windows-amd64 \
	windows-amd64-v1 \
	windows-amd64-v2 \
	windows-amd64-v3 \
	windows-arm64 \
    windows-arm32v7

.PHONY: all build test runtime-smoke-core linux-tun-smoke linux-tun-crate-smoke releases legacy-releases rust-all-arch rust-releases rust-openwrt-arm64 rust-openwrt-arm64.gz

all: build

build:
	mkdir -p $(BINDIR)
	if command -v cargo >/dev/null 2>&1; then \
		$(CARGO_BUILD); \
	else \
		$(DOCKER_CARGO_BUILD); \
	fi
	cp $(RUST_BIN) $(BINDIR)/$(NAME)
	cp $(BINDIR)/$(NAME) $(BINDIR)/Clash.Core

runtime-smoke-core: build

test:
	if command -v cargo >/dev/null 2>&1; then \
		$(CARGO_TEST); \
	else \
		$(DOCKER_CARGO_TEST); \
	fi

linux-tun-smoke:
	mkdir -p $(RUST_WORKDIR)/.cargo-home-linux-tun-smoke $(RUST_WORKDIR)/target-docker-linux-tun-smoke
	docker build -t $(DOCKER_LINUX_TUN_SMOKE_IMAGE) -f docker/linux-tun-smoke.Dockerfile . || true
	(if docker image inspect $(DOCKER_LINUX_TUN_SMOKE_IMAGE) >/dev/null 2>&1; then \
		$(DOCKER_CARGO_LINUX_TUN_SMOKE); \
	else \
		$(DOCKER_CARGO_LINUX_TUN_SMOKE_FALLBACK); \
	fi)

docker-auto-redirect-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-auto-redirect-smoke.sh --core /work/bin/Clash.Core'

docker-auto-redirect-native-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-auto-redirect-smoke.sh --core /work/bin/Clash.Core --native'

docker-auto-redirect-lan-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-auto-redirect-lan-smoke.sh --core /work/bin/Clash.Core'

docker-mixed-auto-redirect-lan-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-auto-redirect-lan-smoke.sh --core /work/bin/Clash.Core --stack mixed'

docker-route-address-set-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-route-address-set-smoke.sh --core /work/bin/Clash.Core'

docker-provider-tun-healthcheck-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-provider-tun-healthcheck-smoke.sh --core /work/bin/Clash.Core'

docker-tun-fakeip-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-tun-fakeip-smoke.sh --core /work/bin/Clash.Core'

docker-openwrt-like-provider-fakeip-lan-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-openwrt-like-provider-fakeip-lan-smoke.sh --core /work/bin/Clash.Core'

docker-mixed-openwrt-like-provider-fakeip-lan-smoke: runtime-smoke-core
	$(DOCKER_RUNTIME_SMOKE_RUN) '$(DOCKER_RUNTIME_SMOKE_INSTALL) && sh /work/scripts/docker-openwrt-like-provider-fakeip-lan-smoke.sh --core /work/bin/Clash.Core --stack mixed'

docker-openwrt-like-tun-suite:
	@$(MAKE) docker-auto-redirect-lan-smoke
	@$(MAKE) docker-route-address-set-smoke
	@$(MAKE) docker-provider-tun-healthcheck-smoke
	@$(MAKE) docker-tun-fakeip-smoke
	@$(MAKE) docker-openwrt-like-provider-fakeip-lan-smoke

docker-mixed-openwrt-like-tun-suite:
	@$(MAKE) docker-mixed-auto-redirect-lan-smoke
	@$(MAKE) docker-mixed-openwrt-like-provider-fakeip-lan-smoke

linux-tun-crate-smoke:
	mkdir -p $(RUST_WORKDIR)/.cargo-home-linux-tun-crate-smoke $(RUST_WORKDIR)/target-docker-linux-tun-crate-smoke
	docker build -t $(DOCKER_LINUX_TUN_SMOKE_IMAGE) -f docker/linux-tun-smoke.Dockerfile . || true
	(if docker image inspect $(DOCKER_LINUX_TUN_SMOKE_IMAGE) >/dev/null 2>&1; then \
		$(DOCKER_CARGO_LINUX_TUN_CRATE_SMOKE); \
	else \
		$(DOCKER_CARGO_LINUX_TUN_CRATE_SMOKE_FALLBACK); \
	fi)

go-build:
	$(LEGACY_GOBUILD)

go-test:
	GOCACHE=$(CURDIR)/.gocache GOMODCACHE=$(CURDIR)/.gomodcache go test ./... -tags "legacy_go_runtime"


darwin-all: darwin-amd64-v3 darwin-arm64

docker:
	mkdir -p $(BINDIR)
	if command -v cargo >/dev/null 2>&1; then \
		$(CARGO_RELEASE_BUILD); \
	else \
		$(DOCKER_CARGO_RELEASE_BUILD); \
	fi
	if [ -f "$(RUST_RELEASE_BIN)" ]; then \
		cp $(RUST_RELEASE_BIN) $(BINDIR)/$(NAME)-$@; \
	else \
		cp $(RUST_WORKDIR)/target-docker-release/$(RUST_RELEASE_TARGET)/release/$(NAME) $(BINDIR)/$(NAME)-$@; \
	fi

legacy-docker:
	GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-docker

darwin-386:
	GOARCH=386 GOOS=darwin $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-compatible:
	GOARCH=amd64 GOOS=darwin GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v1:
	GOARCH=amd64 GOOS=darwin GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v2:
	GOARCH=amd64 GOOS=darwin GOAMD64=v2 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-arm64:
	GOARCH=arm64 GOOS=darwin $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-386:
	GOARCH=386 GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-compatible:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v1:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v2:
	GOARCH=amd64 GOOS=linux GOAMD64=v2 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v3:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv5:
	GOARCH=arm GOOS=linux GOARM=5 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv7:
	GOARCH=arm GOOS=linux GOARM=7 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64:
	GOARCH=mips64 GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-riscv64:
	GOARCH=riscv64 GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-loong64:
	GOARCH=loong64 GOOS=linux $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

android-arm64:
	GOARCH=arm64 GOOS=android $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-386:
	GOARCH=386 GOOS=freebsd $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64:
	GOARCH=amd64 GOOS=freebsd GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-arm64:
	GOARCH=arm64 GOOS=freebsd $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@

windows-386:
	GOARCH=386 GOOS=windows $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-compatible:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v1:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v2:
	GOARCH=amd64 GOOS=windows GOAMD64=v2 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v3:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm64:
	GOARCH=arm64 GOOS=windows $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm32v7:
	GOARCH=arm GOOS=windows GOARM=7 $(LEGACY_GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

gz_releases=$(addsuffix .gz, $(PLATFORM_LIST))
zip_releases=$(addsuffix .zip, $(WINDOWS_ARCH_LIST))

$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe

legacy-all-arch: $(PLATFORM_LIST) $(WINDOWS_ARCH_LIST)

all-arch: legacy-all-arch

rust-all-arch: $(addprefix rust-,$(RUST_PACKAGE_OUTPUTS))

rust-releases: $(addprefix rust-,$(addsuffix .gz,$(RUST_GZ_OUTPUTS))) $(addprefix rust-,$(addsuffix .zip,$(RUST_ZIP_OUTPUTS)))

releases:
	mkdir -p $(BINDIR)
	if command -v cargo >/dev/null 2>&1; then \
		$(CARGO_RELEASE_BUILD); \
	else \
		$(DOCKER_CARGO_RELEASE_BUILD); \
	fi
	if [ -f "$(RUST_RELEASE_BIN)" ]; then \
		gzip -c $(RUST_RELEASE_BIN) > $(BINDIR)/$(NAME)-linux-amd64-v1-$(VERSION).gz; \
	else \
		gzip -c $(RUST_WORKDIR)/target-docker-release/$(RUST_RELEASE_TARGET)/release/$(NAME) > $(BINDIR)/$(NAME)-linux-amd64-v1-$(VERSION).gz; \
	fi

legacy-releases: $(gz_releases) $(zip_releases)

define declare_rust_gz_package
rust-$(1):
	@mkdir -p $(BINDIR)
	sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-packages --cargo-home .cargo-home-packages -- cargo build -p mihomo-app --bin $(NAME) --release --target $(2)
	cp $(RUST_PACKAGE_TARGET_DIR)/$(2)/release/$(4) $(BINDIR)/$(NAME)-$(1)

rust-$(1).gz: rust-$(1)
	chmod +x $(BINDIR)/$(NAME)-$(1)
	gzip -c $(BINDIR)/$(NAME)-$(1) > $(BINDIR)/$(NAME)-$(1)-$(VERSION).gz
	rm -f $(BINDIR)/$(NAME)-$(1)
endef

define declare_rust_zip_package
rust-$(1):
	@mkdir -p $(BINDIR)
	sh $(CURDIR)/scripts/docker-rust-test-clean.sh --target-dir target-packages --cargo-home .cargo-home-packages -- cargo build -p mihomo-app --bin $(NAME) --release --target $(2)
	cp $(RUST_PACKAGE_TARGET_DIR)/$(2)/release/$(4) $(BINDIR)/$(NAME)-$(1).exe

rust-$(1).zip: rust-$(1)
	zip -j $(BINDIR)/$(NAME)-$(1)-$(VERSION).zip $(BINDIR)/$(NAME)-$(1).exe
	rm -f $(BINDIR)/$(NAME)-$(1).exe
endef

$(eval $(call declare_rust_gz_package,linux-amd64-v1,x86_64-unknown-linux-gnu,,$(NAME)))
$(eval $(call declare_rust_gz_package,linux-amd64-v2,x86_64-unknown-linux-gnu,-C target-cpu=x86-64-v2,$(NAME)))
$(eval $(call declare_rust_gz_package,linux-amd64-v3,x86_64-unknown-linux-gnu,-C target-cpu=x86-64-v3,$(NAME)))
$(eval $(call declare_rust_gz_package,linux-arm64,aarch64-unknown-linux-gnu,,$(NAME)))
$(eval $(call declare_rust_gz_package,darwin-amd64-v1,x86_64-apple-darwin,,$(NAME)))
$(eval $(call declare_rust_gz_package,darwin-amd64-v2,x86_64-apple-darwin,-C target-cpu=x86-64-v2,$(NAME)))
$(eval $(call declare_rust_gz_package,darwin-amd64-v3,x86_64-apple-darwin,-C target-cpu=x86-64-v3,$(NAME)))
$(eval $(call declare_rust_gz_package,darwin-arm64,aarch64-apple-darwin,,$(NAME)))
$(eval $(call declare_rust_zip_package,windows-amd64-v1,x86_64-pc-windows-msvc,,$(NAME).exe))
$(eval $(call declare_rust_zip_package,windows-amd64-v2,x86_64-pc-windows-msvc,-C target-cpu=x86-64-v2,$(NAME).exe))
$(eval $(call declare_rust_zip_package,windows-amd64-v3,x86_64-pc-windows-msvc,-C target-cpu=x86-64-v3,$(NAME).exe))

rust-openwrt-arm64:
	@mkdir -p $(BINDIR) $(RUST_WORKDIR)/target-openwrt-docker
	$(DOCKER_CARGO_OPENWRT_BUILD)
	cp $(RUST_WORKDIR)/target-openwrt-docker/aarch64-unknown-linux-musl/release/$(NAME) $(BINDIR)/$(NAME)-openwrt-arm64

rust-openwrt-arm64.gz: rust-openwrt-arm64
	chmod +x $(BINDIR)/$(NAME)-openwrt-arm64
	gzip -c $(BINDIR)/$(NAME)-openwrt-arm64 > $(BINDIR)/$(NAME)-openwrt-arm64-$(VERSION).gz
	rm -f $(BINDIR)/$(NAME)-openwrt-arm64

openwrt-arm64-smoke:
	@if [ -z "$(CONFIG)" ]; then \
		echo "usage: make openwrt-arm64-smoke CONFIG=/abs/path/to/config.yaml"; \
		exit 2; \
	fi
	@tmpcfg=$$(mktemp -t mihomo-openwrt-smoke-config) && \
	awk 'BEGIN{in_tun=0} /^tun:/{in_tun=1; print; next} in_tun && /^[^[:space:]]/{in_tun=0} in_tun && /^  enable:/{sub(/true/,"false")} {print}' "$(CONFIG)" > "$$tmpcfg" && \
	docker run --rm --platform linux/arm64 -e MIHOMO_STARTUP_TRACE=1 -v "$$(pwd)/$(BINDIR):/artifacts:ro" -v "$$tmpcfg:/config.yaml:ro" $(DOCKER_OPENWRT_SMOKE_IMAGE) sh -lc 'apk add --no-cache coreutils iproute2 >/dev/null && gzip -dc /artifacts/$(NAME)-openwrt-arm64-$(VERSION).gz > /tmp/$(NAME) && chmod +x /tmp/$(NAME) && timeout -s TERM 20 /tmp/$(NAME) -f /config.yaml' ; \
	rm -f "$$tmpcfg"

openwrt-arm64-tun-smoke:
	@if [ -z "$(CONFIG)" ]; then \
		echo "usage: make openwrt-arm64-tun-smoke CONFIG=/abs/path/to/config.yaml"; \
		exit 2; \
	fi
	@controller=$$(awk '/^external-controller:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	secret=$$(awk '/^secret:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	mixed_port=$$(awk '/^mixed-port:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	if [ -z "$$controller" ] || [ -z "$$secret" ] || [ -z "$$mixed_port" ]; then \
		echo "smoke failed: config must define external-controller, secret, and mixed-port"; \
		exit 2; \
	fi; \
	controller_host=$${controller%:*}; \
	controller_port=$${controller##*:}; \
	docker run --rm --platform linux/arm64 --device /dev/net/tun --cap-add NET_ADMIN -e MIHOMO_STARTUP_TRACE=1 -e MIHOMO_SMOKE_CONTROLLER_HOST="$$controller_host" -e MIHOMO_SMOKE_CONTROLLER_PORT="$$controller_port" -e MIHOMO_SMOKE_SECRET="$$secret" -e MIHOMO_SMOKE_PROXY_PORT="$$mixed_port" -v "$$(pwd)/$(BINDIR):/artifacts:ro" -v "$(CONFIG):/config.yaml:ro" $(DOCKER_OPENWRT_SMOKE_IMAGE) sh -lc '\
		set -eux; \
		apk add --no-cache coreutils iproute2 curl >/dev/null; \
		gzip -dc /artifacts/$(NAME)-openwrt-arm64-$(VERSION).gz > /tmp/$(NAME); \
		chmod +x /tmp/$(NAME); \
		/tmp/$(NAME) -f /config.yaml > /tmp/$(NAME).log 2>&1 & \
		pid=$$!; \
		show_listeners() { \
			if command -v ss >/dev/null 2>&1; then ss -lntup; \
			elif command -v netstat >/dev/null 2>&1; then netstat -lntup; \
			else return 1; fi; \
		}; \
		proxy_code_ok() { \
			case "$$1" in 2??|3??|403) return 0 ;; *) return 1 ;; esac; \
		}; \
		ready=no; \
		for _ in 1 2 3 4 5 6; do \
			sleep 5; \
			if ! kill -0 $$pid 2>/dev/null; then \
				echo "smoke failed: mihomo exited before listeners were ready"; \
				cat /tmp/$(NAME).log; \
				exit 1; \
			fi; \
			if show_listeners 2>/dev/null | grep -q ":$${MIHOMO_SMOKE_PROXY_PORT}\\|:$${MIHOMO_SMOKE_CONTROLLER_PORT}"; then \
				ready=yes; \
				break; \
			fi; \
		done; \
		if [ "$$ready" != yes ]; then \
			echo "smoke failed: listeners $${MIHOMO_SMOKE_PROXY_PORT}/$${MIHOMO_SMOKE_CONTROLLER_PORT} did not appear"; \
			cat /tmp/$(NAME).log; \
			kill $$pid >/dev/null 2>&1 || true; \
			wait $$pid >/dev/null 2>&1 || true; \
			exit 1; \
		fi; \
		before=$$(curl -m 10 -s -H "Authorization: Bearer $${MIHOMO_SMOKE_SECRET}" http://$${MIHOMO_SMOKE_CONTROLLER_HOST}:$${MIHOMO_SMOKE_CONTROLLER_PORT}/traffic | head -n 1); \
		http_code=$$(curl -x http://127.0.0.1:$${MIHOMO_SMOKE_PROXY_PORT} -m 20 -s -o /dev/null -w "%{http_code}" http://www.gstatic.com/generate_204); \
		socks_code=$$(curl --socks5-hostname 127.0.0.1:$${MIHOMO_SMOKE_PROXY_PORT} -m 20 -s -o /dev/null -w "%{http_code}" http://www.gstatic.com/generate_204); \
		after=""; \
		for _ in 1 2 3 4 5; do \
			sleep 1; \
			after=$$(curl -m 10 -s -H "Authorization: Bearer $${MIHOMO_SMOKE_SECRET}" http://$${MIHOMO_SMOKE_CONTROLLER_HOST}:$${MIHOMO_SMOKE_CONTROLLER_PORT}/traffic | head -n 1); \
			if [ "$$after" != "$$before" ]; then \
				break; \
			fi; \
		done; \
		echo "traffic_before=$$before"; \
		echo "proxy_http_code=$$http_code"; \
		echo "proxy_socks5_code=$$socks_code"; \
		echo "traffic_after=$$after"; \
		kill $$pid >/dev/null 2>&1 || true; \
		wait $$pid >/dev/null 2>&1 || true; \
		tail -n 5 /tmp/$(NAME).log; \
		proxy_code_ok "$$http_code" || { echo "smoke failed: unexpected proxy http code $$http_code"; exit 1; }; \
		proxy_code_ok "$$socks_code" || { echo "smoke failed: unexpected proxy socks5 code $$socks_code"; exit 1; }; \
		[ "$$after" != "$$before" ] || { echo "smoke failed: traffic totals did not increase"; exit 1; }'

openwrt-arm64-missing-tun-smoke:
	@if [ -z "$(CONFIG)" ]; then \
		echo "usage: make openwrt-arm64-missing-tun-smoke CONFIG=/abs/path/to/config.yaml"; \
		exit 2; \
	fi
	docker run --rm --platform linux/arm64 -e MIHOMO_STARTUP_TRACE=1 -v "$$(pwd)/$(BINDIR):/artifacts:ro" -v "$(CONFIG):/config.yaml:ro" $(DOCKER_OPENWRT_SMOKE_IMAGE) sh -lc '\
		set -eux; \
		apk add --no-cache coreutils >/dev/null; \
		gzip -dc /artifacts/$(NAME)-openwrt-arm64-$(VERSION).gz > /tmp/$(NAME); \
		chmod +x /tmp/$(NAME); \
		set +e; \
		output=$$(/tmp/$(NAME) -f /config.yaml 2>&1); \
		status=$$?; \
		set -e; \
		echo "$$output"; \
		[ $$status -ne 0 ] || { echo "smoke failed: expected non-zero exit without /dev/net/tun"; exit 1; }; \
		echo "$$output" | grep -q "/dev/net/tun" || { echo "smoke failed: expected tun guidance in error output"; exit 1; }; \
		echo "$$output" | grep -q "CAP_NET_ADMIN" || { echo "smoke failed: expected CAP_NET_ADMIN guidance in error output"; exit 1; }'

openwrt-arm64-device-check:
	@if [ -z "$(CONFIG)" ]; then \
		echo "usage: make openwrt-arm64-device-check CONFIG=/abs/path/to/config.yaml"; \
		exit 2; \
	fi
	@controller=$$(awk '/^external-controller:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	secret=$$(awk '/^secret:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	mixed_port=$$(awk '/^mixed-port:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	redir_port=$$(awk '/^redir-port:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	tproxy_port=$$(awk '/^tproxy-port:/{sub(/^[^:]+:[[:space:]]*/,""); gsub(/"/,""); print; exit}' "$(CONFIG)"); \
	tun_enabled=$$(awk 'BEGIN{in_tun=0} /^tun:/{in_tun=1; next} in_tun && /^[^[:space:]]/{in_tun=0} in_tun && /^  enable:/{line=$$0; sub(/^[^:]+:[[:space:]]*/,"",line); sub(/[[:space:]]*#.*/,"",line); gsub(/"/,"",line); print line; exit}' "$(CONFIG)"); \
	echo "config=$(CONFIG)"; \
	echo "external-controller=$$controller"; \
	echo "secret_present=$$( [ -n "$$secret" ] && echo yes || echo no )"; \
	echo "mixed-port=$$mixed_port"; \
	echo "redir-port=$$redir_port"; \
	echo "tproxy-port=$$tproxy_port"; \
	echo "tun.enable=$$tun_enabled"; \
	[ -n "$$controller" ] || { echo "check failed: external-controller missing"; exit 1; }; \
	[ -n "$$secret" ] || { echo "check failed: secret missing"; exit 1; }; \
	[ -n "$$mixed_port" ] || { echo "check failed: mixed-port missing"; exit 1; }; \
	if [ "$$tun_enabled" = true ]; then \
		docker run --rm --platform linux/arm64 --device /dev/net/tun --cap-add NET_ADMIN alpine:latest sh -lc 'ls -l /dev/net/tun >/dev/null && echo tun_device=ok && cat /proc/self/status | grep CapEff'; \
	else \
		echo "tun disabled in config; /dev/net/tun not required for startup"; \
	fi

openwrt-device-smoke:
	@if [ -z "$(CORE)" ] || [ -z "$(CONFIG)" ]; then \
		echo "usage: make openwrt-device-smoke CORE=/path/to/Clash.Core CONFIG=/path/to/config.yaml [ARGS='--start']"; \
		exit 2; \
	fi
	@chmod +x scripts/openwrt-device-smoke.sh
	@sh scripts/openwrt-device-smoke.sh --core "$(CORE)" --config "$(CONFIG)" $(ARGS)

openwrt-device-deploy:
	@if [ -z "$(HOST)" ]; then \
		echo "usage: make openwrt-device-deploy HOST=user@device [PACKAGE=bin/$(NAME)-openwrt-arm64-$(VERSION).gz|CORE=/path/to/Clash.Core] [ARGS='--activate --stop-cmd ... --start-cmd ... --smoke-args \"--start\" --live-smoke-args \"--running-service\"']"; \
		exit 2; \
	fi
	@chmod +x scripts/openwrt-device-deploy.sh scripts/openwrt-device-smoke.sh
	@if [ -n "$(CORE)" ]; then \
		sh scripts/openwrt-device-deploy.sh --host "$(HOST)" --core "$(CORE)" $(if $(PORT),--port "$(PORT)") $(ARGS); \
	elif [ -n "$(PACKAGE)" ]; then \
		sh scripts/openwrt-device-deploy.sh --host "$(HOST)" --package "$(PACKAGE)" $(if $(PORT),--port "$(PORT)") $(ARGS); \
	else \
		sh scripts/openwrt-device-deploy.sh --host "$(HOST)" --package "$(BINDIR)/$(NAME)-openwrt-arm64-$(VERSION).gz" $(if $(PORT),--port "$(PORT)") $(ARGS); \
	fi

openwrt-device-deploy-local-test:
	@chmod +x scripts/openwrt-device-deploy.sh scripts/openwrt-device-smoke.sh scripts/openwrt-device-deploy-local-test.sh
	@sh scripts/openwrt-device-deploy-local-test.sh

openwrt-device-install-local-test:
	@tmp=$$(mktemp -d /tmp/mihomo-openwrt-install-test.XXXXXX) && \
	trap 'rm -rf "$$tmp"' EXIT INT TERM && \
	mkdir -p "$$tmp/data/kano_plugins/clash/Proxy" && \
	printf '#!/bin/sh\nif [ "$$1" = "-v" ]; then echo new-core; exit 0; fi\nif [ "$$1" = "-t" ]; then echo config ok; exit 0; fi\nexit 0\n' > "$$tmp/new-core" && \
	printf '#!/bin/sh\nif [ "$$1" = "-v" ]; then echo old-core; exit 0; fi\nif [ "$$1" = "-t" ]; then echo config ok; exit 0; fi\nexit 0\n' > "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" && \
	printf 'mixed-port: 7890\nexternal-controller: 127.0.0.1:7788\nsecret: test\n' > "$$tmp/data/kano_plugins/clash/Proxy/config.yaml" && \
	printf '#!/bin/sh\necho smoke $$*\nexit 0\n' > "$$tmp/openwrt-device-smoke.sh" && \
	chmod +x "$$tmp/new-core" "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" "$$tmp/openwrt-device-smoke.sh" && \
	chmod +x scripts/openwrt-device-install-local.sh && \
	sh scripts/openwrt-device-install-local.sh --core "$$tmp/new-core" --remote-core "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" --config "$$tmp/data/kano_plugins/clash/Proxy/config.yaml" --smoke-script "$$tmp/openwrt-device-smoke.sh" --stop-cmd "true" --start-cmd "true" && \
	grep -q new-core "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" && \
	printf '#!/bin/sh\nexit 1\n' > "$$tmp/fail-start" && chmod +x "$$tmp/fail-start" && \
	cp "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core.before-fail" && \
	! sh scripts/openwrt-device-install-local.sh --core "$$tmp/new-core" --remote-core "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" --config "$$tmp/data/kano_plugins/clash/Proxy/config.yaml" --smoke-script "$$tmp/openwrt-device-smoke.sh" --stop-cmd "true" --start-cmd "$$tmp/fail-start" --skip-smoke && \
	cmp "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core.before-fail" "$$tmp/data/kano_plugins/clash/Proxy/Clash.Core" >/dev/null && \
	echo "local_install_test=ok"

vet: test

lint:
	golangci-lint run ./...

clean:
	rm $(BINDIR)/*

CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
