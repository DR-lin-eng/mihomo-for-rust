NAME=mihomo
BINDIR=bin
RUST_WORKDIR=rust
RUST_BIN=$(RUST_WORKDIR)/target/release/$(NAME)
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
CARGO_BUILD=cd $(RUST_WORKDIR) && cargo build -p mihomo-app --bin $(NAME) --release
CARGO_TEST=cd $(RUST_WORKDIR) && cargo test --workspace
RUST_RELEASE_TARGET=x86_64-unknown-linux-gnu
RUST_RELEASE_BIN=$(RUST_WORKDIR)/target/$(RUST_RELEASE_TARGET)/release/$(NAME)
CARGO_RELEASE_BUILD=cd $(RUST_WORKDIR) && cargo build -p mihomo-app --bin $(NAME) --release --target $(RUST_RELEASE_TARGET)
DOCKER_RUST=rust:1.88
DOCKER_BUILD_TARGET_DIR=/work/target-docker-build
DOCKER_TEST_TARGET_DIR=/work/target-docker-test
DOCKER_RELEASE_TARGET_DIR=/work/target-docker-release
DOCKER_CARGO_BUILD=docker run --rm -v "$$(pwd)/$(RUST_WORKDIR):/work" -w /work $(DOCKER_RUST) env CARGO_TARGET_DIR=$(DOCKER_BUILD_TARGET_DIR) cargo build -p mihomo-app --bin $(NAME) --release
DOCKER_CARGO_TEST=docker run --rm -v "$$(pwd)/$(RUST_WORKDIR):/work" -w /work $(DOCKER_RUST) env CARGO_TARGET_DIR=$(DOCKER_TEST_TARGET_DIR) cargo test --workspace
DOCKER_CARGO_RELEASE_BUILD=docker run --rm -v "$$(pwd)/$(RUST_WORKDIR):/work" -w /work $(DOCKER_RUST) env CARGO_TARGET_DIR=$(DOCKER_RELEASE_TARGET_DIR) cargo build -p mihomo-app --bin $(NAME) --release --target $(RUST_RELEASE_TARGET)

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

all: build

build:
	mkdir -p $(BINDIR)
	if command -v cargo >/dev/null 2>&1; then \
		$(CARGO_BUILD); \
	else \
		$(DOCKER_CARGO_BUILD); \
	fi
	if [ -f "$(RUST_BIN)" ]; then \
		cp $(RUST_BIN) $(BINDIR)/$(NAME); \
	else \
		cp $(RUST_WORKDIR)/target-docker-build/release/$(NAME) $(BINDIR)/$(NAME); \
	fi

test:
	if command -v cargo >/dev/null 2>&1; then \
		$(CARGO_TEST); \
	else \
		$(DOCKER_CARGO_TEST); \
	fi

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

vet: test

lint:
	golangci-lint run ./...

clean:
	rm $(BINDIR)/*

CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
