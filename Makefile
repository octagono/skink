# Skink build system — local compilation pipeline
#
# Build a single binary:         make
# Build all release variants:    make release
#
# Design principles:
# - Build provenance embedded in binary metadata
# - Checksums for every release artifact
# - Cross-compilation targets for common platforms

BINARY   := skink
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION := $(shell go version | cut -d' ' -f3)
BUILD_USER := $(shell whoami 2>/dev/null || echo "unknown")
BUILD_HOST := $(shell hostname 2>/dev/null || echo "unknown")

# LDFlags: strip debug info + inject build metadata
# Version lives in src/cli/cli.go (package cli), not main
LD_FLAGS := -s -w \
	-X github.com/octagono/skink/src/cli.Version=$(VERSION)

# Additional ldflags for release builds (more provenance)
RELEASE_LD_FLAGS := $(LD_FLAGS) \
	-X "main.BuildCommit=$(COMMIT)" \
	-X "main.BuildDate=$(DATE)" \
	-X "main.BuildGoVersion=$(GO_VERSION)"

# Output directory for release artifacts
RELEASE_DIR := ./build

# Architecture matrix for release builds
LINUX_ARCHS   := amd64 arm64 arm riscv64
DARWIN_ARCHS  := amd64 arm64
WINDOWS_ARCHS := amd64 arm64
# Linux 32-bit and less common architectures
LINUX_32_ARCHS := 386

.PHONY: all build build-tunnel build-transfer build-mcp \
        build-static release release-linux release-darwin release-windows \
        checksums clean test test-race sbom

all: build

# ──────────────────────────────────────────────
# Standard builds (development, quick iteration)
# ──────────────────────────────────────────────

# Full build (all features)
build:
	@echo "==> Building $(BINARY) $(VERSION)..."
	go build -ldflags='$(LD_FLAGS)' -o $(BINARY) .
	@echo "==> Done: $(BINARY)"

# Tunnel-only build (~2MB with UPX)
build-tunnel:
	@echo "==> Building tunnel-only binary..."
	go build -ldflags='$(LD_FLAGS)' -tags notransfer -o $(BINARY)-tunnel .
	@strip -s $(BINARY)-tunnel 2>/dev/null || true
	-upx --best --lzma $(BINARY)-tunnel 2>/dev/null
	@echo "==> Done: $(BINARY)-tunnel ($(shell du -sh $(BINARY)-tunnel 2>/dev/null | cut -f1))"
	@$(MAKE) checksum-file CHECKSUM_FILE=$(BINARY)-tunnel

# Transfer-only build (no tunnel features)
build-transfer:
	@echo "==> Building transfer-only binary..."
	go build -ldflags='$(LD_FLAGS)' -tags notunnel -o $(BINARY)-transfer .
	@strip -s $(BINARY)-transfer 2>/dev/null || true
	@echo "==> Done: $(BINARY)-transfer"
	@$(MAKE) checksum-file CHECKSUM_FILE=$(BINARY)-transfer

# MCP server binary for AI agent integration
build-mcp:
	@echo "==> Building MCP server..."
	go build -ldflags='-s -w -X main.Version=$(VERSION)' -o $(BINARY)-mcp ./cmd/mcp/
	@echo "==> Done: $(BINARY)-mcp"
	@$(MAKE) checksum-file CHECKSUM_FILE=$(BINARY)-mcp

# Static binary for minimal environments
build-static:
	CGO_ENABLED=0 go build -ldflags='-s -w $(LD_FLAGS) -extldflags=-static' -o $(BINARY)-static .
	@echo "==> Done: $(BINARY)-static"
	@$(MAKE) checksum-file CHECKSUM_FILE=$(BINARY)-static

# ──────────────────────────────────────────────
# Release builds (cross-platform matrix)
# ──────────────────────────────────────────────

# Build all release variants
release: clean-release release-linux release-darwin release-windows checksums

# Linux multi-arch release
release-linux:
	@echo "==> Linux release builds..."
	@mkdir -p $(RELEASE_DIR)/linux
	for arch in $(LINUX_ARCHS); do \
		echo "    linux/$$arch..."; \
		GOOS=linux GOARCH=$$arch go build -ldflags='$(RELEASE_LD_FLAGS)' \
			-o $(RELEASE_DIR)/linux/$(BINARY)-linux-$$arch .; \
		strip -s $(RELEASE_DIR)/linux/$(BINARY)-linux-$$arch 2>/dev/null || true; \
	done
	for arch in $(LINUX_32_ARCHS); do \
		echo "    linux/$$arch..."; \
		GOOS=linux GOARCH=$$arch go build -ldflags='$(RELEASE_LD_FLAGS)' \
			-o $(RELEASE_DIR)/linux/$(BINARY)-linux-$$arch .; \
		strip -s $(RELEASE_DIR)/linux/$(BINARY)-linux-$$arch 2>/dev/null || true; \
	done
	@echo "==> Linux release done"

# macOS release
release-darwin:
	@echo "==> macOS release builds..."
	@mkdir -p $(RELEASE_DIR)/darwin
	for arch in $(DARWIN_ARCHS); do \
		echo "    darwin/$$arch..."; \
		GOOS=darwin GOARCH=$$arch go build -ldflags='$(RELEASE_LD_FLAGS)' \
			-o $(RELEASE_DIR)/darwin/$(BINARY)-darwin-$$arch .; \
	done
	@echo "==> macOS release done"

# Windows release
release-windows:
	@echo "==> Windows release builds..."
	@mkdir -p $(RELEASE_DIR)/windows
	for arch in $(WINDOWS_ARCHS); do \
		echo "    windows/$$arch..."; \
		GOOS=windows GOARCH=$$arch go build -ldflags='$(RELEASE_LD_FLAGS)' \
			-o $(RELEASE_DIR)/windows/$(BINARY)-windows-$$arch.exe .; \
	done
	@echo "==> Windows release done"

# ──────────────────────────────────────────────
# SBOM & checksums
# ──────────────────────────────────────────────

# Generate SBOM (software bill of materials) for a binary
sbom:
	@echo "==> Generating SBOM..."
	@mkdir -p $(RELEASE_DIR)
	@echo "# Skink SBOM" > $(RELEASE_DIR)/SBOM.txt
	@echo "Version: $(VERSION)" >> $(RELEASE_DIR)/SBOM.txt
	@echo "Commit: $(COMMIT)" >> $(RELEASE_DIR)/SBOM.txt
	@echo "Build date: $(DATE)" >> $(RELEASE_DIR)/SBOM.txt
	@echo "Go version: $(GO_VERSION)" >> $(RELEASE_DIR)/SBOM.txt
	@echo "Build user: $(BUILD_USER)@$(BUILD_HOST)" >> $(RELEASE_DIR)/SBOM.txt
	@echo "" >> $(RELEASE_DIR)/SBOM.txt
	@echo "## Dependencies" >> $(RELEASE_DIR)/SBOM.txt
	@go version -m $(BINARY) 2>/dev/null >> $(RELEASE_DIR)/SBOM.txt || \
		echo "(build binary first with 'make build')" >> $(RELEASE_DIR)/SBOM.txt
	@echo "==> SBOM: $(RELEASE_DIR)/SBOM.txt"

# Generate SHA256 checksums for all release artifacts
checksums:
	@echo "==> Generating checksums..."
	@mkdir -p $(RELEASE_DIR)
	@rm -f $(RELEASE_DIR)/checksums.txt
	$(shell find $(RELEASE_DIR) -type f -name 'skink-*' | sort | \
		while read f; do \
			if [ -f "$$f" ]; then \
				sha256sum "$$f" >> $(RELEASE_DIR)/checksums.txt; \
			fi; \
		done)
	@echo "==> Checksums: $(RELEASE_DIR)/checksums.txt"

# Generate checksum for a single file
checksum-file:
	@if [ -f "$(CHECKSUM_FILE)" ]; then \
		mkdir -p $(RELEASE_DIR); \
		sha256sum "$(CHECKSUM_FILE)" >> $(RELEASE_DIR)/checksums.txt 2>/dev/null || true; \
	fi

# ──────────────────────────────────────────────
# Testing
# ──────────────────────────────────────────────

test:
	go test ./... -v -count=1 2>&1 | grep -v "^=== RUN\|^--- PASS\|^ok \|^? "

test-race:
	go test -race ./... -count=1 2>&1 | grep -v "^=== RUN\|^--- PASS\|^ok \|^? "

test-cover:
	go test -coverprofile=coverage.out ./... 2>&1 | grep -v "^ok \|^?"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'
	@rm -f coverage.out

# ──────────────────────────────────────────────
# Linting & code quality
# ──────────────────────────────────────────────

lint:
	golangci-lint run ./... 2>&1

vet:
	go vet ./... 2>&1

fmt:
	gofmt -l . 2>&1 || true

fmt-fix:
	gofmt -w . 2>&1

# Run fuzz tests for 30s each across all fuzz targets
fuzz:
	@echo "==> Running fuzz tests (30s each)..."
	@for pkg in ./src/tunnel ./src/comm ./src/mnemonicode; do \
		for target in $$(go test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "  $$pkg: $$target"; \
			go test -fuzz=$$target -fuzztime=30s -run xxx $$pkg 2>&1 | tail -3; \
		done; \
	done

# Run a single fuzz target for an extended duration
fuzz-long:
	@read -p "Package (e.g. ./src/tunnel): " pkg && \
	read -p "Fuzz target (e.g. FuzzParseStreamID): " target && \
	read -p "Duration (e.g. 10m): " dur && \
	go test -fuzz=$$target -fuzztime=$$dur -run xxx $$pkg

check: lint vet fmt

# ──────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────

clean:
	rm -f $(BINARY) $(BINARY)-tunnel $(BINARY)-transfer $(BINARY)-mcp $(BINARY)-static

clean-release:
	rm -rf $(RELEASE_DIR)

distclean: clean clean-release
