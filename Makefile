.PHONY: all build test lint security specs reproducible clean golden golden-update boundaries coverage-table

BINARY := wardex
PKG    := ./...

all: build

build:
	go build -trimpath -ldflags="-s -w -buildid=" -o bin/$(BINARY) .

test:
	go test -v -race -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out

lint:
	golangci-lint run $(PKG)

# Verify the canonical structure, inventory and vocabulary of the specs.
specs:
	go run ./tools/check-specs

# Check the import graph against doc/architecture/modules.yaml. Both build
# configurations run: without tags, and with grpc, which adds files the default
# build never sees.
boundaries:
	go run ./tools/check-boundaries
	go run ./tools/check-boundaries -tags grpc

# Run the black-box golden harness (flows G1 to G10). -count=1 disables the
# test cache: a case can embed the current date in its output, so a cached
# pass would hide a failure that appears later.
golden:
	go test -tags golden -count=1 ./test/golden/...

# Rewrite want/ from the current binary. The change needs a Golden-Change
# trailer naming the ADR or issue that justifies the new expectation.
golden-update:
	GOLDEN_UPDATE=1 go test -tags golden -count=1 ./test/golden/...

# Measure coverage per package. coverage.json is the input to the ratchet in
# P5; coverage.md is the human-readable table published by CI.
coverage-table:
	go test -coverprofile=coverage.out ./...
	go run ./tools/coverage-report -profile coverage.out -out coverage.md -json coverage.json

security:
	govulncheck $(PKG)
	gosec $(PKG)

# Build the release settings in separate git worktrees and compare digests.
# Reads its flags from .goreleaser.yaml, so it tracks the real release build.
reproducible:
	go run ./tools/verify-reproducible -n 2

clean:
	rm -rf bin/ coverage.out
