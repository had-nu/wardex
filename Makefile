.PHONY: all build test lint security specs reproducible clean golden golden-update

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

# Run the black-box golden harness (flows G1 to G10).
golden:
	go test -tags golden ./test/golden/...

# Rewrite want/ from the current binary. The change needs a Golden-Change
# trailer naming the ADR or issue that justifies the new expectation.
golden-update:
	GOLDEN_UPDATE=1 go test -tags golden ./test/golden/...

security:
	govulncheck $(PKG)
	gosec $(PKG)

# Build the release settings in separate git worktrees and compare digests.
# Reads its flags from .goreleaser.yaml, so it tracks the real release build.
reproducible:
	go run ./tools/verify-reproducible -n 2

clean:
	rm -rf bin/ coverage.out
