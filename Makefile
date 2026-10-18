.PHONY: all build test lint security reproducible clean

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

security:
	govulncheck $(PKG)
	gosec $(PKG)

# Build the release settings in separate git worktrees and compare digests.
# Reads its flags from .goreleaser.yaml, so it tracks the real release build.
reproducible:
	go run ./tools/verify-reproducible -n 2

clean:
	rm -rf bin/ coverage.out
