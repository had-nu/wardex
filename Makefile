.PHONY: all build test lint security clean

BINARY := wardex
PKG    := ./...

all: build

build:
	go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) .

test:
	go test -v -race -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out

lint:
	golangci-lint run $(PKG)

security:
	govulncheck $(PKG)
	gosec $(PKG)

clean:
	rm -rf bin/ coverage.out
