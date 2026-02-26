.PHONY: all build test lint clean

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

clean:
	rm -rf bin/ coverage.out
