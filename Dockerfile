FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION
RUN CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X main.Version=${VERSION:-dev}" \
  -o /wardex .

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /wardex /wardex

# GitHub Actions mounts the workspace at /github/workspace.
# Setting WORKDIR ensures os.Getwd() returns the workspace root,
# so pathguard validation uses the correct base path.
WORKDIR /github/workspace

USER 65532:65532

ENTRYPOINT ["/wardex"]
