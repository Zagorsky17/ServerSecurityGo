# Сборка ServerSecurityGo. Все цели используют только стандартный Go.
#   make build        — бинарник для текущей ОС в bin/
#   make build-linux  — статические бинарники linux/amd64 и linux/arm64 в dist/
#   make test         — тесты (на Linux дополнительно проверяется настоящий /proc)
#   make demo         — веб-панель на демонстрационных данных: http://127.0.0.1:8090
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG     := ./cmd/serversecuritygo

.PHONY: build build-linux test vet fmt demo clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/serversecuritygo $(PKG)

build-linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/serversecuritygo-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/serversecuritygo-linux-arm64 $(PKG)
	cd dist && sha256sum serversecuritygo-linux-* > SHA256SUMS 2>/dev/null || shasum -a 256 serversecuritygo-linux-* > SHA256SUMS

test:
	go test -race ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Нужен gofmt:"; gofmt -l .; exit 1)

fmt:
	gofmt -w .

demo:
	go run $(PKG) demo

clean:
	rm -rf bin dist
