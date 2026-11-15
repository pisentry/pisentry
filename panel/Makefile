VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
IMAGE   ?= ghcr.io/pisentry/pisentry-panel
DIST    := internal/web/dist

.PHONY: all ui build test vet dist image

all: vet test ui build

# Builds the Vue app into the Go package that embeds it. Needs Node 22.
# Vite empties the output directory, so the placeholder is written back.
ui:
	cd web && npm ci --no-audit --no-fund && npm run build
	printf 'The built web UI goes here (make ui). Only this file is committed.\n' > $(DIST)/.gitkeep

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o pisentry-panel ./cmd/pisentry-panel

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)

test:
	go test -race ./...

# Run `make ui` first, or the binaries serve a placeholder page.
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64         go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pisentry-panel-linux-arm64 ./cmd/pisentry-panel
	CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pisentry-panel-linux-armv7 ./cmd/pisentry-panel
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64         go build -trimpath -ldflags "$(LDFLAGS)" -o dist/pisentry-panel-linux-amd64 ./cmd/pisentry-panel
	cd dist && sha256sum pisentry-panel-* > SHA256SUMS

image:
	docker buildx build --platform linux/arm64,linux/arm/v7,linux/amd64 \
		--build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) --push .
