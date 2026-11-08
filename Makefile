BINARY := temp-ssh-key
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build install test vet fmt fmt-check lint vuln check clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/$(BINARY)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	golangci-lint fmt

fmt-check:
	golangci-lint fmt --diff

lint:
	golangci-lint run

vuln:
	govulncheck ./...

check: fmt-check lint test vuln

clean:
	rm -rf bin dist
