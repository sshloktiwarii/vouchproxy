.PHONY: build test-race fuzz audit snapshot clean

VERSION ?= 1.1.0
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -s -w \
	-X github.com/sshloktiwarii/vouchproxy/internal/version.Version=$(VERSION) \
	-X github.com/sshloktiwarii/vouchproxy/internal/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/sshloktiwarii/vouchproxy/internal/version.BuildDate=$(BUILD_DATE)

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/vouchproxy ./cmd/vouchproxy

test-race:
	go test -v -race ./...

fuzz:
	go test -v -run=^$$ ./...

audit:
	go vet ./...
	which govulncheck >/dev/null 2>&1 && govulncheck ./... || echo "govulncheck completed or not installed"

snapshot:
	@if command -v goreleaser >/dev/null 2>&1; then \
		goreleaser release --snapshot --clean; \
	else \
		echo "goreleaser not installed, building local snapshot binary via go..."; \
		$(MAKE) build; \
	fi

clean:
	rm -rf bin dist
