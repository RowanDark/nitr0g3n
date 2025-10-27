.PHONY: install build test clean help install-local run

# Default Go parameters
BINARY_NAME=nitr0g3n
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)

# Build information
VERSION?=dev
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS=-ldflags "-X github.com/RowanDark/nitr0g3n/cmd/nitro.Version=$(VERSION) \
                  -X github.com/RowanDark/nitr0g3n/cmd/nitro.GitCommit=$(GIT_COMMIT) \
                  -X github.com/RowanDark/nitr0g3n/cmd/nitro.BuildDate=$(BUILD_DATE)"

## help: Display this help message
help:
	@echo "Available targets:"
	@echo "  install     - Install nitr0g3n to GOPATH/bin"
	@echo "  install-local - Build and install to /usr/local/bin (requires sudo)"
	@echo "  build       - Build the binary to ./bin/"
	@echo "  test        - Run tests"
	@echo "  clean       - Remove built binaries"
	@echo "  run         - Build and run (use ARGS='--domain example.com')"

## install: Install to GOPATH/bin
install:
	@echo "Installing nitr0g3n to $(shell go env GOPATH)/bin..."
	@go install $(LDFLAGS) .
	@echo ""
	@echo "✓ Installation complete!"
	@echo ""
	@echo "If 'nitr0g3n --version' doesn't work, add Go's bin to your PATH:"
	@echo "  export PATH=\"\$$PATH:\$$(go env GOPATH)/bin\""
	@echo ""
	@echo "Add to ~/.bashrc or ~/.zshrc to make it permanent."

## install-local: Install to /usr/local/bin (requires sudo)
install-local: build
	@echo "Installing to /usr/local/bin (requires sudo)..."
	@sudo cp $(GOBIN)/$(BINARY_NAME) /usr/local/bin/
	@echo "✓ Installed to /usr/local/bin/$(BINARY_NAME)"

## build: Build binary to ./bin/
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(GOBIN)
	@go build $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) .
	@echo "✓ Built: $(GOBIN)/$(BINARY_NAME)"

## test: Run tests
test:
	@echo "Running tests..."
	@go test -v -cover ./...

## clean: Remove built binaries
clean:
	@echo "Cleaning..."
	@rm -rf $(GOBIN)
	@go clean
	@echo "✓ Cleaned"

## run: Build and run (use ARGS='--domain example.com')
run: build
	@$(GOBIN)/$(BINARY_NAME) $(ARGS)
