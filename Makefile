SHELL := /bin/bash

BINARY_NAME := nitro
CMD_PATH := ./cmd/nitro

VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test install clean

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) $(CMD_PATH)

test:
	go test -v -cover ./...

install:
	go install -ldflags "$(LDFLAGS)" $(CMD_PATH)

clean:
	rm -rf bin/
