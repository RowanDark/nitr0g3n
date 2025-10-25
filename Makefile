SHELL := /bin/bash

BINARY_NAME := nitro
CMD_PATH := ./cmd/nitro
BIN_DIR := bin
BUILD_DIR := build
PROFILE := $(BUILD_DIR)/cpu.prof

VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
STRIPPED_LDFLAGS := $(LDFLAGS) -s -w
FAST_GCFLAGS := all=-B
FAST_ENV := GOEXPERIMENT=inlfuncswithclosures

.PHONY: build build-fast build-pgo build-race test install clean profile

build:
        mkdir -p $(BIN_DIR)
        go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PATH)

build-fast:
        mkdir -p $(BIN_DIR)
        $(FAST_ENV) go build -trimpath -ldflags "$(STRIPPED_LDFLAGS)" -gcflags "$(FAST_GCFLAGS)" -o $(BIN_DIR)/nitro-fast $(CMD_PATH)

profile:
        mkdir -p $(BUILD_DIR)
        $(FAST_ENV) go test -run '^$$' -count=1 -cpuprofile $(PROFILE) ./...

build-pgo: profile
        mkdir -p $(BIN_DIR)
        $(FAST_ENV) go build -trimpath -ldflags "$(LDFLAGS)" -pgo $(PROFILE) -o $(BIN_DIR)/nitro-pgo $(CMD_PATH)

build-race:
        mkdir -p $(BIN_DIR)
        go build -trimpath -race -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/nitro-debug $(CMD_PATH)

test:
        go test -v -cover ./...

install:
        go install -trimpath -ldflags "$(LDFLAGS)" $(CMD_PATH)

clean:
        rm -rf $(BIN_DIR)/ $(BUILD_DIR)/
