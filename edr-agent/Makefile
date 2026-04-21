BINARY    = edr-agent
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT = $(shell git log -1 --format=%H 2>/dev/null || echo unknown)
GIT_BRANCH = $(shell git symbolic-ref --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME = $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
VER_PKG    = github.com/youredr/edr-agent/internal/version
LDFLAGS    = -ldflags "\
  -X $(VER_PKG).Version=$(VERSION) \
  -X $(VER_PKG).GitCommit=$(GIT_COMMIT) \
  -X $(VER_PKG).GitBranch=$(GIT_BRANCH) \
  -X $(VER_PKG).BuildTime=$(BUILD_TIME) \
  -X github.com/youredr/edr-agent/internal/agent.Version=$(VERSION) \
  -w -s"
BPF_CC    = clang
ARCH     ?= x86

KERN_HEADERS ?= /usr/include/$(shell uname -m)-linux-gnu
ifeq ($(wildcard $(KERN_HEADERS)/asm),)
  KERN_HEADERS = /usr/include
endif
LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include/bpf")
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I$(KERN_HEADERS) -Iebpf $(LIBBPF_CFLAGS)

GOBIN      := $(shell go env GOPATH 2>/dev/null)/bin
BPF2GO     := $(shell command -v bpf2go 2>/dev/null || echo "$(GOBIN)/bpf2go")
LLVM_STRIP := $(shell \
  command -v llvm-strip 2>/dev/null || \
  ls /usr/bin/llvm-strip-* 2>/dev/null | sort -t- -k3 -n | tail -1 || \
  command -v strip 2>/dev/null || echo "strip")

BPF_SRCS = $(wildcard ebpf/*/*.bpf.c)
BPF_OBJS = $(BPF_SRCS:.bpf.c=.bpf.o)

.PHONY: all ebpf vmlinux generate build run install clean test lint check-deps help

all: check-deps vmlinux ebpf generate build

check-deps:
	@echo "==> Checking build dependencies..."
	@command -v clang >/dev/null 2>&1 || { echo "ERROR: clang not found. apt-get install clang"; exit 1; }
	@command -v go    >/dev/null 2>&1 || { echo "ERROR: go not found. apt-get install golang-go"; exit 1; }
	@command -v bpftool >/dev/null 2>&1 || echo "WARN: bpftool not found. apt-get install linux-tools-common"
	@command -v llvm-strip >/dev/null 2>&1 || \
	  ls /usr/bin/llvm-strip-* >/dev/null 2>&1 || \
	  echo "WARN: llvm-strip not found. apt-get install llvm"
	@( pkg-config --exists libbpf 2>/dev/null \
	   || test -f /usr/include/bpf/bpf_helpers.h \
	   || test -f /usr/local/include/bpf/bpf_helpers.h ) \
	  || { echo "ERROR: libbpf headers not found. apt-get install libbpf-dev"; exit 1; }
	@GO_VER=$$(go version | awk '{print $$3}' | sed 's/go//'); \
	 python3 -c "import sys; v='$$GO_VER'.split('.'); sys.exit(0 if (int(v[0]),int(v[1])) >= (1,21) else 1)" \
	  || { echo "ERROR: Go >= 1.21 required. Got: $$GO_VER"; exit 1; }
	@echo "==> OK"

vmlinux: ebpf/vmlinux.h

ebpf/vmlinux.h:
	@echo "==> Generating vmlinux.h..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@; \
		echo "==> vmlinux.h written"; \
	elif [ -f $@ ]; then \
		echo "==> Using existing $@"; \
	else \
		echo "ERROR: /sys/kernel/btf/vmlinux not found."; exit 1; \
	fi

ebpf: $(BPF_OBJS)
	@echo "==> eBPF compile done"

%.bpf.o: %.bpf.c ebpf/vmlinux.h
	@echo "  CC  $<"
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

generate:
	@echo "==> Running go generate (bpf2go)..."
	@echo "    llvm-strip : $(LLVM_STRIP)"
	@echo "    bpf2go     : $(BPF2GO)"
	@if [ ! -x "$(BPF2GO)" ]; then \
		echo "  installing bpf2go@v0.16.0 ..."; \
		go install github.com/cilium/ebpf/cmd/bpf2go@v0.16.0; \
	fi
	@rm -f gen.go
	@PROJ="$$(pwd)"; \
	 printf 'package process\n//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I'"'"'%s/ebpf'"'"' -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" Process %s/ebpf/process/process.bpf.c\n' "$$PROJ" "$$PROJ" > internal/monitor/process/gen.go; \
	 printf 'package network\n//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I'"'"'%s/ebpf'"'"' -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" Network %s/ebpf/network/network.bpf.c\n' "$$PROJ" "$$PROJ" > internal/monitor/network/gen.go; \
	 printf 'package file\n//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I'"'"'%s/ebpf'"'"' -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" File %s/ebpf/file/file.bpf.c\n' "$$PROJ" "$$PROJ" > internal/monitor/file/gen.go
	@echo "  per-package gen.go files written with absolute paths"
	BPF2GO_STRIP="$(LLVM_STRIP)" PATH="$(GOBIN):$$PATH" go generate ./internal/monitor/...

build:
	@echo "==> Tidying Go modules..."
	go mod tidy
	@echo "==> Building $(BINARY) ($(VERSION))..."
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(BINARY) ./cmd/agent
	@echo "==> ./$(BINARY) ready"

run: build
	sudo ./$(BINARY) --config config/agent.yaml

install: build
	sudo install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	sudo mkdir -p /etc/edr /var/lib/edr /var/log/edr
	[ -f /etc/edr/agent.yaml ] || sudo install -m 640 config/agent.yaml /etc/edr/agent.yaml
	sudo install -m 644 deploy/edr-agent.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable edr-agent
	@echo "==> Start: sudo systemctl start edr-agent"

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) gen.go
	rm -f $(BPF_OBJS)
	find internal -name '*_bpfel.go' -o -name '*_bpfeb.go' 2>/dev/null | xargs rm -f
	@echo "==> Clean"

help:
	@echo "Targets: all check-deps vmlinux ebpf generate build run install test lint clean"
