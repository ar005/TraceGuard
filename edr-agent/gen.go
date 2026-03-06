// gen.go — root-level go:generate for all eBPF objects.
//
// Run ONLY via: make generate   (sets PROJ_ROOT and correct PATH)
// Or:           go generate .   (from project root, after: export PROJ_ROOT=$(pwd))
//
// IMPORTANT: -I${PROJ_ROOT}/ebpf uses the PROJ_ROOT env var set by the Makefile.
// This ensures vmlinux.h is found regardless of where bpf2go changes its cwd to.

package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I${PROJ_ROOT}/ebpf -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" -output-dir internal/monitor/process ProcessBPF ebpf/process/process.bpf.c
//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I${PROJ_ROOT}/ebpf -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" -output-dir internal/monitor/network NetworkBPF ebpf/network/network.bpf.c
//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I${PROJ_ROOT}/ebpf -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" -output-dir internal/monitor/file    FileBPF    ebpf/file/file.bpf.c
