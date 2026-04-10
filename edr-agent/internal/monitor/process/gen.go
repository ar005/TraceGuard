package process
//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I'/home/devubuntu/projects/TraceGuard/edr-agent/ebpf' -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf" Process /home/devubuntu/projects/TraceGuard/edr-agent/ebpf/process/process.bpf.c
