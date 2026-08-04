// Package execsnoop loads a minimal BPF program that emits one event per
// execve() call via a ring buffer. It exists to prove the compile -> load
// -> attach -> read pipeline end to end (netguard milestone M0) before any
// packet-inspection code is written.
package execsnoop

// -target bpf drops clang's usual x86_64-linux-gnu multiarch include dir,
// which is where asm/types.h (pulled in by linux/bpf.h) actually lives on
// Debian/Ubuntu; add it back explicitly. CI runs on ubuntu-latest (x86_64).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event bpf ../../bpf/execsnoop.c
