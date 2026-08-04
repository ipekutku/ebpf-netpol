// Package execsnoop loads a minimal BPF program that emits one event per
// execve() call via a ring buffer. It exists to prove the compile -> load
// -> attach -> read pipeline end to end (netguard milestone M0) before any
// packet-inspection code is written.
package execsnoop

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type event bpf ../../bpf/execsnoop.c
