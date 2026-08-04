//go:build ignore

// execsnoop is netguard's M0 toolchain check: a minimal BPF program that
// proves the compile -> load -> attach -> read pipeline works before any
// networking code is written. It attaches to the sys_enter_execve
// tracepoint and emits one event per execve() call via a ring buffer.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	__u32 pid;
	char comm[16];
};

// struct event is otherwise only referenced through a local pointer, which
// clang's BPF target can optimize out of the object's debug info entirely.
// A dummy global reference keeps it there so bpf2go's -type flag can find
// it and generate a matching Go struct.
struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
