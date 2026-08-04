# netguard

[![CI](https://github.com/ipekutku/ebpf-netpol/actions/workflows/ci.yml/badge.svg)](https://github.com/ipekutku/ebpf-netpol/actions/workflows/ci.yml)

An eBPF-based runtime network policy enforcer for Kubernetes: kernel-level
detection and blocking of policy-violating pod-to-pod (and pod-to-external)
connections as they happen, with violations surfaced via Prometheus/Grafana
for audit purposes. This is a portfolio project built milestone by milestone;
see the current status below.

## Requirements

- A real Linux kernel with BPF support, **5.8+** (for the ring buffer map
  type used here). This does **not** run reliably on Docker Desktop for
  Mac/Windows depending on VM configuration — use WSL2 or a Linux VM/cloud
  box. Confirm support with `bpftool feature probe kernel` before doing
  anything else.
- `clang`/`llvm` and `libbpf-dev` (provides the BPF-side headers).
- Go (see `go.mod` for the minimum version).
- Running the compiled binary requires `CAP_BPF`/`CAP_SYS_ADMIN` (in
  practice: run it with `sudo`, or as a privileged container/DaemonSet in
  the eventual Kubernetes deployment). That privilege requirement is a real
  security consideration for the deployed daemon, not an implementation
  detail to gloss over — it will be documented further as the project
  reaches M4 (Kubernetes integration).

This repo can't be fully built or run on macOS — there's no Linux kernel to
load BPF programs into. Local edits are fine on any OS; the toolchain
(`make generate` / `make build` / `make run`) needs Linux, and CI
(`.github/workflows/ci.yml`, running on `ubuntu-latest`) is the actual
verification environment for each milestone's exit criteria.

## Quick start

```sh
make generate   # compile bpf/*.c -> BPF bytecode via bpf2go (needs clang + libbpf-dev)
make build      # go build the netguard binary
sudo make run   # load the BPF program and print events it emits
```

## Status

- [x] **M0 — Environment & toolchain.** A minimal BPF program
      ([bpf/execsnoop.c](bpf/execsnoop.c)) attaches to the
      `syscalls/sys_enter_execve` tracepoint, emits one event per `execve()`
      call over a ring buffer, and the Go control plane
      ([internal/execsnoop](internal/execsnoop),
      [cmd/netguard](cmd/netguard)) loads it and reads those events back.
      This proves the compile -> load -> attach -> read pipeline end to end
      before any networking code is written. Verified on every push by CI.
- [ ] M1 — Packet inspection at the TC hook
- [ ] M2 — Policy representation & BPF maps
- [ ] M3 — Enforcement (drop violating traffic)
- [ ] M4 — Kubernetes integration
- [ ] M5 — Socket-level detection
- [ ] M6 — Observability
- [ ] M7 — Testing, including adversarial cases
- [ ] M8 — Performance overhead measurement
- [ ] M9 — Docs

## Layout

```
bpf/                    BPF C source, compiled to bytecode via bpf2go
internal/execsnoop/     go:generate directive + Go loader for the M0 program
cmd/netguard/           control-plane entry point
```
