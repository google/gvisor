# Technology Stack

**Analysis Date:** 2026-03-08

## Languages

**Primary:**
- Go 1.24.1 - All application code (kernel, runtime, networking, tooling)

**Secondary:**
- Assembly (amd64, arm64) - Low-level platform code in `pkg/ring0/`, `pkg/sentry/platform/kvm/`, `pkg/sentry/platform/systrap/`
- Protocol Buffers - Metric definitions, event serialization, security check points (generated `_go_proto` packages throughout `pkg/`)

## Runtime

**Environment:**
- Go 1.24.1 (Linux-only target; amd64 and arm64 supported)
- Note: This is a synthetic Go-only branch. The authoritative source uses Bazel as the primary build system (see `master` branch). No `WORKSPACE`, `BUILD`, `MODULE.bazel`, or `Makefile` exists on this branch.

**Package Manager:**
- Go Modules
- Lockfile: `go.sum` present

## Frameworks

**Core:**
- OCI Runtime Spec (`github.com/opencontainers/runtime-spec v1.1.0-rc.1`) - Container runtime interface compliance
- containerd Shim v2 API (`github.com/containerd/containerd v1.6.36`) - Container runtime integration with containerd
- Kubernetes client-go (`k8s.io/client-go v0.23.16`) - Used only by the webhook admission controller

**Testing:**
- Not applicable on this branch (synthetic Go-only branch; tests live on `master`)

**Build/Dev:**
- `tools/checklocks/` - Custom static analysis tool for lock ordering verification (`go/analysis` framework)
- `tools/xdp/` - XDP debugging/testing tools using eBPF

## Key Dependencies

**Critical (direct, tightly coupled):**
- `golang.org/x/sys v0.26.0` - Linux syscall interface (used pervasively across `pkg/`, `runsc/`)
- `github.com/opencontainers/runtime-spec v1.1.0-rc.1` - OCI runtime spec types for container configuration
- `github.com/google/subcommands v1.0.2` - CLI subcommand framework for `runsc`
- `google.golang.org/protobuf v1.33.0` - Protobuf serialization for metrics, events, security checks
- `github.com/containerd/containerd v1.6.36` - Containerd shim v2 task API integration
- `github.com/gogo/protobuf v1.3.2` - Legacy protobuf (used by containerd API types)

**Infrastructure:**
- `github.com/vishvananda/netlink v1.1.1` - Linux netlink interface for network device setup (`runsc/sandbox/network.go`, `runsc/sandbox/xdp.go`)
- `github.com/cilium/ebpf v0.12.3` - eBPF/XDP program loading (`runsc/sandbox/xdp.go`, `tools/xdp/`)
- `github.com/containerd/cgroups v1.0.4` - Cgroup v1/v2 management for container resource limits (`runsc/cgroup/`, `pkg/shim/`)
- `github.com/coreos/go-systemd/v22 v22.5.0` - systemd-managed cgroup integration (`runsc/cgroup/systemd.go`)
- `github.com/godbus/dbus/v5 v5.1.0` - D-Bus IPC for systemd cgroup operations (`runsc/cgroup/systemd.go`)
- `github.com/cenkalti/backoff v2.2.1` - Exponential backoff for retries (`runsc/sandbox/`, `runsc/container/`, `runsc/cgroup/`)
- `github.com/moby/sys/capability v0.4.0` - Linux capability management (`runsc/sandbox/`, `runsc/boot/`)
- `github.com/gofrs/flock v0.8.0` - File locking for container state files (`runsc/container/state_file.go`)
- `github.com/google/btree v1.1.2` - B-tree data structure for TCP SACK scoreboard (`pkg/tcpip/transport/tcp/`)
- `github.com/BurntSushi/toml v1.4.1` - TOML config parsing for containerd shim options (`pkg/shim/v1/runsc/service.go`)
- `github.com/sirupsen/logrus v1.9.3` - Structured logging (containerd shim integration) (`pkg/shim/v1/runsc/`)
- `golang.org/x/sync v0.8.0` - Errgroup for concurrent operations (`runsc/cgroup/`)
- `golang.org/x/time v0.7.0` - Rate limiting
- `golang.org/x/exp v0.0.0` - Experimental Go libraries
- `golang.org/x/mod v0.21.0` - Module version parsing
- `golang.org/x/tools v0.26.0` - Go analysis framework for `tools/checklocks/`

**Kubernetes (webhook only):**
- `k8s.io/api v0.23.16` - Kubernetes API types (admission, core)
- `k8s.io/apimachinery v0.23.16` - Kubernetes API machinery
- `k8s.io/client-go v0.23.16` - Kubernetes API client
- `github.com/mattbaird/jsonpatch v0.0.0` - JSON patch generation for webhook mutations (`webhook/pkg/injector/`)

**Utility:**
- `github.com/kr/pty v1.1.5` - PTY allocation for container console (`runsc/console/console.go`)
- `github.com/mohae/deepcopy v0.0.0` - Deep copy for OCI spec manipulation (`runsc/specutils/specutils.go`)
- `github.com/containerd/fifo v1.0.0` - FIFO handling for containerd shim I/O
- `github.com/containerd/console v1.0.3` - Console/TTY management for containerd shim
- `github.com/containerd/go-runc v1.0.0` - runc binary interaction for shim fallback
- `github.com/containerd/errdefs v0.1.0` - Containerd error definitions
- `github.com/hashicorp/go-multierror v1.1.1` - Error aggregation (indirect, via containerd)

## Configuration

**Runtime Configuration:**
- All configuration via command-line flags, defined in `runsc/config/config.go` as struct tags (`flag:"..."`)
- Flag registration in `runsc/config/flags.go`
- Configuration propagated to child processes via same flags
- OCI annotation overrides supported (controlled by `--allow-flag-override`)

**Key Configuration Categories:**
- Platform selection: `--platform` (kvm, ptrace, systrap)
- Network mode: `--network` (sandbox, host, none)
- Filesystem access: `--file-access`, `--directfs`, `--overlay2`
- GPU support: `--nvproxy`, `--tpuproxy`
- Security: `--oci-seccomp`, `--enable-core-tags`
- Observability: `--metric-server`, `--strace`, `--debug-log`
- Cgroups: `--ignore-cgroups`, `--systemd-cgroup`
- Networking: `--num-network-channels`, `--gso`, `--software-gso`, `--gvisor-gro`
- XDP: `--EXPERIMENTAL-xdp`

**Container State:**
- Container metadata stored as `meta.json` in per-container subdirectories under `--root` directory
- File locking via `gofrs/flock` for concurrent access safety (`runsc/container/state_file.go`)

**Containerd Shim Configuration:**
- TOML-based options via `containerd` config (`pkg/shim/v1/runtimeoptions/`)

## Three Binaries

**`runsc`** (entry: `runsc/main.go` -> `runsc/cli/main.go`):
- The OCI-compliant container runtime binary
- Implements: create, start, run, exec, kill, delete, pause, resume, checkpoint, restore, list, state, events, ps, spec, wait, do, gofer, boot, portforward, debug, install, metric-server, metric-export, metric-metadata, etc.
- 46 subcommand files in `runsc/cmd/`

**`containerd-shim-runsc-v1`** (entry: `shim/main.go` -> `shim/v1/cli/cli.go`):
- Containerd shim v2 plugin implementing `io.containerd.runsc.v1`
- Bridges containerd task API to runsc operations

**`gvisor-admission-webhook`** (entry: `webhook/main.go` -> `webhook/pkg/cli/cli.go`):
- Kubernetes mutating admission webhook
- Sets `RuntimeClassName: gvisor` on pods in selected namespaces

## Platform Requirements

**Development:**
- Go 1.24.1+
- Linux (amd64 or arm64) for building and running
- Bazel (on the `master` branch, not this synthetic branch)

**Production:**
- Linux kernel (amd64 or arm64)
- Platform-specific requirements:
  - KVM: `/dev/kvm` access
  - Systrap: seccomp-bpf support (default platform)
  - ptrace: `PTRACE_ATTACH` capability
- Optional: NVIDIA GPU driver (for `--nvproxy`)
- Optional: TPU device access (for `--tpuproxy`)
- Optional: XDP-capable NIC (for `--EXPERIMENTAL-xdp`)
- Cgroup v1 or v2 support
- Typically deployed as a Docker/containerd runtime or via Kubernetes RuntimeClass

## Internal Libraries (Notable)

**Networking Stack (netstack):**
- Full userspace TCP/IP stack in `pkg/tcpip/`
- Protocols: IPv4, IPv6, ARP, TCP, UDP, ICMP, raw sockets
- Link layers: fd-based, loopback, ethernet, TUN, veth, XDP, shared memory
- Features: nftables, netfilter (iptables), PCAP logging, QDisc

**Filesystem (VFS2 + LisaFS):**
- Virtual filesystem layer in `pkg/sentry/vfs/`
- 23 filesystem implementations in `pkg/sentry/fsimpl/` (tmpfs, proc, sys, cgroupfs, devpts, fuse, overlay, gofer, EROFS, etc.)
- LisaFS: custom filesystem RPC protocol (`pkg/lisafs/`) replacing 9P2000.L (`pkg/p9/`, deprecated)
- Gofer: host filesystem proxy process (`runsc/fsgofer/`)

**Kernel (Sentry):**
- Application kernel in `pkg/sentry/`
- Syscall implementation: `pkg/sentry/syscalls/`
- Process/thread management: `pkg/sentry/kernel/`
- Memory management: `pkg/sentry/mm/`, `pkg/sentry/pgalloc/`
- Platform abstraction: `pkg/sentry/platform/` (KVM, systrap, ptrace)
- Ring 0 support: `pkg/ring0/` (for KVM platform)

**IPC/Control:**
- urpc: custom JSON-over-Unix-socket RPC (`pkg/urpc/`)
- unet: Unix domain socket abstraction (`pkg/unet/`)
- Control server: sandbox management RPC (`pkg/control/`)

**Observability:**
- Metrics: `pkg/metric/` with Prometheus exposition format (`pkg/prometheus/`)
- Strace: syscall tracing (`pkg/sentry/strace/`)
- Security checks: pluggable security audit framework (`pkg/sentry/seccheck/`)

---

*Stack analysis: 2026-03-08*
