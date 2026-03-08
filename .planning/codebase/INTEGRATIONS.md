# External Integrations

**Analysis Date:** 2026-03-08

## APIs & External Services

**OCI Runtime Interface:**
- gVisor (`runsc`) implements the OCI Runtime Spec as a low-level container runtime
  - Spec compliance: `github.com/opencontainers/runtime-spec v1.1.0-rc.1`
  - Spec version: defined in `runsc/specutils/`
  - Entry point: `runsc/cli/main.go` -> subcommands in `runsc/cmd/`
  - Consumers: Docker, containerd, CRI-O, Kubernetes via RuntimeClass

**containerd Shim v2 API:**
- Binary `containerd-shim-runsc-v1` implements the containerd task API
  - Plugin ID: `io.containerd.runsc.v1`
  - Implementation: `pkg/shim/v1/runsc/service.go`
  - API surface: `github.com/containerd/containerd/runtime/v2/task` (Create, Start, Delete, Exec, Kill, State, etc.)
  - Communication: ttrpc (via `github.com/containerd/ttrpc`)
  - Events: Published via containerd event system (`github.com/containerd/containerd/api/events`)

**Kubernetes Admission Webhook:**
- Mutating webhook that patches pods to use gVisor runtime
  - Binary: `webhook/main.go`
  - Implementation: `webhook/pkg/injector/webhook.go`
  - API: Kubernetes AdmissionReview v1beta1
  - Client: `k8s.io/client-go` with in-cluster config (`rest.InClusterConfig()`)
  - Mutation: Sets `spec.runtimeClassName: gvisor`, strips SELinux options
  - TLS: Self-signed certificates embedded in `webhook/pkg/injector/certs.go`
  - Registration: Creates `MutatingWebhookConfiguration` via Kubernetes API

## Data Storage

**Databases:**
- None - gVisor stores no data in external databases

**File Storage:**
- Container state: JSON metadata files (`meta.json`) in per-container directories under `--root` (default: `/var/run/runsc`)
  - Implementation: `runsc/container/container.go`
  - File locking: `github.com/gofrs/flock` in `runsc/container/state_file.go`
- Checkpoint/restore: State serialization via `pkg/state/` to files
  - Save format: custom binary format via `pkg/state/statefile/`
- Debug logs: Written to files specified by `--debug-log` flag
- PCAP capture: Network packet logs to `--pcap-log` file
- Profiling data: CPU/heap/mutex/block profiles to specified files

**Caching:**
- None - no external caching services

## Authentication & Identity

**Auth Provider:**
- No external auth for gVisor itself
- Kubernetes webhook uses in-cluster service account token (`rest.InClusterConfig()`)
  - File: `webhook/pkg/cli/cli.go`

**Container Identity:**
- Linux capabilities managed via `github.com/moby/sys/capability`
  - Files: `runsc/sandbox/sandbox.go`, `runsc/boot/loader.go`
- User namespaces and credential management in `pkg/sentry/kernel/auth/`

## Monitoring & Observability

**Metrics:**
- Custom Prometheus-compatible metrics exposition
  - Metric definitions: `pkg/metric/metric.go` using protobuf (`pkg/metric/metric_go_proto/`)
  - Prometheus format: `pkg/prometheus/prometheus.go` (pure Go, no external dependency)
  - Metric server: `runsc/cmd/metric_server.go` exposes HTTP endpoint
  - Metric export: `runsc/cmd/metric_export.go` for one-shot export
  - Labels: `sandbox`, `pod_name`, `namespace_name`, `iteration`
  - Profiling metrics: CSV time-series output to file (`--profiling-metrics-log`)

**Tracing/Security Auditing:**
- Security check framework: `pkg/sentry/seccheck/`
  - Pluggable sinks via `seccheck.RegisterSink()`
  - Remote sink: serializes events over Unix domain socket (`pkg/sentry/seccheck/sinks/remote/remote.go`)
  - Null sink: discards events (`pkg/sentry/seccheck/sinks/null/null.go`)
  - Wire protocol: protobuf over `SOCK_SEQPACKET` Unix socket (`pkg/sentry/seccheck/sinks/remote/wire/`)
  - Point types: syscall entry/exit, clone, execve, exit, container start, etc. (`pkg/sentry/seccheck/points/`)

**Strace:**
- Built-in syscall tracing: `pkg/sentry/strace/`
  - Enabled via `--strace` flag
  - Output: log or event channel
  - Configurable syscall filter: `--strace-syscalls`

**Error Tracking:**
- None - errors logged via `pkg/log/`

**Logs:**
- Custom logging package: `pkg/log/log.go`
  - Formats: text, JSON (`--log-format`, `--debug-log-format`)
  - Levels: Info, Warning, Debug
  - Containerd shim uses logrus: `github.com/sirupsen/logrus` (`pkg/shim/v1/runsc/`)

## CI/CD & Deployment

**Hosting:**
- Self-hosted Linux binary
- Deployed as OCI runtime alongside Docker/containerd/Kubernetes
- Google Cloud: available as GKE Sandbox (managed gVisor)

**CI Pipeline:**
- Not present on this synthetic branch
- Primary build system is Bazel (on `master` branch)

## Linux Kernel Interfaces

**KVM:**
- `/dev/kvm` ioctl interface for hardware virtualization
  - Files: `pkg/sentry/platform/kvm/`
  - Used when `--platform=kvm`

**Seccomp-BPF:**
- Syscall interception for the systrap platform
  - BPF program generation: `pkg/seccomp/`
  - BPF interpreter: `pkg/bpf/`
  - Platform: `pkg/sentry/platform/systrap/`

**Ptrace:**
- `PTRACE_ATTACH`/`PTRACE_SYSCALL` for syscall interception
  - Files: `pkg/sentry/platform/ptrace/`
  - Used when `--platform=ptrace`

**Netlink:**
- Network device configuration via `github.com/vishvananda/netlink`
  - Files: `runsc/sandbox/network.go`
  - Used for setting up sandbox network interfaces

**eBPF/XDP:**
- AF_XDP socket-based packet I/O (experimental)
  - eBPF loading: `github.com/cilium/ebpf` in `runsc/sandbox/xdp.go`
  - XDP queue management: `pkg/xdp/`
  - Link layer: `pkg/tcpip/link/xdp/`
  - Tools: `tools/xdp/`

**Cgroups:**
- Cgroup v1 and v2 resource management
  - Implementation: `runsc/cgroup/cgroup.go`, `runsc/cgroup/cgroup_v2.go`
  - Systemd integration: `runsc/cgroup/systemd.go` (via D-Bus)
  - Shim-side cgroup management: `pkg/shim/v1/runsc/` using `github.com/containerd/cgroups`

**D-Bus:**
- Systemd unit management for cgroup operations
  - Package: `github.com/godbus/dbus/v5`
  - File: `runsc/cgroup/systemd.go`

## Hardware Device Proxies

**NVIDIA GPU (nvproxy):**
- Proxies NVIDIA GPU ioctls from sandboxed containers to host driver
  - Implementation: `pkg/sentry/devices/nvproxy/`
  - Configuration: `pkg/sentry/devices/nvproxy/nvconf/`
  - Enabled via `--nvproxy` flag
  - Seccomp filters: `pkg/sentry/devices/nvproxy/seccomp_filters.go`
  - Driver version auto-detection or manual override via `--nvproxy-driver-version`
  - Save/restore support: `pkg/sentry/devices/nvproxy/save_restore.go`

**Google TPU (tpuproxy):**
- Proxies TPU device ioctls from sandboxed containers to host
  - Implementation: `pkg/sentry/devices/tpuproxy/`
  - Sub-devices: `accel/`, `vfio/`
  - Enabled via `--tpuproxy` flag

## Internal IPC

**urpc (Unix RPC):**
- Custom JSON-over-Unix-socket RPC between runsc processes (sandbox <-> controller)
  - Implementation: `pkg/urpc/urpc.go`
  - Transport: `pkg/unet/` (Unix domain sockets with SCM_RIGHTS FD passing)
  - Client: `pkg/control/client/client.go`
  - Used for: sandbox lifecycle control, metric collection, debugging

**LisaFS:**
- Custom filesystem RPC protocol between sandbox (client) and gofer (server)
  - Protocol definition: `pkg/lisafs/lisafs.go`
  - Server implementation: `runsc/fsgofer/lisafs.go`
  - Replaces deprecated 9P2000.L (`pkg/p9/`)
  - Transport: Unix domain sockets with shared memory

**Event Channel:**
- Internal pub/sub for events within the sentry
  - Implementation: `pkg/eventchannel/`
  - Used for: strace events, memory events, uncaught signals

## Plugin System

**Network Plugin:**
- Interface for third-party network stack integration
  - Definition: `pkg/sentry/socket/plugin/plugin.go`
  - Used when `--network=plugin`
  - Allows replacing netstack with external implementations

**Platform Plugin:**
- Pluggable platform backends registered via `init()`
  - Registry: `pkg/sentry/platform/`
  - All platforms imported: `pkg/sentry/platform/platforms/platforms.go`
  - Available: kvm, ptrace, systrap

**Security Check Sinks:**
- Pluggable security audit sinks
  - Registry: `pkg/sentry/seccheck/seccheck.go` via `RegisterSink()`
  - Built-in: remote (Unix socket), null (discard)

## Environment Configuration

**Required env vars:**
- None strictly required; all configuration via flags

**Kubernetes-related annotations (read from OCI spec):**
- `io.kubernetes.cri.sandbox-name` - Pod name for metric labeling
- `io.kubernetes.cri.sandbox-namespace` - Pod namespace for metric labeling
- `dev.gvisor.spec.cgroup-parent` - Custom cgroup parent override

**Shim env vars:**
- Shim reads containerd runtime options from TOML config
- OCI spec environment variables passed through to container

## Webhooks & Callbacks

**Incoming:**
- Kubernetes admission webhook at `webhook/pkg/injector/webhook.go`
  - Endpoint: HTTPS `POST /` (any path)
  - Payload: `AdmissionReview` v1beta1
  - Response: JSON patch to set `runtimeClassName: gvisor`
  - TLS: Self-signed certs

**Outgoing:**
- Security check remote sink sends events to external process over Unix socket
  - Implementation: `pkg/sentry/seccheck/sinks/remote/remote.go`
  - Protocol: protobuf over `SOCK_SEQPACKET`

---

*Integration audit: 2026-03-08*
