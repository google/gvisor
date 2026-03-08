# Architecture

**Analysis Date:** 2026-03-08

## Pattern Overview

**Overall:** Multi-process sandboxed kernel emulation

gVisor is a user-space kernel that intercepts and emulates Linux system calls. It runs containerized applications inside a sandbox process that reimplements the Linux kernel in Go, providing strong isolation without hardware virtualization. The architecture follows a multi-process model: a host-side CLI (`runsc`), a filesystem gofer process, and a sandboxed sentry (kernel emulator).

**Key Characteristics:**
- System call interception via platform-specific mechanisms (KVM, systrap, ptrace)
- Complete reimplementation of Linux kernel subsystems (VFS, networking, memory management, scheduling) in Go
- Separate trusted gofer process for host filesystem access (principle of least privilege)
- OCI runtime spec compatible CLI (`runsc`) for integration with Docker/containerd
- State machine-based task execution model where each task goroutine cycles through run states
- Checkpoint/restore support via state serialization (`+stateify savable` annotations)

## Layers

**CLI Layer (`runsc/cli`, `runsc/cmd`):**
- Purpose: OCI-compatible container runtime CLI (like runc)
- Location: `runsc/cli/main.go`, `runsc/cmd/`
- Contains: Subcommand implementations (create, start, run, exec, kill, delete, etc.)
- Depends on: `runsc/container`, `runsc/sandbox`, `runsc/config`
- Used by: Docker, containerd, Kubernetes via CRI

**Container Management Layer (`runsc/container`):**
- Purpose: Orchestrates container lifecycle (create, start, stop, destroy)
- Location: `runsc/container/container.go`
- Contains: Container state management, metadata persistence, gofer/sandbox process coordination
- Depends on: `runsc/sandbox`, `runsc/boot`, `runsc/cgroup`
- Used by: CLI subcommands

**Sandbox Layer (`runsc/sandbox`):**
- Purpose: Creates and manages the sandbox process (which runs the sentry)
- Location: `runsc/sandbox/sandbox.go` (~2074 lines)
- Contains: Sandbox process creation, cgroup setup, network configuration, control socket management
- Depends on: `runsc/boot`, `pkg/control`, `pkg/urpc`
- Used by: `runsc/container`

**Boot/Loader Layer (`runsc/boot`):**
- Purpose: Initializes and runs the sentry kernel inside the sandbox process
- Location: `runsc/boot/loader.go` (~2090 lines)
- Contains: Kernel initialization, VFS setup, network stack creation, seccomp filter installation, container process creation
- Depends on: `pkg/sentry/kernel`, `pkg/sentry/platform`, `pkg/sentry/vfs`, `pkg/tcpip`
- Used by: `runsc/cmd/boot.go` (internal boot subcommand)

**Sentry Kernel Layer (`pkg/sentry/kernel`):**
- Purpose: Core Linux kernel emulation (task management, scheduling, signals, IPC)
- Location: `pkg/sentry/kernel/` (kernel.go ~2106 lines)
- Contains: Kernel struct, Task struct, ThreadGroup, TaskSet, FD table, futex, auth, IPC namespaces
- Depends on: `pkg/sentry/platform`, `pkg/sentry/vfs`, `pkg/sentry/mm`, `pkg/sentry/loader`
- Used by: `runsc/boot`, syscall implementations

**Syscall Implementation Layer (`pkg/sentry/syscalls/linux`):**
- Purpose: Implements Linux system calls
- Location: `pkg/sentry/syscalls/linux/` (50 `sys_*.go` files)
- Contains: Individual syscall handlers (file ops, memory, signals, networking, IPC, etc.)
- Depends on: `pkg/sentry/kernel`, `pkg/sentry/vfs`, `pkg/sentry/mm`
- Used by: Syscall dispatch table in `linux64.go`

**VFS Layer (`pkg/sentry/vfs`):**
- Purpose: Virtual filesystem abstraction (VFS2)
- Location: `pkg/sentry/vfs/` (vfs.go defines `VirtualFilesystem`)
- Contains: Mount management, dentry resolution, file descriptions, filesystem type registry, epoll, inotify
- Depends on: `pkg/sentry/kernel/auth`, `pkg/fspath`
- Used by: Filesystem implementations, syscall handlers

**Filesystem Implementations (`pkg/sentry/fsimpl/`):**
- Purpose: Concrete filesystem implementations
- Location: `pkg/sentry/fsimpl/` (23 subdirectories)
- Contains: gofer (host FS via LISAFS), tmpfs, procfs, sysfs, devpts, cgroupfs, overlayfs, EROFS, FUSE, kernfs, etc.
- Depends on: `pkg/sentry/vfs`, `pkg/lisafs`
- Used by: VFS layer via filesystem type registration

**Platform Layer (`pkg/sentry/platform`):**
- Purpose: Abstracts CPU execution context and address space management
- Location: `pkg/sentry/platform/platform.go`
- Contains: Platform interface, Context interface, AddressSpace interface
- Implementations: `kvm/`, `systrap/`, `ptrace/`
- Used by: Kernel for task execution, memory management

**Networking Stack (`pkg/tcpip`):**
- Purpose: User-space TCP/IP networking stack (netstack)
- Location: `pkg/tcpip/` (~83K lines of Go)
- Contains: Full TCP/IP stack: ARP, IPv4, IPv6, TCP, UDP, ICMP, raw sockets, nftables
- Sub-layers: `stack/` (core), `transport/` (TCP/UDP/ICMP), `network/` (IP), `link/` (ethernet/loopback/FD-based), `header/`
- Depends on: `pkg/buffer`, `pkg/waiter`
- Used by: `pkg/sentry/socket/netstack`

**Memory Management (`pkg/sentry/mm`, `pkg/sentry/pgalloc`):**
- Purpose: Virtual memory management and page allocation
- Location: `pkg/sentry/mm/`, `pkg/sentry/pgalloc/`
- Contains: MemoryManager, address space management, memory mapping, page allocation
- Depends on: `pkg/sentry/platform`, `pkg/sentry/memmap`, `pkg/hostarch`
- Used by: Kernel, loader, syscall handlers

**Gofer/LISAFS Layer (`pkg/lisafs`, `runsc/fsgofer`):**
- Purpose: Filesystem access proxy running outside the sandbox
- Location: `pkg/lisafs/` (protocol), `runsc/fsgofer/` (server implementation)
- Contains: LISAFS protocol (client/server), file operations over Unix domain sockets
- Depends on: `pkg/unet`, `pkg/p9` (types only; 9P2000.L replaced by LISAFS)
- Used by: `pkg/sentry/fsimpl/gofer` (client side), `runsc/cmd/gofer.go` (server side)

## Data Flow

**Container Creation & Startup:**

1. User runs `runsc create <id>` which invokes `cmd.Create.Execute()`
2. `container.New()` creates Container metadata, determines if root or sub-container
3. For root container: `container.createGoferProcess()` forks a gofer process running `runsc gofer`
4. `sandbox.New()` forks a sandbox process running `runsc boot` with donated FDs
5. Inside sandbox: `boot.New(args)` creates the Loader, initializes platform, kernel, VFS, network stack
6. Sandbox notifies parent via sync pipe, then waits for start signal
7. `runsc start <id>` sends start signal via control socket (uRPC)
8. `Loader.Run()` installs seccomp filters, creates root container init task, starts kernel

**Syscall Execution:**

1. Application makes a syscall
2. Platform intercepts (KVM trap / systrap signal / ptrace stop)
3. Platform returns to sentry with `ErrContextInterrupt` or `ErrContextSignalCPUID`
4. Task goroutine enters `runSyscallAfterPtraceEventSeccomp` or `runSyscallAfterSyscallEnterStop`
5. Syscall number is looked up in the syscall table (`linux64.go`)
6. Corresponding `sys_*.go` handler is invoked with the Task as receiver context
7. Handler interacts with kernel subsystems (VFS, networking, memory, etc.)
8. Return value is placed in the task's register set
9. Task goroutine resumes application execution via `Context.Switch()`

**File System Access (Gofer Path):**

1. Application makes a file operation syscall (open, read, write, etc.)
2. VFS routes to the gofer filesystem implementation (`pkg/sentry/fsimpl/gofer/`)
3. Gofer client sends LISAFS RPC over Unix domain socket to the gofer process
4. Gofer process (running `runsc gofer`) performs the actual host filesystem operation
5. Result is returned via LISAFS protocol back to the sandbox

**State Management:**
- Container metadata is persisted as JSON in `<rootDir>/<sandboxID>/<containerID>/meta.json`
- Sandbox communicates with host via uRPC over Unix domain control socket
- Kernel state can be serialized for checkpoint/restore using `+stateify savable` annotations

## Key Abstractions

**Platform (`pkg/sentry/platform/platform.go`):**
- Purpose: Abstracts how user code is executed and how memory is mapped
- Implementations: `kvm/` (hardware virtualization), `systrap/` (seccomp + syscall interception), `ptrace/` (ptrace-based)
- Pattern: Interface with `NewContext()`, `NewAddressSpace()`, `Context.Switch()` methods
- Registration: Platforms register via `platform.Register()`, looked up by name

**Task (`pkg/sentry/kernel/task.go`):**
- Purpose: Represents a thread of execution in the sandboxed application
- Each task has a dedicated goroutine that runs a state machine (`taskRunState`)
- States: `runApp` (execute user code), `runSyscallAfterPtraceEventSeccomp`, `runSyscallExit`, `runInterrupt`, `runExit`
- Pattern: State machine with `execute(*Task) taskRunState` transitions

**VirtualFilesystem (`pkg/sentry/vfs/vfs.go`):**
- Purpose: Combines filesystems into mount trees, routes path operations
- Pattern: Central coordinator with registered `FilesystemType` implementations
- Key interfaces: `FilesystemImpl`, `DentryImpl`, `FileDescriptionImpl`
- Each filesystem registers its type; VFS instantiates via `Mount()`

**Loader (`runsc/boot/loader.go`):**
- Purpose: Bootstraps the entire sentry kernel from boot arguments
- Manages: Kernel, platform, VFS mounts, network stack, control server, seccomp filters
- Pattern: Builder that initializes all subsystems, then `Run()` starts execution

**containerManager (`runsc/boot/controller.go`):**
- Purpose: uRPC service handling control commands from the host side
- Methods: `StartRoot`, `CreateSubcontainer`, `StartSubcontainer`, `ExecuteAsync`, `Signal`, `Checkpoint`, `Restore`, etc.
- Pattern: RPC server registered with `urpc.Server`

**Sandbox (`runsc/sandbox/sandbox.go`):**
- Purpose: Host-side representation of the sandbox process
- Communicates with sandbox via Unix domain socket + uRPC
- Pattern: Process manager with `createSandboxProcess()`, `call()` for RPCs

## Entry Points

**`runsc` CLI (`runsc/cli/main.go`):**
- Location: `runsc/cli/main.go` -> `Main()`
- Triggers: Invoked by Docker/containerd/Kubernetes
- Responsibilities: Parse flags, load config, dispatch to subcommands

**`runsc boot` (internal) (`runsc/cmd/boot.go`):**
- Location: `runsc/cmd/boot.go` -> `Boot.Execute()`
- Triggers: Forked by sandbox creation (`runsc/sandbox/sandbox.go`)
- Responsibilities: Initialize sentry, create Loader, run kernel, manage container lifecycle

**`runsc gofer` (internal) (`runsc/cmd/gofer.go`):**
- Location: `runsc/cmd/gofer.go` -> `Gofer.Execute()`
- Triggers: Forked by container creation (`runsc/container/container.go`)
- Responsibilities: Serve LISAFS filesystem RPCs, chroot into container root, apply seccomp

**containerd shim (`shim/main.go`):**
- Location: `shim/main.go` -> delegates to `shim/v1/cli/cli.go`
- Triggers: containerd starts it as `containerd-shim-runsc-v1`
- Responsibilities: containerd shim v2 API, manages runsc lifecycle

**Kubernetes webhook (`webhook/main.go`):**
- Location: `webhook/main.go` -> delegates to `webhook/pkg/cli/cli.go`
- Triggers: Kubernetes admission webhook
- Responsibilities: Mutating webhook to inject gVisor runtime class annotations

## Error Handling

**Strategy:** Direct error returns with wrapping, fatal exits for unrecoverable states

**Patterns:**
- `util.Fatalf()` for unrecoverable errors in CLI and boot paths (exits process immediately)
- Standard Go `fmt.Errorf("context: %w", err)` for error wrapping throughout `pkg/`
- `linuxerr` package provides Linux errno constants as sentinel errors (e.g., `linuxerr.EAGAIN`)
- `syserr` package provides syscall-level error abstractions that map to errnos
- Syscall handlers return `(uintptr, *SyscallControl, error)` where error is a Linux errno

## Cross-Cutting Concerns

**Logging:**
- `pkg/log` package with levels: Debug, Info, Warning
- Multiple emitter support: text, JSON, Kubernetes JSON (`json-k8s`)
- Debug logging controlled by `--debug` flag and `--debug-log` path

**Seccomp Filtering:**
- Both the sandbox and gofer install seccomp-bpf filters to restrict host syscalls
- Sandbox filters: `runsc/boot/filter/` (assembled from `config/` rules)
- Gofer filters: `runsc/fsgofer/filter/`
- BPF program generation: `pkg/bpf/`, `pkg/seccomp/`

**State Serialization (Checkpoint/Restore):**
- `+stateify savable` annotations on structs enable automatic serialization
- `pkg/state/` implements the state serialization framework
- `save*`/`load*` methods for custom serialization logic
- Dangling network endpoints specially handled during save/restore

**Concurrency:**
- Custom `pkg/sync` package (extends standard sync)
- Detailed lock ordering documented in package comments (kernel, VFS)
- `+checklocks:mu` annotations enforced by `tools/checklocks/` analyzer
- Each Task runs in its own goroutine; fields annotated as "owned by task goroutine" vs shared

**Metrics & Monitoring:**
- `pkg/metric/` for internal metrics collection
- `pkg/prometheus/` for Prometheus-compatible export
- `runsc/metricserver/` for standalone metric server
- Profiling via pprof integration (`runsc/boot/pprof/`)

---

*Architecture analysis: 2026-03-08*
