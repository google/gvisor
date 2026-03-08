# Codebase Structure

**Analysis Date:** 2026-03-08

## Directory Layout

```
gvisor/
├── pkg/                    # Core libraries and kernel implementation
│   ├── abi/                # ABI definitions (Linux constants, types)
│   ├── bpf/                # BPF bytecode interpreter and program builder
│   ├── buffer/             # Memory buffer management
│   ├── cleanup/            # Deferred cleanup utilities
│   ├── context/            # Context interface extensions
│   ├── control/            # Control server/client for uRPC
│   ├── cpuid/              # CPUID feature detection
│   ├── errors/             # Error types (linuxerr for Linux errnos)
│   ├── fd/                 # File descriptor wrapper types
│   ├── hostarch/           # Host architecture abstractions (page size, address types)
│   ├── lisafs/             # LISAFS protocol (sandbox-gofer filesystem RPC)
│   ├── log/                # Logging framework
│   ├── marshal/            # Binary marshaling utilities
│   ├── memutil/            # Memory utilities
│   ├── metric/             # Metrics collection framework
│   ├── p9/                 # Legacy 9P2000.L types (used by LISAFS)
│   ├── prometheus/         # Prometheus metrics export
│   ├── rand/               # Randomness utilities
│   ├── refs/               # Reference counting with leak detection
│   ├── ring0/              # Ring 0 (kernel mode) support for KVM
│   ├── safecopy/           # Safe memory copy operations
│   ├── safemem/            # Safe memory access abstractions
│   ├── seccomp/            # Seccomp-BPF filter generation
│   ├── sentry/             # Sentry: the user-space kernel (largest component)
│   │   ├── arch/           # Architecture-specific register context (amd64, arm64)
│   │   ├── control/        # In-sandbox control server endpoints
│   │   ├── devices/        # Device emulation (nvproxy, tpuproxy, tty, tun, memdev)
│   │   ├── fdimport/       # File descriptor import from host
│   │   ├── fsimpl/         # Filesystem implementations (VFS2)
│   │   │   ├── cgroupfs/   # Cgroup filesystem
│   │   │   ├── dev/        # /dev filesystem
│   │   │   ├── devpts/     # devpts (pseudo-terminal) filesystem
│   │   │   ├── devtmpfs/   # devtmpfs filesystem
│   │   │   ├── erofs/      # Enhanced Read-Only File System
│   │   │   ├── eventfd/    # eventfd filesystem
│   │   │   ├── fuse/       # FUSE filesystem
│   │   │   ├── gofer/      # Gofer client filesystem (host FS via LISAFS)
│   │   │   ├── host/       # Host filesystem passthrough
│   │   │   ├── iouringfs/  # io_uring filesystem
│   │   │   ├── kernfs/     # Kernel filesystem framework (base for proc, sys)
│   │   │   ├── lock/       # File locking
│   │   │   ├── mqfs/       # POSIX message queue filesystem
│   │   │   ├── nsfs/       # Namespace filesystem
│   │   │   ├── overlay/    # Overlay filesystem
│   │   │   ├── pipefs/     # Pipe filesystem
│   │   │   ├── proc/       # procfs implementation
│   │   │   ├── signalfd/   # signalfd filesystem
│   │   │   ├── sockfs/     # Socket filesystem
│   │   │   ├── sys/        # sysfs implementation
│   │   │   ├── timerfd/    # timerfd filesystem
│   │   │   ├── tmpfs/      # tmpfs implementation
│   │   │   └── user/       # User namespace filesystem helpers
│   │   ├── fsmetric/       # Filesystem metrics
│   │   ├── hostcpu/        # Host CPU interaction
│   │   ├── hostfd/         # Host file descriptor operations
│   │   ├── hostmm/         # Host memory management interaction
│   │   ├── inet/           # Network interface abstractions
│   │   ├── kernel/         # Kernel emulation core
│   │   │   ├── auth/       # Credentials, capabilities, user namespaces
│   │   │   ├── fasync/     # Async I/O notifications
│   │   │   ├── futex/      # Futex implementation
│   │   │   ├── ipc/        # IPC namespace
│   │   │   ├── mq/         # POSIX message queues
│   │   │   ├── msgqueue/   # System V message queues
│   │   │   ├── pipe/       # Pipe implementation
│   │   │   ├── sched/      # Scheduling utilities
│   │   │   ├── semaphore/  # System V semaphores
│   │   │   └── shm/        # System V shared memory
│   │   ├── ktime/          # Kernel time management
│   │   ├── limits/         # Resource limits (rlimit)
│   │   ├── loader/         # ELF/script binary loader
│   │   ├── memmap/         # Memory mapping interfaces
│   │   ├── mm/             # Memory manager (virtual memory)
│   │   ├── pgalloc/        # Page allocator
│   │   ├── platform/       # Platform abstraction layer
│   │   │   ├── kvm/        # KVM-based platform
│   │   │   ├── ptrace/     # ptrace-based platform
│   │   │   ├── systrap/    # Syscall trap (seccomp-based) platform
│   │   │   ├── platforms/  # Platform registration
│   │   │   └── interrupt/  # Interrupt handling
│   │   ├── seccheck/       # Security check points (audit/trace)
│   │   ├── socket/         # Socket implementations
│   │   │   ├── control/    # Socket control messages
│   │   │   ├── hostinet/   # Host networking passthrough
│   │   │   ├── netfilter/  # Netfilter (iptables) implementation
│   │   │   ├── netlink/    # Netlink socket family
│   │   │   ├── netstack/   # Netstack socket integration
│   │   │   ├── plugin/     # Plugin network stack
│   │   │   └── unix/       # Unix domain sockets
│   │   ├── strace/         # Syscall tracing
│   │   ├── syscalls/       # Syscall implementations
│   │   │   └── linux/      # Linux syscall handlers (50 sys_*.go files)
│   │   ├── time/           # Time management
│   │   ├── unimpl/         # Unimplemented syscall handling
│   │   ├── usage/          # Memory usage tracking
│   │   ├── vfs/            # Virtual filesystem layer (VFS2)
│   │   └── watchdog/       # Task watchdog
│   ├── shim/               # containerd shim implementation
│   │   └── v1/             # Shim v1 API implementation
│   ├── state/              # State serialization (checkpoint/restore)
│   ├── sync/               # Extended sync primitives
│   ├── syserr/             # Syscall error types
│   ├── tcpip/              # User-space TCP/IP stack (netstack)
│   │   ├── adapters/       # Adapter utilities
│   │   ├── checksum/       # Checksum calculation
│   │   ├── header/         # Protocol headers (Ethernet, IP, TCP, UDP, etc.)
│   │   ├── link/           # Link layer (ethernet, loopback, FD-based, XDP)
│   │   ├── network/        # Network layer (IPv4, IPv6, ARP)
│   │   ├── nftables/       # nftables implementation
│   │   ├── ports/          # Port management
│   │   ├── stack/          # Network stack core
│   │   └── transport/      # Transport layer (TCP, UDP, ICMP, raw)
│   ├── unet/               # Unix domain socket utilities
│   ├── urpc/               # Micro RPC over Unix domain sockets
│   ├── usermem/            # User memory access utilities
│   ├── waiter/             # Wait queue implementation
│   └── xdp/                # XDP (eXpress Data Path) support
├── runsc/                  # Runtime binary (OCI runtime)
│   ├── boot/               # Sandbox boot and kernel initialization
│   │   ├── filter/         # Seccomp filter assembly for sandbox
│   │   │   └── config/     # Per-feature filter rules
│   │   ├── portforward/    # Port forwarding support
│   │   ├── pprof/          # Profiling support
│   │   └── procfs/         # Procfs data for sandbox
│   ├── cgroup/             # Cgroup management
│   ├── cli/                # CLI entrypoint
│   ├── cmd/                # Subcommand implementations
│   │   ├── nvproxy/        # NVIDIA proxy command
│   │   ├── trace/          # Trace commands
│   │   └── util/           # Command utilities
│   ├── config/             # Runtime configuration
│   ├── console/            # Console/PTY handling
│   ├── container/          # Container lifecycle management
│   ├── donation/           # File descriptor donation
│   ├── flag/               # Flag parsing utilities
│   ├── fsgofer/            # Filesystem gofer server
│   │   └── filter/         # Seccomp filters for gofer
│   ├── hostsettings/       # Host setting detection
│   ├── metricserver/       # Prometheus metric server
│   ├── mitigate/           # CPU vulnerability mitigations
│   ├── profile/            # Profiling support
│   ├── sandbox/            # Sandbox process management
│   ├── specutils/          # OCI spec utilities
│   │   └── seccomp/        # OCI seccomp spec handling
│   ├── starttime/          # Process start time tracking
│   └── version/            # Version information
├── shim/                   # containerd shim binary
│   ├── main.go             # Shim entrypoint
│   └── v1/                 # Shim v1 CLI
├── tools/                  # Development tools
│   ├── checklocks/         # Lock ordering analysis tool
│   └── xdp/                # XDP development tools
├── webhook/                # Kubernetes mutating webhook
│   ├── main.go             # Webhook entrypoint
│   └── pkg/
│       ├── cli/            # Webhook CLI
│       └── injector/       # Webhook injection logic
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
└── README.md               # Project readme
```

## Directory Purposes

**`pkg/sentry/`:**
- Purpose: The core user-space kernel ("sentry") that intercepts and handles system calls
- Contains: All kernel subsystem reimplementations (~234K lines of Go excluding autogen)
- Key files: `kernel/kernel.go` (Kernel struct, ~2106 lines), `kernel/task.go` (Task struct), `vfs/vfs.go` (VFS2)

**`pkg/tcpip/`:**
- Purpose: Complete user-space TCP/IP networking stack (netstack)
- Contains: Full protocol implementations from link layer to transport layer (~84K lines)
- Key files: `stack/stack.go` (Stack struct), `transport/tcp/`, `transport/udp/`

**`runsc/`:**
- Purpose: The `runsc` OCI runtime binary - host-side container management
- Contains: CLI, container lifecycle, sandbox process management, boot logic (~36K lines)
- Key files: `cli/main.go` (entrypoint), `boot/loader.go` (Loader), `sandbox/sandbox.go` (Sandbox)

**`pkg/lisafs/`:**
- Purpose: LISAFS (LInux SAndbox FileSystem) protocol for sandbox-gofer communication
- Contains: Client/server implementation, message types, connection management
- Key files: `client.go`, `server.go`, `handlers.go`, `connection.go`

**`pkg/sentry/platform/`:**
- Purpose: Platform abstraction - how syscalls are intercepted and user code is executed
- Contains: Platform interface definition and three implementations
- Key files: `platform.go` (interface), `kvm/kvm.go`, `systrap/systrap.go`, `ptrace/ptrace.go`

**`runsc/boot/filter/`:**
- Purpose: Seccomp-BPF filter rules applied to the sandbox process
- Contains: Filter configuration split by feature (hostinet, profile, race, CGo, platform-specific)
- Key files: `filter.go` (entry), `config/config.go` (rule assembly), `config/config_main.go`

**`pkg/sentry/fsimpl/gofer/`:**
- Purpose: Gofer client filesystem - connects sandbox VFS to the gofer process
- Contains: Dentry, inode, file description implementations using LISAFS
- Key files: `gofer.go`, `filesystem.go`, `lisafs_inode.go`, `directfs_inode.go`

## Key File Locations

**Entry Points:**
- `runsc/cli/main.go`: runsc CLI entrypoint (`Main()`)
- `runsc/cmd/boot.go`: Sandbox boot subcommand (starts sentry)
- `runsc/cmd/gofer.go`: Gofer process subcommand
- `shim/main.go`: containerd shim entrypoint
- `webhook/main.go`: Kubernetes webhook entrypoint

**Configuration:**
- `runsc/config/config.go`: `Config` struct with all runtime flags (~400 fields)
- `runsc/config/flags.go`: Flag registration
- `go.mod`: Go module and dependency management

**Core Logic:**
- `runsc/boot/loader.go`: `Loader` struct - kernel bootstrap and lifecycle
- `runsc/sandbox/sandbox.go`: `Sandbox` struct - host-side sandbox management
- `runsc/container/container.go`: `Container` struct - container lifecycle
- `runsc/boot/controller.go`: uRPC control server (sandbox commands)
- `runsc/boot/vfs.go`: VFS mount setup
- `runsc/boot/network.go`: Network stack setup

**Kernel Core:**
- `pkg/sentry/kernel/kernel.go`: `Kernel` struct (~2106 lines)
- `pkg/sentry/kernel/task.go`: `Task` struct
- `pkg/sentry/kernel/task_run.go`: Task state machine
- `pkg/sentry/kernel/task_syscall.go`: Syscall dispatch
- `pkg/sentry/syscalls/linux/linux64.go`: Syscall table
- `pkg/sentry/platform/platform.go`: Platform interface

**Networking:**
- `pkg/tcpip/stack/stack.go`: Network stack core
- `pkg/tcpip/transport/tcp/`: TCP implementation
- `pkg/tcpip/transport/udp/`: UDP implementation
- `pkg/sentry/socket/netstack/`: Netstack socket provider

## Naming Conventions

**Files:**
- Snake case for multi-word: `task_run.go`, `fd_table.go`, `file_description.go`
- Architecture-specific suffixes: `*_amd64.go`, `*_arm64.go`
- Unsafe code suffixes: `*_unsafe.go`
- Auto-generated: `*_state_autogen.go`, `*_abi_autogen_unsafe.go`
- Test files: `*_test.go` (not present in this synthetic Go branch)
- Filter/config splits: `extra_filters_hostinet.go`, `config_profile.go`

**Directories:**
- Lowercase, single word preferred: `kernel/`, `vfs/`, `boot/`, `auth/`
- Combined lowercase for compound names: `fsimpl/`, `pgalloc/`, `hostarch/`, `netstack/`
- Version suffixes for shim: `v1/`

**Packages:**
- Package name matches directory name
- Package-level doc comments describe purpose
- Internal packages use descriptive names matching their subsystem

**Types and Interfaces:**
- CamelCase for exported types: `Kernel`, `Task`, `Loader`, `Sandbox`, `Container`
- Interfaces named for capability: `Platform`, `FilesystemImpl`, `FileDescriptionImpl`
- Implementation structs named for what they are: `VirtualFilesystem`, `MemoryManager`
- State enums as typed ints with const blocks: `loaderState`, `ContainerRuntimeState`

## Where to Add New Code

**New Syscall Implementation:**
- Primary code: `pkg/sentry/syscalls/linux/sys_<name>.go`
- Register in: `pkg/sentry/syscalls/linux/linux64.go` (syscall table)
- Architecture-specific: `pkg/sentry/syscalls/linux/sys_<name>_amd64.go` / `*_arm64.go`

**New Filesystem:**
- Implementation: `pkg/sentry/fsimpl/<fsname>/`
- Must implement: `vfs.FilesystemImpl`, `vfs.DentryImpl`, `vfs.FileDescriptionImpl` interfaces
- Register type in: `runsc/boot/vfs.go` during VFS setup
- Can extend: `pkg/sentry/fsimpl/kernfs/` base for synthetic filesystems

**New Platform:**
- Implementation: `pkg/sentry/platform/<name>/`
- Must implement: `platform.Platform` interface from `pkg/sentry/platform/platform.go`
- Register in: `pkg/sentry/platform/platforms/` (imports for side-effect registration)
- Add seccomp filter rules: `pkg/sentry/platform/<name>/filters.go`

**New Device:**
- Implementation: `pkg/sentry/devices/<name>/`
- Register with VFS device registry
- Example pattern: `pkg/sentry/devices/nvproxy/` (NVIDIA GPU proxy)

**New CLI Subcommand:**
- Implementation: `runsc/cmd/<name>.go`
- Must implement: `subcommands.Command` interface
- Register in: `runsc/cli/main.go` -> `forEachCmd()`

**New Network Protocol:**
- Transport: `pkg/tcpip/transport/<proto>/`
- Network: `pkg/tcpip/network/<proto>/`
- Link: `pkg/tcpip/link/<name>/`
- Register with stack in: `runsc/boot/loader.go` (network stack creation)

**New Seccomp Filter Rules:**
- Sandbox filters: `runsc/boot/filter/config/`
- Gofer filters: `runsc/fsgofer/filter/`
- Use `pkg/seccomp/` to build BPF programs

**Utilities/Helpers:**
- Shared helpers: `pkg/<name>/` (create a new package for reusable utilities)
- OS-level helpers: `pkg/hostarch/`, `pkg/hostos/`, `pkg/hostsyscall/`
- Container runtime helpers: `runsc/specutils/`

## Special Directories

**Auto-generated Files (`*_state_autogen.go`, `*_abi_autogen_unsafe.go`):**
- Purpose: Generated by stateify (serialization) and go_marshal (ABI marshaling)
- Generated: Yes (by build tools, typically Bazel)
- Committed: Yes (this is a synthetic Go-tools-compatible branch)
- Do not edit manually

**`pkg/ring0/`:**
- Purpose: Ring 0 kernel mode support for KVM platform
- Contains: Assembly entry points, page tables, kernel definitions
- Architecture-specific assembly: `entry_amd64.s`, `entry_arm64.s`

**`pkg/sentry/platform/systrap/sysmsg/`:**
- Purpose: Shared memory message passing between sentry and systrap stubs
- Contains: Definitions for the fast syscall interception path

**`runsc/boot/filter/config/`:**
- Purpose: Modular seccomp filter rules, one file per feature/platform
- Pattern: Each file returns `[]seccomp.RuleSet` for its concern

---

*Structure analysis: 2026-03-08*
