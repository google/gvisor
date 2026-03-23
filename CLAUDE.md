# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is gVisor?

gVisor is an application kernel that implements a substantial portion of the Linux system surface in Go. It intercepts application system calls and acts as the guest kernel, providing a security boundary between the host and the application. The main binary is `runsc`, an OCI-compatible container runtime.

## Build System

gVisor uses **Bazel** (version 8, specified in `.bazelversion`) with Make wrappers. Builds run inside Docker containers by default.

### Key Commands

```bash
# Build
make build TARGETS=//runsc                    # Build runsc binary
make copy TARGETS=runsc DESTINATION=/tmp      # Build and copy binary

# Test
make test TARGETS="//pkg/buffer:buffer_test"  # Run a single test
make unit-tests                                # All unit tests (pkg/...)
make syscall-tests                             # Syscall compatibility tests
make tests                                     # All tests (unit + syscall)
make nogo-tests                                # Lint/static analysis

# Development workflow
make dev                                       # Build and install runsc as Docker runtime
make refresh                                   # Refresh binary after changes
docker run --runtime=my-branch --rm hello-world

# Direct Bazel usage
bazel test //pkg/buffer:buffer_test
bazel test ...                                 # All tests
bazel build :gopath                            # Generate GOPATH tree for editor support
```

To disable Docker-containerized builds: `DOCKER_BUILD=false`.

### BUILD Files

Use custom rule wrappers from `//tools:defs.bzl`, not raw Bazel rules:

```python
load("//tools:defs.bzl", "go_library", "go_test")
```

`go_library()` automatically runs stateify (serialization codegen), go_marshal (ABI-safe struct codegen), and nogo analysis. `go_test()` uses `library` attribute to link the package under test.

## Architecture

- **`pkg/sentry/`** — The application kernel: kernel implementation, filesystem (`fsimpl/`), memory management (`mm/`), platform abstractions, socket/networking, architecture-specific code
- **`pkg/tcpip/`** — Full userspace TCP/IP network stack (netstack)
- **`runsc/`** — OCI container runtime binary: CLI commands (`cmd/`), container lifecycle (`container/`), bootstrap (`boot/`), host filesystem access (`fsgofer/`), configuration (`config/`)
- **`shim/`** — containerd runtime shim (v2)
- **`tools/`** — Build infrastructure: custom Bazel rules (`defs.bzl`), nogo linter, code generators (go_marshal, go_stateify, go_generics), analysis tools (checklocks, checkescape, checkunsafe)
- **`test/`** — Integration tests: syscall tests (`syscalls/`, mostly C++), e2e tests, benchmarks, Docker integration tests

## Coding Rules

### Dependency Restrictions

**Core** (`//pkg/sentry/...` and its transitive deps in `//pkg/...`):
- No cgo — must be statically-linked pure Go
- Files importing `unsafe` must be named `*_unsafe.go`
- Only allowed external deps: stdlib, `golang.org/x/sys/unix`, `golang.org/x/time/rate`, `github.com/google/btree`, protobuf

**runsc** (`//runsc/...`):
- No cgo — pure Go binary
- Additional allowed deps: `github.com/google/subcommands`, `github.com/opencontainers/runtime-spec`
- `runsc boot` must not run the netpoller goroutine (performance)

### Style

Follows [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and [Effective Go](https://golang.org/doc/effective_go.html). Key project-specific conventions:

- **Early exit** from loops and functions where possible
- **Mutexes**: name `mu` or `xxxMu`, never exported; place before protected fields; comment ordering requirements
- **Function comments**: use `Preconditions:` and `Postconditions:` blocks for entry/exit conditions (one condition per bullet `*`)
- **Unused returns**: explicitly ignore with underscores
- **Formatting verbs**: use `%v` for non-builtin types even if they implement Stringer; use `%w` only with `fmt.Errorf`
- **Comments** wrapped at 80 columns (2-space tab)
- C++ code (syscall tests) follows Google C++ Style Guide

### Bug IDs

`b/1234` references in TODOs/NOTEs refer to an internal bug tracker — ignore them.

## Updating Dependencies

```bash
git checkout origin/go
go get <package>
git checkout origin/master
bazel run //:gazelle -- update-repos -from_file=go.mod
```

## Linting (nogo)

Custom static analysis runs automatically as part of builds. Configuration in `nogo.yaml`. Custom analyzers in `tools/`: checklocks (mutex ordering), checkescape (escape analysis), checkunsafe, checkaligned, checkconst, checklinkname.

## Our goal
**Author:** @Alessio Toniolo 

**Reviewers:** @Peyton 

## Summary

Support gVisor for multi-node workloads

## Motivation


Currently, multi-node containers assume ownership of the entire host. This provides limited flexibility, as machines with low GPU utilization from one container cannot allow other containers with higher utilization requirements to be scheduled onto the same host.

## Goals

1. Get RDMA working inside of gVisor

## High-level explanation

gVisor is composed of two main systems: the Sentry, which intercepts systems calls, and the Gofer, which provides file system access to containers. The sentry and gofer communicate with each other via the [9P protocol](https://en.wikipedia.org/wiki/9P_(protocol)). 

In single-node scenarios, gVisor provides host-level isolation guarantees by trapping syscalls to common devices/file descriptors. It sits between the host kernel ↔ application and acts as a guest kernel with rule-based execution. We want to modify gVisor’s internals to accomodate applications that must bypas the kernel for IB verbs.

There are three main platforms for intercepting syscalls:

1. [systrap](https://gvisor.dev/docs/architecture_guide/platforms/#systrap) will mark system calls to the host with the `SIGSYS` signal, whcih are then communicated via a stub thread to the Sentry for interception. `systrap` allows for GPU support in both bare metal environments and environments with nested virtualization .
2. [KVM](https://gvisor.dev/docs/architecture_guide/platforms/#kvm) allows you to run virtualized machiens via the Linux kernel. Since KVM runs best on bare-metal setups and performs poorly with nested virtualization, we will want to use systrap for GPU workloads that may run on cloud hypervisors.
3. [ptrace](https://gvisor.dev/docs/architecture_guide/platforms/#ptrace) lets the application run user-side code without allowing it to make system calls to the host. While ptrace allows for increased flexibilty in what environments you run it in, any system-call heavy application will suffer a massive performance penalty due to the high context switch overhead. This platform is being phased out of gVisor, so we want to stick to systrap.

## Implementation

### High-level Overview

1. Trap all syscalls to the uverbs API, which is available in `/dev/infinibad/uverbs0` .
    
    ```bash
    touch nccl_allreduce.cu
    nano nccl_allreduce.cu
    # paste this code: https://claude.ai/artifacts/8af80140-80c7-4089-be57-3a1b8f1b493a
    # save the file ctrl+x and enter
    sudo apt install nvidia-cuda-toolkit
    # NCCL is a separate package from the toolkit
    sudo apt-get install libnccl-dev
    # compile the script 
    nvcc -o nccl_allreduce nccl_allreduce.cu -lnccl
    # run the script with strace
    CUDA_VISIBLE_DEVICES=0,1 NCCL_P2P_DISABLE=1 NCCL_SHM_DISABLE=1 NCCL_IB_HCA=mlx5_1 strace -e trace=mmap,ioctl,open,close ./nccl_allreduce 2>/tmp/strace.log
    # send these logs to your local device using magic-wormhole
    sudo apt install magic-wormhole
    wormhole send /tmp/strace.log
    # on your own device, run the command output to receive it
    # parse the uverb ioctl headers
    touch minimal_sniffer.c
    nano minimal_sniffer.c
    # paste this code: https://gist.github.com/atoniolo76/9786e04327c6a13d26e0ef99dc784ca1
    gcc -shared -fPIC -o minimal_sniff.so minimal_sniff.c -ldl
    # rerun the above script with the sniffer
    LD_PRELOAD=./minimal_sniff.so CUDA_VISIBLE_DEVICES=0,1 NCCL_P2P_DISABLE=1 NCCL_SHM_DISABLE=1 NCCL_IB_HCA=mlx5_1 ./nccl_allreduce 2 2>/tmp/sniff_decoded.log
    wormhole send /tmp/sniff_decoded.log
    # you can also run a simpler test to get less log output
    LD_PRELOAD=./minimal_sniff.so ib_write_bw -d mlx5_1 2>/tmp/sniff_v2.log
    # on the client
    ib_write_bw -d mlx5_1 <ipv4-addr-server>
    # send the output to your computer
    wormhole send /tmp/sniff_v2.log
    ```
    
- Here is the sample output of sniffing a ib_write_bw call wtih this sniffer script: https://gist.github.com/atoniolo76/9786e04327c6a13d26e0ef99dc784ca1
    
    [SNIFF] 20:50:33.408128 tid=3284291 OPEN /dev/infiniband/uverbs1 => fd=3
    [SNIFF] 20:50:33.408222 tid=3284291 IOCTL fd=3 DEVICE           CAPABILITY_PROBE     attrs=1 len=40 drv=1 => FAIL (errno=28/No space left on device)
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF] 20:50:33.409350 tid=3284291 IOCTL fd=3 DEVICE           QUERY_GID            attrs=4 len=88 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=4     flags=0x0003 data=0x00007ffe1c175558
    [SNIFF]     attr[01] id=0x0001 len=8     flags=0x0003 data=0x00007ffe1c175560
    [SNIFF]     attr[02] id=0x1000 len=32    flags=0x0001 data=0x00007ffe1c175640
    [SNIFF]       0000: 10 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00
    [SNIFF]       0010: 01 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00
    [SNIFF]     attr[03] id=0x1001 len=72    flags=0x0003 data=0x00007ffe1c175668
    [SNIFF]       0000: 00 00 02 00 00 02 00 00 00 00 00 00 40 00 00 00
    [SNIFF]       0010: 00 04 00 02 00 80 00 00 00 80 00 00 00 80 00 00
    [SNIFF]       0020: 01 00 00 00 2f 00 00 00 48 00 00 00 01 03 00 01
    [SNIFF]       0030: 00 00 00 00 00 00 00 00 0c 00 00 00 01 00 00 00
    [SNIFF] 20:50:33.409525 tid=3284291 MMAP fd=3 (/dev/infiniband/uverbs1) len=4096 prot=R- offset=0x500000 => 0x7f4327ef2000
    [SNIFF] 20:50:33.409543 tid=3284291 MMAP fd=3 (/dev/infiniband/uverbs1) len=4096 prot=R- offset=0x700000 => 0x7f4327e9f000
    [SNIFF] 20:50:33.410824 tid=3284291 IOCTL fd=3 OBJ(0x1000)      QUERY_HCA_CAP        attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=16    flags=0x0001 data=0x00007ffe1c172160
    [SNIFF]       0000: 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00
    [SNIFF]     attr[01] id=0x1001 len=4112  flags=0x0003 data=0x00007ffe1c172180
    [SNIFF] 20:50:33.411155 tid=3284291 IOCTL fd=3 OBJ(0x1000)      QUERY_HCA_CAP        attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=16    flags=0x0001 data=0x00007ffe1c172170
    [SNIFF]       0000: 01 00 00 00 00 00 00 41 00 00 00 00 00 00 00 00
    [SNIFF]     attr[01] id=0x1001 len=4112  flags=0x0003 data=0x00007ffe1c173190
    [SNIFF] 20:50:33.411340 tid=3284291 IOCTL fd=3 OBJ(0x1000)      QUERY_HCA_CAP        attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=16    flags=0x0001 data=0x00007ffe1c1741e0
    [SNIFF]       0000: 01 00 00 00 00 00 00 19 00 00 00 00 00 00 00 00
    [SNIFF]     attr[01] id=0x1001 len=4112  flags=0x0003 data=0x00007ffe1c174390
    [SNIFF] 20:50:33.411564 tid=3284291 IOCTL fd=3 DEVICE           ALLOC_CONTEXT_EX     attrs=4 len=88 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000080000001
    [SNIFF]     attr[01] id=0x0000 len=8     flags=0x0001 data=0x0000000000000000
    [SNIFF]     attr[02] id=0x0001 len=304   flags=0x0003 data=0x00007ffe1c1741f0
    [SNIFF]       0000: f6 03 2b 00 1c 00 00 00 b7 1c 01 96 8e 94 95 05
    [SNIFF]       0010: 94 6d ae 03 00 b7 60 92 ff ff ff ff ff ff ff ff
    [SNIFF]       0020: 00 f0 ff ff ff ff ff ff c9 02 00 00 1e 10 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 02 00 00 80 00 00 36 1c 36 21
    [SNIFF]     attr[03] id=0x1001 len=112   flags=0x0003 data=0x00007ffe1c174320
    [SNIFF]       0000: 00 00 00 00 70 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0020: 40 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 00 00 00 00 00 00 0f 00 00 00
    [SNIFF] 20:50:33.412063 tid=3284291 IOCTL fd=3 DEVICE           QUERY_PORT           attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0001 len=48    flags=0x0003 data=0x00007ffe1c175300
    [SNIFF]       0000: 48 ec 51 a3 00 00 00 40 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 08 00 00 00 80 00 11 02 01 00 04 05 05 00 03 00
    [SNIFF]       0020: 12 00 02 80 05 01 00 00 32 04 00 00 80 00 00 00
    [SNIFF] 20:50:33.412253 tid=3284291 IOCTL fd=3 OBJ(0x1008)      ALLOC_UAR            attrs=5 len=104 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=0     flags=0x0001 data=0x0000000000000000
    [SNIFF]     attr[01] id=0x1001 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[02] id=0x1002 len=8     flags=0x0003 data=0x000055a932f43d58
    [SNIFF]     attr[03] id=0x1003 len=4     flags=0x0003 data=0x000055a932f43dbc
    [SNIFF]     attr[04] id=0x1004 len=4     flags=0x0003 data=0x000055a932f43dc0
    [SNIFF] 20:50:33.412271 tid=3284291 MMAP fd=3 (/dev/infiniband/uverbs1) len=4096 prot=-W offset=0x900000 => 0x7f4327e9e000
    [SNIFF] 20:50:33.412281 tid=3284291 IOCTL fd=3 OBJ(0x0010)      DESTROY              attrs=1 len=40 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=0     flags=0x0001 data=0x0000000000000004
    [SNIFF] 20:50:33.412287 tid=3284291 IOCTL fd=3 DEVICE           ALLOC_CONTEXT        attrs=3 len=72 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0000 len=8     flags=0x0001 data=0x00007ffe1c174560
    [SNIFF]     attr[02] id=0x0001 len=176   flags=0x0003 data=0x00007ffe1c174560
    [SNIFF]       0000: f6 03 2b 00 1c 00 00 00 b7 1c 01 96 8e 94 95 05
    [SNIFF]       0010: 94 6d ae 03 00 b7 60 92 ff ff ff ff ff ff ff ff
    [SNIFF]       0020: 00 f0 ff ff ff ff ff ff c9 02 00 00 1e 10 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 02 00 00 80 00 00 36 1c 36 21
    [SNIFF] 20:50:33.412702 tid=3284291 IOCTL fd=3 DEVICE           QUERY_PORT           attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0001 len=48    flags=0x0003 data=0x00007ffe1c1756d0
    [SNIFF]       0000: 48 ec 51 a3 00 00 00 40 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 08 00 00 00 80 00 11 02 01 00 04 05 05 00 03 00
    [SNIFF]       0020: 12 00 02 80 05 01 00 00 32 04 00 00 80 00 00 00
    [SNIFF] 20:50:33.412744 tid=3284291 IOCTL fd=3 DEVICE           ALLOC_CONTEXT        attrs=3 len=72 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0000 len=8     flags=0x0001 data=0x00007ffe1c174550
    [SNIFF]     attr[02] id=0x0001 len=176   flags=0x0003 data=0x00007ffe1c174550
    [SNIFF]       0000: f6 03 2b 00 1c 00 00 00 b7 1c 01 96 8e 94 95 05
    [SNIFF]       0010: 94 6d ae 03 00 b7 60 92 ff ff ff ff ff ff ff ff
    [SNIFF]       0020: 00 f0 ff ff ff ff ff ff c9 02 00 00 1e 10 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 02 00 00 80 00 00 36 1c 36 21
    [SNIFF] 20:50:41.126888 tid=3284291 IOCTL fd=3 DEVICE           QUERY_PORT           attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0001 len=48    flags=0x0003 data=0x00007ffe1c175640
    [SNIFF]       0000: 48 ec 51 a3 00 00 00 40 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 08 00 00 00 80 00 11 02 01 00 04 05 05 00 03 00
    [SNIFF]       0020: 12 00 02 80 05 01 00 00 32 04 00 00 80 00 00 00
    [SNIFF] 20:50:41.126983 tid=3284291 IOCTL fd=3 DEVICE           ALLOC_CONTEXT        attrs=3 len=72 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0000 len=8     flags=0x0001 data=0x00007ffe1c174460
    [SNIFF]     attr[02] id=0x0001 len=176   flags=0x0003 data=0x00007ffe1c174460
    [SNIFF]       0000: f6 03 2b 00 1c 00 00 00 b7 1c 01 96 8e 94 95 05
    [SNIFF]       0010: 94 6d ae 03 00 b7 60 92 ff ff ff ff ff ff ff ff
    [SNIFF]       0020: 00 f0 ff ff ff ff ff ff c9 02 00 00 1e 10 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 02 00 00 80 00 00 36 1c 36 21
    [SNIFF] 20:50:41.127188 tid=3284291 IOCTL fd=3 DEVICE           ALLOC_CONTEXT_EX     attrs=4 len=88 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000000000003
    [SNIFF]     attr[01] id=0x0000 len=8     flags=0x0001 data=0x00007ffe1c1756b8
    [SNIFF]     attr[02] id=0x0001 len=4     flags=0x0003 data=0x00007ffe1c1756b8
    [SNIFF]     attr[03] id=0x1001 len=4     flags=0x0003 data=0x00007ffe1c1756bc
    [SNIFF] 20:50:41.127533 tid=3284291 IOCTL fd=3 DEVICE           ALLOC_CONTEXT        attrs=3 len=72 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x0000000000000009
    [SNIFF]     attr[01] id=0x0000 len=40    flags=0x0001 data=0x00007ffe1c175598
    [SNIFF]       0000: 84 55 17 1c fe 7f 00 00 00 40 94 27 43 7f 00 00
    [SNIFF]       0010: 00 00 02 00 00 00 00 00 00 40 94 27 43 7f 00 00
    [SNIFF]       0020: 01 00 00 00 03 00 10 00
    [SNIFF]     attr[02] id=0x0001 len=12    flags=0x0003 data=0x00007ffe1c175584
    [SNIFF]       0000: 02 00 00 00 00 08 04 00 00 08 04 00
    [SNIFF] 20:50:41.127934 tid=3284291 IOCTL fd=3 CQ               CREATE               attrs=8 len=152 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=0     flags=0x0001 data=0x0000000000000003
    [SNIFF]     attr[01] id=0x0006 len=4     flags=0x0003 data=0x00007ffe1c1752dc
    [SNIFF]     attr[02] id=0x0001 len=4     flags=0x0001 data=0x00000000000000ff
    [SNIFF]     attr[03] id=0x0002 len=8     flags=0x0001 data=0x000055a932f443a0
    [SNIFF]     attr[04] id=0x0004 len=4     flags=0x0001 data=0x0000000000000000
    [SNIFF]     attr[05] id=0x0007 len=0     flags=0x0000 data=0x0000000000000004
    [SNIFF]     attr[06] id=0x1000 len=32    flags=0x0001 data=0x00007ffe1c175538
    [SNIFF]       0000: 00 30 f5 32 a9 55 00 00 00 80 f5 32 a9 55 00 00
    [SNIFF]       0010: 40 00 00 00 00 00 02 00 11 00 00 00 00 00 00 00
    [SNIFF]     attr[07] id=0x1001 len=8     flags=0x0003 data=0x00007ffe1c175570
    [SNIFF] 20:50:41.128127 tid=3284291 IOCTL fd=3 OBJ(0x1008)      ALLOC_UAR            attrs=5 len=104 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=0     flags=0x0001 data=0x0000000000000004
    [SNIFF]     attr[01] id=0x1001 len=8     flags=0x0001 data=0x0000000000000000
    [SNIFF]     attr[02] id=0x1002 len=8     flags=0x0003 data=0x000055a932f52d98
    [SNIFF]     attr[03] id=0x1003 len=4     flags=0x0003 data=0x000055a932f52dfc
    [SNIFF]     attr[04] id=0x1004 len=4     flags=0x0003 data=0x000055a932f52e00
    [SNIFF] 20:50:41.128155 tid=3284291 MMAP fd=3 (/dev/infiniband/uverbs1) len=4096 prot=-W offset=0x901000 => 0x7f4327e9d000
    [SNIFF] 20:50:41.130126 tid=3284291 IOCTL fd=3 QP               CREATE               attrs=12 len=216 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=0     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0004 len=0     flags=0x0001 data=0x0000000000000003
    [SNIFF]     attr[02] id=0x0005 len=0     flags=0x0001 data=0x0000000000000003
    [SNIFF]     attr[03] id=0x0000 len=0     flags=0x0001 data=0x0000000000000005
    [SNIFF]     attr[04] id=0x0009 len=8     flags=0x0001 data=0x0000000000000002
    [SNIFF]     attr[05] id=0x0007 len=8     flags=0x0001 data=0x000055a932f52358
    [SNIFF]     attr[06] id=0x0008 len=20    flags=0x0001 data=0x00007ffe1c175570
    [SNIFF]       0000: 80 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00
    [SNIFF]       0010: 1c 00 00 00
    [SNIFF]     attr[07] id=0x000c len=0     flags=0x0001 data=0x0000000000000004
    [SNIFF]     attr[08] id=0x000d len=20    flags=0x0003 data=0x00007ffe1c175570
    [SNIFF]       0000: 80 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00
    [SNIFF]       0010: 1c 00 00 00
    [SNIFF]     attr[09] id=0x000e len=4     flags=0x0003 data=0x00007ffe1c174ebc
    [SNIFF]     attr[10] id=0x1000 len=56    flags=0x0001 data=0x00007ffe1c175350
    [SNIFF]       0000: 00 a0 f5 32 a9 55 00 00 40 80 f5 32 a9 55 00 00
    [SNIFF]       0010: 80 00 00 00 04 00 00 00 04 00 00 00 02 04 00 00
    [SNIFF]       0020: 00 00 00 00 12 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0030: 00 00 00 10 00 00 00 00
    [SNIFF]     attr[11] id=0x1001 len=40    flags=0x0003 data=0x00007ffe1c175240
    [SNIFF]       0000: 00 00 00 80 00 02 00 30 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0020: 00 00 00 00 00 00 00 00
    [SNIFF] 20:50:41.130438 tid=3284291 IOCTL fd=3 DEVICE           QUERY_CONTEXT        attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x000000000000001a
    [SNIFF]     attr[01] id=0x0000 len=112   flags=0x0001 data=0x00007ffe1c1752f8
    [SNIFF]       0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF] 20:50:41.130811 tid=3284291 IOCTL fd=3 DEVICE           QUERY_PORT           attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=8     flags=0x0001 data=0x0000000000000001
    [SNIFF]     attr[01] id=0x0001 len=48    flags=0x0003 data=0x00007ffe1c175650
    [SNIFF]       0000: 48 ec 51 a3 00 00 00 40 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 08 00 00 00 80 00 11 02 01 00 04 05 05 00 03 00
    [SNIFF]       0020: 12 00 02 80 05 01 00 00 32 04 00 00 80 00 00 00
    [SNIFF] 20:50:41.132079 tid=3284291 IOCTL fd=3 DEVICE           QUERY_CONTEXT        attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0002 len=8     flags=0x0001 data=0x000000000000001a
    [SNIFF]     attr[01] id=0x0000 len=112   flags=0x0001 data=0x00007ffe1c175348
    [SNIFF]       0000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0010: 00 00 00 00 c8 01 00 00 00 00 00 00 00 00 00 01
    [SNIFF]       0020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF]       0030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    [SNIFF] 20:50:41.404440 tid=3284291 IOCTL fd=3 QP               CREATE               attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0001 len=4     flags=0x0003 data=0x00007ffe1c1756f4
    [SNIFF]     attr[01] id=0x0000 len=0     flags=0x0001 data=0x0000000000000005
    [SNIFF] 20:50:41.404600 tid=3284291 IOCTL fd=3 CQ               CREATE               attrs=2 len=56 drv=1 => OK
    [SNIFF]     attr[00] id=0x0001 len=8     flags=0x0003 data=0x00007ffe1c1756e8
    [SNIFF]     attr[01] id=0x0000 len=0     flags=0x0001 data=0x0000000000000003
    [SNIFF] 20:50:41.404631 tid=3284291 IOCTL fd=3 MR               REG                  attrs=1 len=40 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=0     flags=0x0001 data=0x0000000000000002
    [SNIFF] 20:50:41.404686 tid=3284291 IOCTL fd=3 PD               DEALLOC              attrs=1 len=40 drv=1 => OK
    [SNIFF]     attr[00] id=0x0000 len=0     flags=0x0001 data=0x0000000000000001
    [SNIFF] 20:50:41.404703 tid=3284291 MUNMAP addr=0x7f4327ef2000 len=4096 (was fd=3) => OK
    [SNIFF] 20:50:41.404709 tid=3284291 MUNMAP addr=0x7f4327e9f000 len=4096 (was fd=3) => OK
    [SNIFF] 20:50:41.404715 tid=3284291 MUNMAP addr=0x7f4327e9d000 len=4096 (was fd=3) => OK
    [SNIFF] 20:50:41.404784 tid=3284291 IOCTL fd=3 OBJ(0x1008)      DEALLOC_UAR          attrs=1 len=40 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=0     flags=0x0001 data=0x0000000000000004
    [SNIFF] 20:50:41.404793 tid=3284291 MUNMAP addr=0x7f4327e9e000 len=4096 (was fd=3) => OK
    [SNIFF] 20:50:41.404855 tid=3284291 IOCTL fd=3 OBJ(0x1008)      DEALLOC_UAR          attrs=1 len=40 drv=1 => OK
    [SNIFF]     attr[00] id=0x1000 len=0     flags=0x0001 data=0x0000000000000000
    [SNIFF] 20:50:41.404861 tid=3284291 CLOSE fd=3 (/dev/infiniband/uverbs1)
    alessio@alessios-MacBook-Air ~ %
    
- Here’s a chunk of the NCCL all-reduce trace output
    
    mmap(0x7f13e1dec000, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, 27, 0) = 0x7f13e1dec000
    close(27)                               = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2b, 0x30), 0x7ffcd81faa60) = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), 0x7ffcd81f9ae0) = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2b, 0x30), 0x7ffcd81fab80) = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), 0x7ffcd81f9aa0) = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), 0x7ffcd81f9af0) = 0
    ioctl(9, _IOC(_IOC_NONE, 0, 0x1b, 0), 0x7ffcd81fb220) = 0
    ioctl(9, _IOC(_IOC_NONE, 0, 0x1b, 0), 0x7ffcd81fb220) = 0
    ioctl(9, _IOC(_IOC_NONE, 0, 0x1b, 0), 0x7ffcd81fb220) = 0
    ioctl(9, _IOC(_IOC_NONE, 0, 0x1b, 0), 0x7ffcd81fb220) = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), 0x7ffcd81fa130) = 0
    ioctl(27, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0xc9, 0x4), 0x7ffcd81fb130) = 0
    ioctl(27, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0xce, 0x10), 0x7ffcd81fb120) = 0
    ioctl(27, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2b, 0x30), 0x7ffcd81fb110) = 0
    ioctl(8, _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2b, 0x30), 0x7ffcd81fb060) = 0
    mmap(NULL, 155648, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f15ec067000
    
NEXT TODO: Expose sysfs for InfiniBand device discovery, then implement uverbs device proxy.

### Host Device Layout (9x mlx5 HCAs on 2x8 H100 node)

**Character devices** (`/dev/infiniband/`):
- `uverbs0`–`uverbs8` — major 231, minors 192–200 (mode 0666)
- `umad0`–`umad8` — major 231, minors 0–8
- `issm1`–`issm8` — major 231, minors 65–72
- `rdma_cm` — major 10, minor 121 (misc device)

**Sysfs for device discovery** (required for libibverbs):
- `/sys/class/infiniband_verbs/uverbsN/` — `ibdev` (e.g. "mlx5_0"), `abi_version` ("1"), `dev` ("231:192"), `device` symlink
- `/sys/class/infiniband/mlx5_N/` — `node_type` ("1: CA"), `node_guid`, `sys_image_guid`, `fw_ver`, `hca_type`, `hw_rev`, `board_id`, `node_desc`
- `/sys/class/infiniband/mlx5_N/ports/1/` — `state`, `phys_state`, `link_layer`, `rate`, `lid`, `sm_lid`, `sm_sl`, `cap_mask`, `gids/`, `pkeys/`, `gid_attrs/`, `counters/`, `hw_counters/`

**Discovery flow** (from strace of `ibv_devinfo`):
1. `socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA)` → fails with `EPROTONOSUPPORT` (expected, gVisor doesn't support this)
2. Falls back to `openat("/sys/class/infiniband_verbs")` → currently `ENOENT` ← **this is what we need to fix first**
3. Reads `ibdev`, `abi_version` for each uverbsN
4. Opens `/dev/infiniband/uverbsN` and issues ioctls

### Implementation Steps

1. **Virtual sysfs provider for infiniband** — expose `/sys/class/infiniband_verbs/` and `/sys/class/infiniband/` trees in the sentry (similar to nvproxy's sysfs for `/sys/bus/pci/devices/`)
2. **uverbs device proxy** — virtual `/dev/infiniband/uverbs0` chardev that intercepts and safety-checks ioctls, using the same pin-translate-forward pattern as TPU proxy for memory registration
3. **Seccomp allowlist** — permit uverbs ioctl commands through the BPF filter
4. Add link endpoints that speak InfiniBand verbs
5. Update [NVProxy](https://github.com/google/gvisor/tree/90faaeb34f23eded12ec65c68af395ac4273c331/pkg/sentry/devices/nvproxy) to isolate RDMA NICs in `NVIDIA_VISIBLE_DEVICES` given OCI config. We may not need this?

### Big Questions
- How do we quickly test RDMA support? What will this look like in the upstream repo? How can we make local development align closely with upstream testing so we don’t have to rewrite the testing suite from scratch?
    - We will need to have an automated test suite for RDMA that can involve both mock tests e.g. using a sample input of syscalls (see above) and performance/functionality tests that must be run on a GPU worker with RDMA support e.g. 2x8:H100 nodes that must communicate over a ib_write_bw test

## Commentary from Github issue #10906 on https://github.com/google/gvisor.git
Having looked (maybe too) quickly at verbs, it should be possible to support if my understanding is correct. Thoughts:

Infiniband verbs are probably a bunch of ioctls for their special character device. We can support this: we'd make our own virtual per-container/pod /dev/infinibad/uverbs0 that understands and safety-checks ioctls. We'd also have syscall filters specific to Infiniband (e.g. GPUs).
Based on my super quick look at your links, I think libibverbs works by mapping in some shared memory for notification queues and packet data. This reminds me of XDP support, and so I think should work as well. We would need a link endpoint that speaks Infiniband verbs.
While the path to implementation seems reasonably clear, this is a significant chunk of work. The implementer would need to understand Infiniband verbs. I think we'd accept a PR for it, but for now it's not on the roadmap.

Syscall Interception     

  User app executes syscall instruction                                                                            
    ↓
  platform.Switch()          — pkg/sentry/platform/ptrace/ptrace.go:110                                            
    returns isSyscall=true                                                                                       
    ↓
  Task.doSyscall()           — pkg/sentry/kernel/task_syscall.go:213
    extracts sysno + args from registers                                                                           
    ↓
  Task.executeSyscall()      — pkg/sentry/kernel/task_syscall.go:84                                                
    ↓                                                       
  SyscallTable.Lookup(sysno) — pkg/sentry/kernel/syscalls.go
    table defined in pkg/sentry/syscalls/linux/linux64.go                                                          
   
  No changes needed here — this infrastructure handles all syscalls already.                                       
                                                            
  open path                                                                                                        
                                                            
  Openat()                                  — pkg/sentry/syscalls/linux/sys_file.go:84
    ↓                                                                                                              
  VirtualFilesystem.OpenAt()                — pkg/sentry/vfs/vfs.go:419                                            
    resolves path through filesystem layers                                                                        
    ↓                                                                                                              
  filesystem.OpenAt() on the /dev mount (devtmpfs/tmpfs)    
    sees it's a device special file                                                                                
    ↓
  VFS.OpenDeviceSpecialFile(kind, major, minor) — pkg/sentry/vfs/device.go:140                                     
    looks up (CharDevice, major, minor) in registered device map
    ↓                                                                                                              
  Device.Open(ctx, mnt, dentry, opts)       — your registered device's Open()
    ↓                                                                                                              
    ← NEW FILE: pkg/sentry/devices/rdmaproxy/rdmaproxy.go                                                          
    │  Define uverbsDevice struct implementing vfs.Device                                                          
    │  Register() calls vfsObj.GetDynamicCharDevMajor() then                                                       
    │  vfsObj.RegisterDevice(CharDevice, major, 0, &uverbsDevice{},                                                
    │    &RegisterDeviceOptions{Pathname: "infiniband/uverbs0"})                                                   
    │                                                                                                              
    ← NEW FILE: pkg/sentry/devices/rdmaproxy/frontend.go                                                           
    │  func (dev *uverbsDevice) Open(...) (*vfs.FileDescription, error)                                            
    │    - open host /dev/infiniband/uverbs0 fd                                                                    
    │    - create uverbsFD struct                                                                                  
    │    - call fd.vfsfd.Init(fd, flags, creds, mnt, vfsd, &opts)                                                  
    │    - return &fd.vfsfd                                                                                        
    │                                                                                                              
    ← EDIT: runsc/boot/vfs.go (around line 140, alongside other Register calls)                                    
    │  Add: rdmaproxy.Register(vfsObj)                                                                             
    ↓                                                       
  task.NewFDFrom(file)                      — assigns fd number in task's table                                    
                                                            
  ioctl path                                                                                                       
                                                            
  Ioctl()                          — pkg/sentry/syscalls/linux/sys_file.go:200
    task.GetFile(fd)               — resolves fd number → *vfs.FileDescription                                     
    handles generic ioctls (FIOCLEX, FIONBIO, etc.) inline                                                         
    ↓                                                                                                              
  file.Ioctl(t, uio, sysno, args) — pkg/sentry/vfs/file_description.go:720                                         
    ↓                                                                                                              
  fd.impl.Ioctl(...)              — dispatches to your uverbsFD.Ioctl()
    ↓                                                                                                              
    ← IN: pkg/sentry/devices/rdmaproxy/frontend.go          
    │  func (fd *uverbsFD) Ioctl(ctx, uio, sysno, args) (uintptr, error)                                           
    │    - extract cmd := args[1].Uint()                                                                           
    │    - extract nr := linux.IOC_NR(cmd), size := linux.IOC_SIZE(cmd)                                            
    │    - dispatch through handler table by nr                                                                    
    │                                                                                                              
    ← NEW FILE: pkg/sentry/devices/rdmaproxy/handlers.go                                                           
    │  Handler table: map command numbers → handler functions                                                      
    │  Each handler:                                                                                               
    │    1. CopyIn params from userspace                    
    │    2. Validate fields (handle refs, flags, bounds)                                                           
    │    3. Proxy validated ioctl to host fd                                                                       
    │    4. CopyOut results to userspace                                                                           
    │                                                                                                              
    ← NEW FILE: pkg/abi/linux/infiniband.go (or pkg/abi/rdma/)                                                     
    │  Ioctl command constants (IB_USER_VERBS_CMD_*, RDMA_VERBS_IOCTL)                                             
    │  Parameter structs with structs.HostLayout embedding                                                         
    │  e.g. IBUverbsQueryDevice, IBUverbsAllocPD, IBUverbsCreateCQ, etc.                                           
                                                                                                                   
  mmap path                                                                                                        
                                                                                                                   
  Mmap()                           — pkg/sentry/syscalls/linux/sys_mmap.go:40
    parses args into memmap.MMapOpts                                                                               
    task.GetFile(fd)
    ↓                                                                                                              
  file.ConfigureMMap(t, &opts)     — pkg/sentry/vfs/file_description.go:715
    ↓                                                                                                              
  fd.impl.ConfigureMMap(...)       — dispatches to your uverbsFD.ConfigureMMap()
    ↓                                                                                                              
    ← NEW FILE: pkg/sentry/devices/rdmaproxy/frontend_mmap.go
    │  func (fd *uverbsFD) ConfigureMMap(ctx, opts *memmap.MMapOpts) error                                         
    │    - validate opts.Offset is a known region
    │      (doorbell page, CQ buffer, etc.)                                                                        
    │    - validate page alignment                                                                                 
    │    - call vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)                                           
    │  func (fd *uverbsFD) Translate(...) — map to host fd backing                                                 
    ↓                                                                                                              
  task.MemoryManager().MMap(opts)  — actually installs the mapping         

## Sysfs entries that need to be exposed
modal@wo-56zx66rzbveo1nv7y5cn9fx55-prod-b694d5dc5440:~/gvisor$ ls /sys/class/infiniband_verbs/
  ls -la /sys/class/infiniband_verbs/uverbs0/
  cat /sys/class/infiniband_verbs/uverbs0/ibdev
  cat /sys/class/infiniband_verbs/uverbs0/abi_version
  ls /sys/class/infiniband/
abi_version  uverbs0  uverbs1  uverbs2  uverbs3  uverbs4  uverbs5  uverbs6  uverbs7  uverbs8
total 0
drwxr-xr-x 3 root root    0 Mar 17 21:04 .
drwxr-xr-x 3 root root    0 Mar 17 21:04 ..
-r--r--r-- 1 root root 4096 Mar 20 17:27 abi_version
-r--r--r-- 1 root root 4096 Mar 20 17:27 dev
lrwxrwxrwx 1 root root    0 Mar 20 17:27 device -> ../../../0000:00:07.0
-r--r--r-- 1 root root 4096 Mar 20 17:27 ibdev
drwxr-xr-x 2 root root    0 Mar 20 17:27 power
lrwxrwxrwx 1 root root    0 Mar 20 17:27 subsystem -> ../../../../../class/infiniband_verbs
-rw-r--r-- 1 root root 4096 Mar 17 21:04 uevent
mlx5_0
1
mlx5_0  mlx5_1  mlx5_2  mlx5_3  mlx5_4  mlx5_5  mlx5_6  mlx5_7  mlx5_8


NOTE that on some proivders IPoIB interfaces won't be present but rather ethernet interfaces will exist. See what it looks like on OCI:
modal@modal-worker-oci-h100-dj276id:~$ ls /sys/class/net
docker0        enp134s0f1np1  enp189s0f1np1  enp65s0f1np1  ens1240np0  modalsvc0     vethb244962d
enp12s0f0np0   enp165s0f0np0  enp42s0f0np0   enp88s0f0np0  lo          tailscale0    vethba4d4658
enp12s0f1np1   enp165s0f1np1  enp42s0f1np1   enp88s0f1np1  modal0      veth32882c05  vethbca493a1
enp134s0f0np0  enp189s0f0np0  enp65s0f0np0   ens1200np0    modal1      vetha9894ee5  vethd9f75e11
modal@modal-worker-oci-h100-dj276id:~$ lspci -vv | grep -i "Mellanox"
0c:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
0c:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
1f:00.0 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
	Subsystem: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
2a:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
2a:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
41:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
41:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
58:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
58:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
86:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
86:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
9a:00.0 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
	Subsystem: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
a5:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
a5:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
bd:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
bd:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7]
d5:00.0 Memory controller: Mellanox Technologies MT2910 Family [ConnectX-7 Flash Recovery]
	Subsystem: Mellanox Technologies MT2910 Family [ConnectX-7 Flash Recovery] 