# Performance Guide

[TOC]

gVisor is designed to provide a secure, virtualized environment while preserving
key benefits of containerization, such as small fixed overheads and a dynamic
resource footprint. For containerized infrastructure, this can provide a
turn-key solution for sandboxing untrusted workloads: there are no changes to
the fundamental resource model presented by containers.

## Instant cold starts & high packing density

gVisor's defining architectural advantage is combining strong multi-tenant sandbox
isolation with the simple resource model of standard Linux host processes. For multi-tenant compute
platforms, event-driven serverless engines, and modern AI agent sandboxes—such as
[**Substrate**](https://github.com/agent-substrate/substrate) and interactive code execution runtimes—gVisor enables a highly efficient
scale-from-zero operational model.

Hardware virtual machines and microVMs isolate tenants by partitioning physical
hardware. While secure, this architecture imposes two fundamental constraints:
1. **Guest-kernel boot overhead:** Every virtual machine must boot a dedicated Linux
   guest kernel, initialize virtual device models (e.g. virtio, PCI), run guest init
   systems, and configure guest memory tables before executing user code.
2. **Static memory partitioning:** MicroVMs and hardware virtual machines typically
   require pre-allocated, dedicated memory reservations carved out from the host.
   Because guest operating systems manage memory independently, physical RAM
   remains locked even when the workload is completely idle, capping host packing
   density.

gVisor takes a fundamentally different architectural approach: **process-based sandboxing**.
The [Sentry](../README.md#sentry) is an unprivileged userspace kernel written in Go that acts
as a secure boundary directly between the application and the host. This design delivers
three advantages:

* **Fast Cold Starts:** Starting a gVisor sandbox does not require booting a full guest
  OS and virtual hardware. Sandbox creation is as lightweight as launching a regular host
  process, with Sentry initialization completing in milliseconds (~169ms cold boot) to
  provide instantaneous cold starts for on-demand agentic workloads.
* **High Sandbox Packing Density:** Rather than carving out fixed RAM partitions, gVisor
  processes participate directly in host virtual memory management. A clean sandbox requires
  only **~14–45MB of fixed memory overhead** across real application workloads, and unneeded pages are reclaimed dynamically
  by the host. This avoids reserving static blocks of host RAM for idle instances, maximizing
  packing density and infrastructure utilization.
* **Stateful Snapshot Restoration:** Using gVisor's process-level checkpoint and restore
  primitives (`runsc checkpoint` / `runsc restore`), suspended sandboxes resume in
  **~100–300ms** with pre-warmed runtimes and pre-imported application libraries ready to serve.

### Structural costs vs. implementation costs

gVisor imposes runtime costs over native containers. These costs come in two forms:
additional cycles and memory usage, which may manifest as increased latency, reduced
throughput, or not at all. In general, these costs stem from two distinct sources:

First, the existence of the [Sentry](../README.md#sentry) means that additional
memory will be required, and application system calls must traverse additional
layers of software. The design emphasizes [security](/docs/architecture_guide/security/)
and therefore we chose to use a memory-safe language for the Sentry that provides benefits
in this domain but may not yet offer the raw performance of other choices. Costs imposed
by these design choices are **structural costs**.

Second, as gVisor is an independent implementation of the system call surface,
many of the subsystems or specific calls are not as optimized as more mature
implementations. A good example is the network stack, which is continuing
to evolve with features such as GRO/GSO and buffer pooling, but requires ongoing
tuning for complex congestion scenarios. This is an **implementation cost** and
is distinct from **structural costs**. Improvements here are ongoing and driven
by the workloads that matter to gVisor users and contributors.

## Methodology & platforms

All data below is statically benchmarked and measured using gVisor's open-source
[benchmark suite][benchmark-tools] executed on uniform [Google Compute Engine][gce]
Virtual Machines (VMs) with the following specifications:

```
Machine type: c2-standard-8 (Intel Cascade Lake, 8 vCPUs, 32GB RAM)
Image: Ubuntu 22.04 LTS (Linux kernel 5.15+)
BootDisk: 100GB SSD persistent disk
```

Through this document, results report measured data across three
runtime configurations:
- **`systrap`**: The default production gVisor platform. Uses userspace seccomp
  interception with shared-memory fast-paths for high-performance syscall handling
  without requiring hardware virtualization or elevated privileges.
- **`kvm`**: Hardware-assisted virtualization platform utilizing Linux KVM. When
  deployed on physical bare-metal hardware, KVM provides low-latency hardware-accelerated
  system call trapping. Because cloud CI environments operate under nested virtualization
  (which artificially inflates hypervisor VM exits for stateful I/O workloads), KVM is
  evaluated in the structural architectural sections (system call latency, startup, and
  memory footprint). Application and storage benchmarks focus on the production default
  (`systrap`) vs. native Linux (`runc`).
- **`runc`**: Unsandboxed Linux container baseline (native Linux host execution).

### Configuration & optimization flags

To accurately measure gVisor under production-recommended performance settings,
several runtime flags, compilation options, and harness isolation parameters are
configured. Any flag that is changed from upstream default settings is documented
below:

#### 1. Runtime flags (`runsc`)
These options are supplied via the container runtime engine (e.g. `/etc/docker/daemon.json`
or containerd configuration):
* **`--gvisor-gro=true` (Changed from default: `false`)**: Enables userspace Generic
  Receive Offload (GRO) in Netstack. GRO aggregates incoming network packets into larger
  virtual segments before traversing protocol layers, substantially reducing lock acquisitions,
  per-packet buffer allocations, and system call overhead in network-intensive workloads.
* **`--num-network-channels=4` (Changed from default: `1`)**: Allocates 4 independent
  network RX/TX channels across available host vCPUs. This removes single-channel Netstack
  serialization bottlenecks on multi-core VMs.
* **`--host-settings=adjust` (Changed from default: `ignore`)**: Automatically inspects
  and tunes host kernel networking parameters (e.g. `net.core.rmem_max`, `net.core.wmem_max`,
  `net.ipv4.tcp_rmem`, `net.ipv4.tcp_wmem`, and `net.core.somaxconn`) to match gVisor's
  internal buffer requirements, preventing packet drop during throughput bursts.
* **`--network=sandbox` (Default)**: Ensures network namespaces remain fully isolated
  inside userspace Netstack.

Sample Docker configuration (`/etc/docker/daemon.json`):
```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--gvisor-gro=true",
        "--num-network-channels=4",
        "--host-settings=adjust"
      ]
    }
  }
}
```

#### 2. Compilation and build flags
* **`-opt` / `--compilation_mode=opt`**: gVisor binaries (`runsc`, `sentry`) are built with
  full compiler optimization (`-tags=opt`), stripping debug overhead and enabling Go function inlining.
* **`--noshow_progress --noshow_loading_progress`**: Passed to Bazel to suppress terminal animation
  escapes and prevent stdout buffer contention during automated CI test runs.

## Start-up time & cold starts

For serverless functions, multi-tenant coding agents, and interactive microservices,
the ability to spin up secure containers instantaneously is critical. Because gVisor
is a process-based sandbox rather than a virtual machine, starting a sandbox
does not require booting a guest Linux kernel.

{% include graph.html id="startup" better="lower"
title="BenchmarkStartup* (//test/benchmarks/base:startup_test)" %}

The above figure indicates total start-up time across container workloads in
[`//test/benchmarks/base:startup_test`][startup-test]: an empty container (`sleep 100`),
an Nginx web server, and a Node.js application.

- **Empty container startup:** For trivial workloads, total startup time is dominated
  by Docker daemon container creation and cgroup setup latency (~120–180ms);
  native `runc` initializes an empty container in ~136ms, while `systrap` (~169ms)
  and `kvm` (~184ms) add minimal sandboxing overhead (~33–48ms) for Sentry
  initialization and seccomp filter configuration.
- **Application startup:** When launching real applications with runtime dependencies,
  file loading and module execution introduce expected sandboxing overhead:
  Nginx starts in ~417ms on `systrap` (~510ms on `kvm`) versus ~364ms on `runc`,
  and Node.js starts in ~682ms on `systrap` (~960ms on `kvm`) versus ~471ms on `runc`.
- **Pre-warmed snapshots:** For ultra-low-latency cold starts, gVisor's checkpoint/restore
  mechanism allows pre-initialized containers with pre-loaded libraries to restore in ~100–300ms.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=startup BENCHMARKS_TARGETS=test/benchmarks/base:startup_test BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

## Memory footprint & sandbox packing density

The Sentry provides an additional layer of indirection, and it requires memory
in order to store state associated with the application. This memory consists
of a fixed component, plus an amount that varies with operating system resource
usage (e.g. open file descriptors and sockets).

For high-density multi-tenant platforms (such as [Substrate](https://github.com/agent-substrate/substrate)),
fixed memory overheads determine infrastructure economics. While microVMs and hardware
virtual machines typically lock dedicated blocks of RAM per instance,
gVisor enables high packing density by sharing host memory dynamically.

{% include graph.html id="density" better="lower" subtract_baseline="runc"
title="Sentry Memory Overhead over non-sandboxed container (//test/benchmarks/base:size_test)" %}

The above figure demonstrates the fixed memory overhead of the Sentry
(`runsc` memory minus non-sandboxed `runc` container memory) across
[`BenchmarkSizeEmpty`][usage-test] (running `sleep`), `BenchmarkSizeNode` (a synthetic
Node.js web service), and `BenchmarkSizeNginx` (an Nginx web server) in
`//test/benchmarks/base:size_test`.

Importantly, non-sandboxed containers (`runc`) exhibit minimal userspace memory
because they share the host Linux kernel directly.
When sandboxing untrusted code, gVisor's Sentry introduces a **flat, fixed overhead
of ~14–45MB on `systrap`** (and ~45–55MB on `kvm`) over the non-sandboxed container baseline.
Crucially, this overhead remains relatively fixed regardless of workload size: whether running
an empty container, Nginx, or Node.js, the memory delta over `runc` remains constant
because application memory is backed directly by host virtual memory rather than locked
into static guest reservations.

By contrast, traditional microVMs (such as Firecracker or Cloud Hypervisor) require
dedicated guest kernels and static RAM allocations (typically configured with 128MB–1GB+
minimum guest memory reservations per instance). Under gVisor, memory unused by the
workload is reclaimed dynamically by the host, unlocking significantly higher density
for multi-tenant workloads.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=usage BENCHMARKS_TARGETS=test/benchmarks/base:usage_test BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

## CPU performance & computation

gVisor does not perform emulation or otherwise interfere with the raw execution
of CPU instructions by the application. Therefore, there is negligible runtime cost
imposed for CPU operations.

### Raw CPU execution

{% include graph.html id="sysbench-cpu" better="higher" exclude_runtimes="kvm"
title="BenchmarkSysbench (//test/benchmarks/base:sysbench_test)" %}

The above figure demonstrates the [`BenchmarkSysbench`][sysbench-test] measurement
of CPU events per second in `//test/benchmarks/base:sysbench_test` (`operation: CPU`,
1 thread). Events per second is based on a CPU-bound loop calculating prime
numbers in a specified range. We note that `systrap` executes at 99.8% of native
`runc`, as instructions execute natively on the hardware CPU.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=sysbench BENCHMARKS_TARGETS=test/benchmarks/base:sysbench_test BENCHMARKS_FILTER="BenchmarkSysbench/CPU"
```

### Computation & machine learning

This has important consequences for classes of workloads that are compute-bound,
such as data processing, numerical simulation, or machine learning. In these cases,
`runsc` imposes minimal runtime overhead.

{% include graph.html id="tensorflow" better="lower" exclude_runtimes="kvm"
title="BenchmarkTensorflowDashboard (//test/benchmarks/ml:tensorflow_test)" %}

For example, the above figure shows a sample TensorFlow workload training a
convolutional neural network in [`BenchmarkTensorflowDashboard`][tensorflow-test]
(`//test/benchmarks/ml:tensorflow_test`). The time indicated includes the full start-up
and execution time for the workload.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=tensorflow BENCHMARKS_TARGETS=test/benchmarks/ml:tensorflow_test BENCHMARKS_FILTER="BenchmarkTensorflowDashboard"
```

## Memory access

Once memory mappings are established, gVisor does not intercept or emulate raw
CPU memory instructions: reads and writes to mapped memory pages execute directly
on the host CPU at native hardware speed.

{% include graph.html id="sysbench-memory" better="higher" exclude_runtimes="kvm"
title="BenchmarkSysbench (//test/benchmarks/base:sysbench_test)" %}

The above figure demonstrates memory operations per second as measured by
[`BenchmarkSysbench`][sysbench-test] (`operation: Memory`) in
`//test/benchmarks/base:sysbench_test`.

While steady-state access speed is near-identical to native execution, the
benchmark reflects a modest overhead (~9% on `systrap`). This delta is not driven
by raw memory reads or writes, but by the initial setup phase:
- **Initial page fault handling:** When memory is first allocated or touched, the
  resulting page faults are intercepted and resolved by the Sentry's memory
  manager to populate application page tables. Under `systrap`, these initial
  fault-ins introduce interception overhead compared to native kernel handling.
- **Steady-state execution:** Once page mappings are faulted in and cached in the
  hardware MMU and TLB, subsequent memory accesses bypass the Sentry entirely and
  run at full hardware throughput.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=sysbench BENCHMARKS_TARGETS=test/benchmarks/base:sysbench_test BENCHMARKS_FILTER="BenchmarkSysbench/Memory"
```

## GPU acceleration via nvproxy

For AI and machine learning workloads utilizing NVIDIA GPUs, gVisor provides
transparent driver interception via [`nvproxy`](/docs/user_guide/gpu/). The Sentry
mediates NVIDIA driver ioctl system calls across the sandbox boundary to enforce
isolation. Once CUDA memory buffers and device execution queues are established,
all tensor operations and device memory transfers run at native hardware speed.

{% include graph.html id="vllm-throughput" better="higher"
title="BenchmarkVLLM (//test/gpu/vllm:vllm_test)" %}

In continuous LLM inference benchmarks ([`BenchmarkVLLM`][vllm-test] in
`//test/gpu/vllm:vllm_test` serving on NVIDIA L4 GPUs), gVisor achieves
**98–99% of native output tokens/second throughput**, making it an ideal
sandbox for multi-tenant LLM serving and untrusted agent execution.

To reproduce this benchmark locally on an NVIDIA GPU host:
```bash
make sudo TARGETS=//tools/gpu:main ARGS="install --latest" && make benchmark-platforms BENCHMARKS_SUITE=vllm BENCHMARKS_TARGETS=test/gpu/vllm:vllm_test BENCHMARKS_PLATFORMS="systrap" BENCHMARKS_RUNC=true BENCHMARKS_OPTIONS="-test.benchtime=1x"
```

## System call interception

A primary **structural cost** inherent to gVisor is system call interception itself,
regardless of the platform chosen. In native Linux, an application system call
executes as a direct CPU transition from ring 3 to ring 0 (~415ns for simple calls like `getpid`).
In gVisor, every untrusted system call must be intercepted, its register state captured,
and execution routed to the Sentry userspace kernel to be inspected and served.
Intercepting the syscall and routing it to the kernel is always a cost.

While the necessity of intercepting and routing system calls is a universal structural cost,
the exact latency and mechanism depend on the [platform choice](/docs/architecture_guide/platforms/).
Today, gVisor uses **`systrap` as its default platform**, combining seccomp-based interception
with shared-memory fast-paths to avoid context-switch overheads.

{% include graph.html id="syscall" better="lower"
title="Raw System Call Latency (//test/benchmarks/base:syscallbench_test)" %}

The above figure demonstrates the time required for a raw system call (`getpid`)
across runtimes as measured by [`BenchmarkSyscall`][syscallbench-test] (`getpidopt`).
Crucially, `getpid` is a system call completely handled by the Sentry in userspace
without needing to invoke the host kernel. As a result, it isolates and directly
measures the pure system call interception and context-routing latency by itself.
On native Linux, a raw system call executes in **~415ns**. When sandboxing the
workload, the Sentry intercepts and handles system calls in userspace, completing
in **~2.37μs on `systrap`** (fast-path `getpidopt` utilizing shared memory; ~5.66μs on seccomp slow path) and **~989ns on `kvm`**—a dramatic speedup over legacy
`ptrace` (~38μs).

While `kvm` leverages hardware virtualization extensions for system call trapping
(~989ns), `systrap` achieves low microsecond latency (~2.37μs) entirely in userspace
via seccomp notification fast-paths and shared memory. This allows `systrap` to run
portably across any Linux environment—including cloud virtual machines and bare metal—without
requiring hardware virtualization privileges or nested virtualization support.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=syscall BENCHMARKS_TARGETS=test/benchmarks/base:syscallbench_test BENCHMARKS_FILTER="BenchmarkSyscall/syscall=getpidopt" BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

## Process scheduling & IPC

Beyond pure computational loops, workloads that spawn many communicating processes
test kernel scheduler latency and IPC channels. [`BenchmarkHackbench`][hackbench-test]
in `//test/benchmarks/base:hackbench_test` runs the standard Linux `hackbench` workload
(creating 100 process pairs communicating across Unix domain socket pairs).

{% include graph.html id="hackbench" better="lower" exclude_runtimes="kvm"
title="BenchmarkHackbench (//test/benchmarks/base:hackbench_test)" %}

The above figure demonstrates total execution time for `BenchmarkHackbench`. Under
`systrap`, context-switching and shared-memory dispatch yield execution times
within 1.5x of native `runc`.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=hackbench BENCHMARKS_TARGETS=test/benchmarks/base:hackbench_test
```

## Workload amortization

This cost will principally impact applications that are system call bound, which
tend to be high-frequency I/O loops and static network services. In general,
the relative impact of system call interception amortizes rapidly as applications
perform useful computational work per syscall.

{% include graph.html id="redis" better="higher" exclude_runtimes="kvm"
title="BenchmarkRedis (//test/benchmarks/database:redis_test)" %}

For example, `redis` is an application that performs relatively little work in
userspace: in general it reads from a connected socket, reads or modifies some
data in memory, and writes a result back. The above figure shows the results
of Redis operations across `SET`, `LPUSH`, and `LRANGE_100` in
[`BenchmarkRedis`][redis-test] (`//test/benchmarks/database:redis_test`). While smaller
operations impose a structural syscall interception overhead (~486k ops/sec on `systrap`
versus ~1.20M on native `runc` for `SET`, and ~468k ops/sec vs ~1.11M for `LPUSH`),
operations where more work is done in the application show lower relative overhead:
for `LRANGE_100`, `systrap` achieves ~106k ops/sec, reaching 75.5% of native `runc` (~140k ops/sec).

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=redis BENCHMARKS_TARGETS=test/benchmarks/database:redis_test BENCHMARKS_FILTER="BenchmarkRedis/operation" BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

## Network

Networking is mostly bound by **implementation costs**, and gVisor's network
stack (Netstack) has seen continuous optimization, including Generic Receive
Offload (GRO), Generic Segmentation Offload (GSO), and optimized buffer pooling.

### Raw bandwidth

{% include graph.html id="iperf" better="higher" exclude_runtimes="kvm"
title="BenchmarkIperfOneConnection (//test/benchmarks/network:iperf_test)" %}

The above figure shows single-connection TCP throughput in [`BenchmarkIperfOneConnection`][iperf-test]
(`//test/benchmarks/network:iperf_test`). On modern Linux hosts with GRO and multi-channel
networking configured, Netstack achieves multi-gigabit throughput: ~3.27 Gbps download on `systrap`
(83.8% of native `runc` at ~3.90 Gbps) and ~2.52 Gbps upload (versus ~3.84 Gbps on `runc`),
delivering strong line-rate capability for networked microservices.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=iperf BENCHMARKS_TARGETS=test/benchmarks/network:iperf_test BENCHMARKS_FILTER="BenchmarkIperfOneConnection" BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

### Web applications

Real applications (like Node.js and Ruby on Rails) spend time in userspace parsing requests,
querying databases, and rendering templates, diluting network stack latency.

Because gVisor's network stack (Netstack) and I/O subsystems encounter lock contention and
goroutine scheduling overheads under high multi-threading, performance is most clearly observed
at lower concurrency levels, which isolate baseline per-request overhead without multi-threaded
contention.

{% include graph.html id="applications" better="higher" metric="requests_per_second" exclude_runtimes="kvm"
title="BenchmarkNode & BenchmarkRuby (//test/benchmarks/network, concurrency 1)" %}

The above figure shows requests per second across `BenchmarkNode` (`//test/benchmarks/network:node_test`)
and `BenchmarkRuby` (`//test/benchmarks/network:ruby_test`) under concurrency 1. Under `systrap`,
Node.js delivers ~811 rps (63.5% of native `runc` at ~1,277 rps; scaling to ~1,205 rps at concurrency 25),
while Ruby reaches ~623 rps (43.5% of native `runc` at ~1,432 rps; scaling to ~1,410 rps at concurrency 25).

To reproduce these benchmarks locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=node BENCHMARKS_TARGETS=test/benchmarks/network:node_test BENCHMARKS_FILTER="BenchmarkNode/concurrency:(1|25)" BENCHMARKS_OPTIONS="-test.benchtime=5s"
make benchmark-platforms BENCHMARKS_SUITE=ruby BENCHMARKS_TARGETS=test/benchmarks/network:ruby_test BENCHMARKS_FILTER="BenchmarkRuby/concurrency:(1|25)" BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

### Web servers

{% include graph.html id="continuous-nginx" better="higher" metric="requests_per_second" exclude_runtimes="kvm"
title="BenchmarkContinuousNginx (//test/benchmarks/network:nginx_test, concurrency 1)" %}

For static web servers where the kernel path dominates (serving 100Kb static files under
concurrency 1 in [`BenchmarkContinuousNginx`][nginx-test]), `systrap` achieves ~3,485 rps (37.4%
of native `runc` at ~9,315 rps), scaling to ~8,619 rps at concurrency 25, reflecting the baseline
overhead of userspace network packet handling.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=nginx BENCHMARKS_TARGETS=test/benchmarks/network:nginx_test BENCHMARKS_FILTER="BenchmarkContinuousNginx.*filesize:100Kb.*concurrency:(1|25)" BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

{% include graph.html id="httpd100k" better="higher" metric="requests_per_second" exclude_runtimes="kvm"
title="BenchmarkContinuousHttpd (//test/benchmarks/network:httpd_test, concurrency 1)" %}

Similarly, the above figure shows throughput for Apache HTTPD serving 100Kb files in
[`BenchmarkContinuousHttpd`][httpd-test] (`//test/benchmarks/network:httpd_test`) under concurrency 1.
`systrap` achieves ~972 rps (71.8% of native `runc` at ~1,353 rps), scaling to ~3,179 rps at concurrency 25.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=httpd BENCHMARKS_TARGETS=test/benchmarks/network:httpd_test BENCHMARKS_FILTER="BenchmarkContinuousHttpd.*concurrency:(1|25)" BENCHMARKS_OPTIONS="-test.benchtime=5s"
```

## Filesystem & storage I/O

gVisor's virtual file system (VFS2) isolates file operations through an unprivileged
external Gofer process. In-memory dentry and metadata caching within the Sentry
significantly accelerates metadata operations and repeated reads. For raw disk I/O,
the underlying storage medium dominates throughput:

{% include graph.html id="fio-bw" better="higher"
title="BenchmarkFio* (//test/benchmarks/fs:fio_test, rootfs)" %}

The above figure demonstrates streaming sequential bandwidth in [`BenchmarkFio`][fio-test]
(`BenchmarkFioRead`, `BenchmarkFioWrite` on `filesystem: rootfs`).
In streaming sequential workloads, physical disk write bandwidth tracks host storage limits:
on a 100GB SSD persistent disk, native `runc` direct I/O achieves ~257 MB/s sequential write bandwidth,
while gVisor's internal buffering delivers high-throughput rootfs writes. Sequential read bandwidth
reaches **~9.62 GB/s** on `runc` and **~12.65 GB/s** on `systrap`.
`kvm` achieves **~591 MB/s** write and **~600 MB/s** read bandwidth. Fine-grained random single-page
I/O benchmarks are omitted, as unbuffered random ops reflect per-syscall intercept traps rather than actual streaming storage throughput.

{% include graph.html id="fio-tmpfs-bw" better="higher"
title="BenchmarkFio* (//test/benchmarks/fs:fio_test, tmpfs)" %}

When workloads operate in memory-backed file systems (`filesystem: tmpfs`), operations bypass
host storage and run directly in Sentry memory, delivering high gigabytes/sec throughput:
`systrap` achieves **~4.44 GB/s** sequential write bandwidth (outperforming native `runc` at ~4.12 GB/s)
and **~12.65 GB/s** sequential read throughput (`runc` at ~9.62 GB/s). `kvm` delivers **~1.11 GB/s** write and **~765 MB/s** read throughput.

To reproduce these benchmarks locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=fio BENCHMARKS_TARGETS=test/benchmarks/fs:fio_test BENCHMARKS_FILTER="BenchmarkFio(Read|Write)/operation.(read|write)/ioEngine.libaio/jobs.1/blockSize.1024K/directIO.true/filesystem.rootfs" BENCHMARKS_OPTIONS="--test.benchtime=1000x"
make benchmark-platforms BENCHMARKS_SUITE=fio-tmpfs BENCHMARKS_TARGETS=test/benchmarks/fs:fio_test BENCHMARKS_FILTER="BenchmarkFio(Read|Write)/operation.(read|write)/ioEngine.libaio/jobs.1/blockSize.1024K/directIO.true/filesystem.tmpfs" BENCHMARKS_OPTIONS="--test.benchtime=1000x"
```

### Software builds & metadata-heavy workloads

Software compilation combines thousands of small file reads, process spawns, and
compiler toolchain invocations. [`BenchmarkBuildABSL`][bazel-test] and [`BenchmarkBuildGRPC`][bazel-test]
measure clean builds of Abseil-C++ and gRPC from scratch on bind-mounted source trees
(`filesystem: bindfs`).

{% include graph.html id="bazel-build" better="lower" exclude_runtimes="kvm"
title="BenchmarkBuildABSL & BenchmarkBuildGRPC (//test/benchmarks/fs:bazel_test)" %}

The above figure demonstrates clean compilation elapsed time in seconds.
With VFS2 dentry caching and optimized Gofer RPC handling, building Abseil takes
~133s on `systrap` compared to ~93s on native `runc`.

To reproduce these build benchmarks locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=absl BENCHMARKS_TARGETS=test/benchmarks/fs:bazel_test BENCHMARKS_FILTER="ABSL/page_cache.clean"
make benchmark-platforms BENCHMARKS_SUITE=grpc-build BENCHMARKS_TARGETS=test/benchmarks/fs:bazel_test BENCHMARKS_FILTER="GRPC/page_cache.clean/filesystem.bind"
```

### Media processing & transcoding

{% include graph.html id="ffmpeg" better="lower" exclude_runtimes="kvm"
title="BenchmarkFfmpeg (//test/benchmarks/media:ffmpeg_test)" %}

For benchmarks that combine disk I/O with heavy compute, file system boundary
costs are minimal. The above figure shows the total time required for an `ffmpeg`
container to transcode a 27MB input video in [`BenchmarkFfmpeg`][ffmpeg-test]
(`//test/benchmarks/media:ffmpeg_test`).

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=ffmpeg BENCHMARKS_TARGETS=test/benchmarks/media:ffmpeg_test
```

[ab]: https://en.wikipedia.org/wiki/ApacheBench
[benchmark-tools]: https://github.com/google/gvisor/tree/master/test/benchmarks
[buildkite]: https://buildkite.com/gvisor/benchmarks
[gce]: https://cloud.google.com/compute/
[cnn]: https://github.com/aymericdamien/TensorFlow-Examples/blob/master/examples/3_NeuralNetworks/convolutional_network.py
[docker]: https://docker.io
[redis-benchmark]: https://redis.io/topics/benchmarks
[vfs]: https://en.wikipedia.org/wiki/Virtual_file_system
[sysbench-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/base/sysbench_test.go
[usage-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/base/usage_test.go
[syscallbench-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/base/syscallbench_test.go
[startup-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/base/startup_test.go
[hackbench-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/base/hackbench_test.go
[redis-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/database/redis_test.go
[iperf-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/network/iperf_test.go
[node-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/network/node_test.go
[ruby-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/network/ruby_test.go
[nginx-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/network/nginx_test.go
[httpd-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/network/httpd_test.go
[fio-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/fs/fio_test.go
[bazel-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/fs/bazel_test.go
[ffmpeg-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/media/ffmpeg_test.go
[tensorflow-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/ml/tensorflow_test.go
[vllm-test]: https://github.com/google/gvisor/tree/master/test/gpu/vllm/vllm_test.go
