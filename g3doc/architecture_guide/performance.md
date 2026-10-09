# Performance Guide

[TOC]

gVisor is designed to provide a secure, virtualized environment while preserving
key benefits of containerization, such as sub-second cold starts, small fixed
overheads, and a dynamic resource footprint. For containerized infrastructure,
this provides a turn-key solution for sandboxing untrusted workloads without
sacrificing agility.

## Architectural value proposition: instant cold starts & high packing density

gVisor's defining architectural advantage is combining strong multi-tenant sandbox
isolation with the agility of standard Linux host processes. For multi-tenant compute
platforms, event-driven serverless engines, and modern AI agent sandboxes—such as
**Substrate** and interactive code execution runtimes—gVisor enables a scale-from-zero
operational model that hardware virtual machines and microVMs cannot match.

Hardware virtual machines and microVMs isolate tenants by partitioning physical
hardware. While secure, this architecture imposes two fundamental constraints:
1. **Guest-kernel boot overhead:** Every virtual machine must boot a dedicated Linux
   guest kernel, initialize virtual device models (e.g. virtio, PCI), run guest init
   systems, and configure guest memory tables before executing user code.
2. **Static memory partitioning:** MicroVMs and hardware virtual machines typically
   require pre-allocated, dedicated memory reservations (e.g. 512MB–2GB per instance)
   carved out from the host. Because guest operating systems manage memory independently,
   physical RAM remains locked even when the workload is completely idle, severely
   capping host packing density to dozens of instances per node.

gVisor takes a fundamentally different architectural approach: **process-based sandboxing**.
The [Sentry](../README.md#sentry) is an unprivileged userspace kernel written in Go that acts
as a secure boundary directly between the application and the host. This design delivers
two premier operational capabilities:

* **Zero-Guest-Boot Cold Starts:** Starting a gVisor sandbox does not require booting a guest
  kernel. Sandbox creation is as lightweight as launching a regular host process. Sentry
  initialization completes in milliseconds (~150ms cold boot), with total container creation
  time adding only modest overhead over native `runc` (~580ms vs. ~480ms). Real-world applications
  (such as Node.js or Nginx) spin up in 1.3–1.7 seconds, providing instantaneous cold starts
  for on-demand agentic workloads.
* **Extreme Sandbox Packing Density:** Rather than carving out fixed RAM partitions, gVisor
  processes participate directly in host virtual memory management. A clean sandbox requires
  only **~17–26MB of fixed memory overhead**, and unneeded pages are reclaimed dynamically
  by the host. As a result, hosts can pack **thousands of isolated tenant sandboxes onto
  a single physical machine**, unlocking orders-of-magnitude higher packing efficiency and
  radically lower infrastructure costs.
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

All data below is continuously generated using gVisor's open-source
[benchmark suite][benchmark-tools] executed in [Buildkite CI][buildkite]
on uniform [Google Compute Engine][gce] Virtual Machines (VMs) with the
following specifications:

```
Machine type: c2-standard-8 (Intel Cascade Lake, 8 vCPUs, 32GB RAM)
Image: Ubuntu 22.04 LTS (Linux kernel 5.15+)
BootDisk: 100GB SSD persistent disk
```

Through this document, results report rolling 30-day medians across three
runtime configurations:
- **`systrap`**: The default gVisor platform. Uses userspace seccomp interception
  with shared-memory fast-paths for high-performance syscall handling without
  requiring hardware virtualization.
- **`kvm`**: Hardware-assisted virtualization platform. In cloud VM CI environments,
  KVM operates under **nested virtualization** (an L2 hypervisor inside an L1 VM).
  Under nested virtualization, every hardware VM-exit triggers an expensive trap
  into the L0 host hypervisor to emulate L1 VMX state, significantly inflating
  VM-exit and context-switch latencies. KVM is included here to illustrate the
  inherent structural overhead of hardware virtualization under nested cloud
  environments compared to process-based sandboxing (`systrap`), which runs purely
  in host userspace and remains largely immune to nested virtualization penalties.
  On physical bare-metal hardware, KVM's performance profile is substantially
  different and achieves much lower exit overheads.
- **`runc`**: Unsandboxed Linux container baseline (native Linux host execution).

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
  by Docker daemon container creation and cgroup setup latency (~450–550ms);
  native `runc` initializes an empty container in ~480ms, while `systrap` (~580ms)
  and `kvm` (~650ms) add modest sandboxing overhead (~100–170ms) for Sentry
  initialization and seccomp filter configuration.
- **Application startup:** When launching real applications with runtime dependencies,
  file loading and module execution introduce expected sandboxing overhead:
  Nginx starts in ~1.56s on `systrap` (~1.30s on `kvm`) versus ~0.99s on `runc`,
  and Node.js starts in ~1.72s on `systrap` (~1.78s on `kvm`) versus ~0.99s on `runc`.
- **Pre-warmed snapshots:** For ultra-low-latency cold starts, gVisor's checkpoint/restore
  mechanism allows pre-initialized containers with pre-loaded libraries to restore in ~100–300ms.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=startup BENCHMARKS_TARGETS=test/benchmarks/base:startup_test
```

## Memory footprint & sandbox packing density

The Sentry provides an additional layer of indirection, and it requires memory
in order to store state associated with the application. This memory consists
of a fixed component, plus an amount that varies with operating system resource
usage (e.g. open file descriptors and sockets).

For multi-tenant platforms (such as Substrate) running thousands of sandboxes per host,
fixed memory overheads determine infrastructure economics. While microVMs and hardware
virtual machines typically lock hundreds of megabytes or gigabytes of RAM per instance,
gVisor allows extreme packing density.

{% include graph.html id="density" better="lower"
title="BenchmarkSize* (//test/benchmarks/base:size_test)" log="true" y_min="100000" %}

The above figure demonstrates container memory usage across
[`BenchmarkSizeEmpty`][size-test] (running `sleep`), `BenchmarkSizeNode` (a synthetic
Node.js web service), and `BenchmarkSizeNginx` (an Nginx web server) in
`//test/benchmarks/base:size_test`. In all cases, the Sentry accounts for a modest
fixed memory footprint (~17–26MB on `systrap`). Unlike microVMs with static
guest RAM allocations, gVisor shares host memory dynamically and returns idle pages
to the host.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=usage BENCHMARKS_TARGETS=test/benchmarks/base:size_test
```

## CPU performance & computation

gVisor does not perform emulation or otherwise interfere with the raw execution
of CPU instructions by the application. Therefore, there is negligible runtime cost
imposed for CPU operations.

### Raw CPU execution

{% include graph.html id="sysbench-cpu" better="higher"
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

{% include graph.html id="tensorflow" better="lower"
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

{% include graph.html id="sysbench-memory" better="higher"
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

Some **structural costs** of gVisor are heavily influenced by the
[platform choice](/docs/architecture_guide/platforms/), which implements system
call interception. Today, gVisor uses **`systrap` as its default platform**,
combining seccomp-based interception with shared-memory fast-paths to avoid
context-switch overheads.

{% include graph.html id="syscall" better="lower"
title="BenchmarkSyscallUnderSeccomp (//test/benchmarks/base:syscallbench_test)" y_min="100"
log="true" %}

The above figure demonstrates the time required for a raw system call (`getpid`)
across runtimes as measured by [`BenchmarkSyscallUnderSeccomp`][syscallbench-test] in
`//test/benchmarks/base:syscallbench_test`. While legacy `ptrace` imposed ~38μs of
overhead per syscall, modern `systrap` completes in ~1.5μs (and `kvm` in ~0.76μs).
However, while KVM exhibits low latency for isolated null syscalls, in complex,
stateful workloads under nested virtualization it incurs compounding dual-level
VM-exit penalties. `systrap`, by contrast, avoids hardware virtualization traps
entirely and operates uniformly across bare-metal and cloud VM hosts.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=syscall BENCHMARKS_TARGETS=test/benchmarks/base:syscallbench_test BENCHMARKS_FILTER="BenchmarkSyscallUnderSeccomp"
```

## Process scheduling & IPC

Beyond pure computational loops, workloads that spawn many communicating processes
test kernel scheduler latency and IPC channels. [`BenchmarkHackbench`][hackbench-test]
in `//test/benchmarks/base:hackbench_test` runs the standard Linux `hackbench` workload
(creating 100 process pairs communicating across Unix domain socket pairs).

{% include graph.html id="hackbench" better="lower"
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

{% include graph.html id="redis" better="higher"
title="BenchmarkRedis (//test/benchmarks/database:redis_test)" %}

For example, `redis` is an application that performs relatively little work in
userspace: in general it reads from a connected socket, reads or modifies some
data in memory, and writes a result back. The above figure shows the results
of Redis operations across `SET`, `LPUSH`, and `LRANGE_100` in
[`BenchmarkRedis`][redis-test] (`//test/benchmarks/database:redis_test`). While smaller
operations impose a structural syscall interception overhead, operations where more
work is done in the application show lower relative overhead.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=redis BENCHMARKS_TARGETS=test/benchmarks/database:redis_test BENCHMARKS_FILTER="BenchmarkRedis/operation"
```

## Network

Networking is mostly bound by **implementation costs**, and gVisor's network
stack (Netstack) has seen continuous optimization, including Generic Receive
Offload (GRO), Generic Segmentation Offload (GSO), and optimized buffer pooling.

### Raw bandwidth

{% include graph.html id="iperf" better="higher"
title="BenchmarkIperfOneConnection (//test/benchmarks/network:iperf_test)" %}

The above figure shows single-connection TCP throughput in [`BenchmarkIperfOneConnection`][iperf-test]
(`//test/benchmarks/network:iperf_test`). On modern Linux hosts, Netstack achieves multi-gigabit
throughput (~2.7 Gbps on `systrap`), delivering strong line-rate capability for networked microservices.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=iperf BENCHMARKS_TARGETS=test/benchmarks/network:iperf_test BENCHMARKS_FILTER="BenchmarkIperfOneConnection"
```

### Web applications

Real applications (like Node.js and Ruby on Rails) spend time in userspace parsing requests,
querying databases, and rendering templates, diluting network stack latency.

{% include graph.html id="applications" better="higher" metric="requests_per_second"
title="BenchmarkNode & BenchmarkRuby (//test/benchmarks/network)" %}

The above figure shows requests per second across `BenchmarkNode` (`//test/benchmarks/network:node_test`)
and `BenchmarkRuby` (`//test/benchmarks/network:ruby_test`) under concurrency 25. Under `systrap`,
Node.js delivers ~4,600 rps (78% of native `runc`), while Ruby reaches ~1,250 rps (90% of native `runc`).

To reproduce these benchmarks locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=node BENCHMARKS_TARGETS=test/benchmarks/network:node_test BENCHMARKS_FILTER="BenchmarkNode/concurrency:25"
make benchmark-platforms BENCHMARKS_SUITE=ruby BENCHMARKS_TARGETS=test/benchmarks/network:ruby_test BENCHMARKS_FILTER="BenchmarkRuby/concurrency:25"
```

### Web servers

{% include graph.html id="continuous-nginx" better="higher" metric="requests_per_second"
title="BenchmarkContinuousNginx (//test/benchmarks/network:nginx_test)" %}

For static web servers where the kernel path dominates (serving 100Kb static files under
concurrency 25 in [`BenchmarkContinuousNginx`][nginx-test]), `systrap` achieves ~13,700 rps (70%
of native `runc`), demonstrating high concurrency serving capacity under pure userspace networking.

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=nginx BENCHMARKS_TARGETS=test/benchmarks/network:nginx_test BENCHMARKS_FILTER="BenchmarkContinuousNginx.*filesize:100Kb.*concurrency:25"
```

{% include graph.html id="httpd100k" better="higher" metric="requests_per_second"
title="BenchmarkContinuousHttpd (//test/benchmarks/network:httpd_test)" %}

Similarly, the above figure shows throughput for Apache HTTPD serving 100Kb files in
[`BenchmarkContinuousHttpd`][httpd-test] (`//test/benchmarks/network:httpd_test`). `systrap`
serves ~12,300 rps (71% of native `runc`).

To reproduce this benchmark locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=httpd BENCHMARKS_TARGETS=test/benchmarks/network:httpd_test BENCHMARKS_FILTER="BenchmarkContinuousHttpd/100k"
```

## Filesystem & storage I/O

gVisor's virtual file system (VFS2) isolates file operations through an unprivileged
external Gofer process. In-memory dentry and metadata caching within the Sentry
significantly accelerates metadata operations and repeated reads. For raw disk I/O,
the underlying storage medium dominates throughput:

{% include graph.html id="fio-bw" better="higher"
title="BenchmarkFio* (//test/benchmarks/fs:fio_test, rootfs)" %}

The above figure demonstrates streaming sequential and random bandwidth in [`BenchmarkFio`][fio-test]
(`BenchmarkFioRead`, `BenchmarkFioWrite`, `BenchmarkFioRandRead`, `BenchmarkFioRandWrite` on `filesystem: rootfs`).
In streaming sequential workloads, disk I/O bandwidth largely matches host disk limits.

{% include graph.html id="fio-tmpfs-bw" better="higher"
title="BenchmarkFio* (//test/benchmarks/fs:fio_test, tmpfs)" %}

When workloads operate in memory-backed file systems (`filesystem: tmpfs`), operations bypass
the Gofer and run directly in Sentry memory, delivering gigabytes/sec throughput.

To reproduce these benchmarks locally:
```bash
make benchmark-platforms BENCHMARKS_SUITE=fio BENCHMARKS_TARGETS=test/benchmarks/fs:fio_test BENCHMARKS_FILTER="BenchmarkFioWrite/filesystem.rootfs/ioengine.sync/bs.1024K"
make benchmark-platforms BENCHMARKS_SUITE=fio-tmpfs BENCHMARKS_TARGETS=test/benchmarks/fs:fio_test BENCHMARKS_FILTER="BenchmarkFioWrite/filesystem.tmpfs/ioengine.sync/bs.1024K"
```

### Software builds & metadata-heavy workloads

Software compilation combines thousands of small file reads, process spawns, and
compiler toolchain invocations. [`BenchmarkBuildABSL`][bazel-test] and [`BenchmarkBuildGRPC`][bazel-test]
measure clean builds of Abseil-C++ and gRPC from scratch on bind-mounted source trees
(`filesystem: bindfs`).

{% include graph.html id="bazel-build" better="lower"
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

{% include graph.html id="ffmpeg" better="lower"
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
[size-test]: https://github.com/google/gvisor/tree/master/test/benchmarks/base/size_test.go
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
