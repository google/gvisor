+++
title = "Performance Guide"
weight = 30
+++
gVisor is designed to provide a secure, virtualized environment while preserving
key benefits of containerization, such as small fixed overheads and a dynamic
resource footprint. For containerized infrastructure, this can provide a
turn-key solution for sandboxing untrusted workloads: there are no changes to
the fundamental resource model.

gVisor imposes runtime costs over native containers. These costs come in two
forms: additional cycles and memory usage, which may manifest as increased
latency, reduced throughput or density, or not at all. In general, these costs
come from two different sources.

First, the existence of the [Sentry](../) means that additional memory will be
required, and application system calls must traverse additional layers of
software. The design emphasizes [security](../security/) and therefore we chose
to use a language for the Sentry that provides benefits in this domain but may
not yet offer the raw performance of other choices. Costs imposed by these
design choices are **structural costs**.

Second, as gVisor is an independent implementation of the system call surface,
many of the subsystems or specific calls are not as optimized as more mature
implementations. A good example here is the network stack, which is continuing
to evolve but does not support all the advanced recovery mechanisms offered by
other stacks and is less CPU efficient. This an **implementation cost** and is
distinct from **structural costs**. Improvements here are ongoing and driven by
the workloads that matter to gVisor users and contributors.

This page provides a guide for understanding baseline performance, and calls out
distint **structural costs** and **implementation costs**, highlighting where
improvements are possible and not possible.

While we include a variety of workloads here, it’s worth emphasizing that gVisor
may not be an appropriate solution for every workload, for reasons other than
performance. For example, a sandbox may provide minimal benefit for a trusted
database, since *user data would already be inside the sandbox* and there is no
need for an attacker to break out in the first place.

## Methodology

All data below was generated using the [benchmark tools][benchmark-tools]
repository, and the machines under test are uniform [Google Compute Engine][gce]
Virtual Machines (VMs) with the following specifications:

```
Machine type: n1-standard-4 (broadwell)
Image: Debian GNU/Linux 9 (stretch) 4.19.0-0
BootDisk: 2048GB SSD persistent disk
```

Through this document, `runsc` is used to indicate the runtime provided by
gVisor. When relevant, we use the name `runsc-platform` to describe a specific
[platform choice](../overview/).

**Except where specified, all tests below are conducted with the `ptrace`
platform. The `ptrace` platform works everywhere and does not require hardware
virtualization or kernel modifications but suffers from the highest structural
costs by far. This platform is used to provide a clear understanding of the
performance model, but in no way represents an ideal scenario. In the future,
this guide will be extended to bare metal environments and include additional
platforms.**

## Memory access

gVisor does not introduce any additional costs with respect to raw memory
accesses. Page faults and other Operating System (OS) mechanisms are translated
through the Sentry, but once mappings are installed and available to the
application, there is no additional overhead.

{{< graph id="sysbench-memory" url="/performance/sysbench-memory.csv" title="perf.py sysbench.memory --runtime=runc --runtime=runsc" >}}

The above figure demonstrates the memory transfer rate as measured by
`sysbench`.

## Memory usage

The Sentry provides an additional layer of indirection, and it requires memory
in order to store state associated with the application. This memory generally
consists of a fixed component, plus an amount that varies with the usage of
operating system resources (e.g. how many sockets or files are opened).

For many use cases, fixed memory overheads are a primary concern. This may be
because sandboxed containers handle a low volume of requests, and it is
therefore important to achieve high densities for efficiency.

{{< graph id="density" url="/performance/density.csv" title="perf.py density --runtime=runc --runtime=runsc" log="true" y_min="100000" >}}

The above figure demonstrates these costs based on three sample applications.
This test is the result of running many instances of a container (typically 50)
and calculating available memory on the host before and afterwards, and dividing
the difference by the number of containers. This technique is used for measuring
memory usage over the `usage_in_bytes` value of the container cgroup because we
found that some container runtimes, other than `runc` and `runsc`, do not use an
individual container cgroup.

The first application is an instance of `sleep`: a trivial application that does
nothing. The second application is a synthetic `node` application which imports
a number of modules and listens for requests. The third application is a similar
synthetic `ruby` application which does the same. Finally, we include an
instance of `redis` storing approximately 1GB of data. In all cases, the sandbox
itself is responsible for a small, mostly fixed amount of memory overhead.

## CPU performance

gVisor does not perform emulation or otherwise interfere with the raw execution
of CPU instructions by the application. Therefore, there is no runtime cost
imposed for CPU operations.

{{< graph id="sysbench-cpu" url="/performance/sysbench-cpu.csv" title="perf.py sysbench.cpu --runtime=runc --runtime=runsc" >}}

The above figure demonstrates the `sysbench` measurement of CPU events per
second. Events per second is based on a CPU-bound loop that calculates all prime
numbers in a specified range. We note that `runsc` does not impose a performance
penalty, as the code is executing natively in both cases.

This has important consequences for classes of workloads that are often
CPU-bound, such as data processing or machine learning. In these cases, `runsc`
will similarly impose minimal runtime overhead.

{{< graph id="tensorflow" url="/performance/tensorflow.csv" title="perf.py tensorflow --runtime=runc --runtime=runsc" >}}

For example, the above figure shows a sample TensorFlow workload, the
[convolutional neural network example][cnn]. The time indicated includes the
full start-up and run time for the workload, which trains a model.

## System calls

Some **structural costs** of gVisor are heavily influenced by the [platform
choice](../overview/), which implements system call interception. Today, gVisor
supports a variety of platforms. These platforms present distinct performance,
compatibility and security trade-offs. For example, the KVM platform has low
overhead system call interception but runs poorly with nested virtualization.

{{< graph id="syscall" url="/performance/syscall.csv" title="perf.py syscall --runtime=runc --runtime=runsc-ptrace --runtime=runsc-kvm" y_min="100" log="true" >}}

The above figure demonstrates the time required for a raw system call on various
platforms. The test is implemented by a custom binary which performs a large
number of system calls and calculates the average time required.

This cost will principally impact applications that are system call bound, which
tend to be high-performance data stores and static network services. In general,
the impact of system call interception will be lower the more work an
application does.

{{< graph id="redis" url="/performance/redis.csv" title="perf.py redis --runtime=runc --runtime=runsc" >}}

For example, `redis` is an application that performs relatively little work in
userspace: in general it reads from a connected socket, reads or modifies some
data, and writes a result back to the socket. The above figure shows the results
of running [comprehensive set of benchmarks][redis-benchmark]. We can see that
small operations impose a large overhead, while larger operations, such as
`LRANGE`, where more work is done in the application, have a smaller relative
overhead.

Some of these costs above are **structural costs**, and `redis` is likely to
remain a challenging performance scenario. However, optimizing the
[platform](../overview) will also have a dramatic impact.

## Start-up time

For many use cases, the ability to spin-up containers quickly and efficiently is
important. A sandbox may be short-lived and perform minimal user work (e.g. a
function invocation).

{{< graph id="startup" url="/performance/startup.csv" title="perf.py startup --runtime=runc --runtime=runsc" >}}

The above figure indicates how total time required to start a container through
[Docker][docker]. This benchmark uses three different applications. First, an
alpine Linux-container that executes `true`. Second, a `node` application that
loads a number of modules and binds an HTTP server. The time is measured by a
successful request to the bound port. Finally, a `ruby` application that
similarly loads a number of modules and binds an HTTP server.

> Note: most of the time overhead above is associated Docker itself. This is
> evident with the empty `runc` benchmark. To avoid these costs with `runsc`,
> you may also consider using `runsc do` mode or invoking the [OCI
> runtime](../../user_guide/oci) directly.

## Network

Networking is mostly bound by **implementation costs**, and gVisor's network stack
is improving quickly.

While typically not an important metric in practice for common sandbox use
cases, nevertheless `iperf` is a common microbenchmark used to measure raw
throughput.

{{< graph id="iperf" url="/performance/iperf.csv" title="perf.py iperf --runtime=runc --runtime=runsc" >}}

The above figure shows the result of an `iperf` test between two instances. For
the upload case, the specified runtime is used for the `iperf` client, and in
the download case, the specified runtime is the server. A native runtime is
always used for the other endpoint in the test.

{{< graph id="applications" metric="requests_per_second" url="/performance/applications.csv" title="perf.py http.(node|ruby) --connections=25 --runtime=runc --runtime=runsc" >}}

The above figure shows the result of simple `node` and `ruby` web services that
render a template upon receiving a request. Because these synthetic benchmarks
do minimal work per request, must like the `redis` case, they suffer from high
overheads. In practice, the more work an application does the smaller the impact
of **structural costs** become.

## File system

Some aspects of file system performance are also reflective of **implementation
costs**, and an area where gVisor's implementation is improving quickly.

In terms of raw disk I/O, gVisor does not introduce significant fundamental
overhead. For general file operations, gVisor introduces a small fixed overhead
for data that transitions across the sandbox boundary. This manifests as
**structural costs** in some cases, since these operations must be routed
through the [Gofer](../) as a result of our [security model](../security/), but
in most cases are dominated by **implementation costs**, due to an internal
[Virtual File System][vfs] (VFS) implementation the needs improvement.

{{< graph id="fio-bw" url="/performance/fio.csv" title="perf.py fio --engine=sync --runtime=runc --runtime=runsc" log="true" >}}

The above figures demonstrate the results of `fio` for reads and writes to and
from the disk. In this case, the disk quickly becomes the bottleneck and
dominates other costs.

{{< graph id="fio-tmpfs-bw" url="/performance/fio-tmpfs.csv" title="perf.py fio --engine=sync --runtime=runc --tmpfs=True --runtime=runsc" log="true" >}}

The above figure shows the raw I/O performance of using a `tmpfs` mount which is
sandbox-internal in the case of `runsc`. Generally these operations are
similarly bound to the cost of copying around data in-memory, and we don't see
the cost of VFS operations.

{{< graph id="httpd100k" metric="transfer_rate" url="/performance/httpd100k.csv" title="perf.py http.httpd --connections=1 --connections=5 --connections=10 --connections=25 --runtime=runc --runtime=runsc" >}}

The high costs of VFS operations can manifest in benchmarks that execute many
such operations in the hot path for serviing requests, for example. The above
figure shows the result of using gVisor to serve small pieces of static content
with predictably poor results. This workload represents `apache` serving a
single file sized 100k from the container image to a client running
[ApacheBench][ab] with varying levels of concurrency. The high overhead comes
principally from the VFS implementation that needs improvement, with several
internal serialization points (since all requests are reading the same file).
Note that some of some of network stack performance issues also impact this
benchmark.

{{< graph id="ffmpeg" url="/performance/ffmpeg.csv" title="perf.py media.ffmpeg --runtime=runc --runtime=runsc" >}}

For benchmarks that are bound by raw disk I/O and a mix of compute, file system
operations are less of an issue. The above figure shows the total time required
for an `ffmpeg` container to start, load and transcode a 27MB input video.

[ab]: https://en.wikipedia.org/wiki/ApacheBench
[benchmark-tools]: https://gvisor.googlesource.com/benchmark-tools
[gce]: https://cloud.google.com/compute/
[cnn]: https://github.com/aymericdamien/TensorFlow-Examples/blob/master/examples/3_NeuralNetworks/convolutional_network.py
[docker]: https://docker.io
[redis-benchmark]: https://redis.io/topics/benchmarks
[vfs]: https://en.wikipedia.org/wiki/Virtual_file_system
