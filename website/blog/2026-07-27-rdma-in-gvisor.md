# RDMA in gVisor: A Deep Dive into GPU Networking

It is helpful to think of the Operating System (OS) on a machine as having two
distinct spaces:

1.  The [kernel](https://github.com/torvalds/linux) space, or the OS's core. It
    manages hardware resources like RAM and CPU.
2.  The user-space, which is the home of most user processes. These
    applications communicate with the OS via system calls (syscalls) to the
    kernel.

DMA (Direct Memory Access) allows devices like network interface cards (NICs)
to directly access RAM without copying data through the CPU. The kernel is
involved in receiving completion events and propogating them back to the
user-space application.

RDMA (Remote Direct Memory Access) extends DMA by allowing one peer to read and
write into another peer's memory. Additionally, user-space work and their
completions bypass the kernel, allowing for high-throughput, low-latency
communication.

<!--/excerpt-->

Special networking hardware for RDMA exists that can send up to
[800 Gbps](https://resources.nvidia.com/en-us/accelerated-networking-resource-library/connectx-9-supernic-datasheet)
of data over the wire. The common physical transports are InfiniBand, which is
dominated by NVIDIA-acquired Mellanox, and RoCE (RDMA over Converged Ethernet),
which implements InfiniBand semantics on upgraded ethernet hardware. To allow
the user-space direct InfiniBand/RoCE access, applications call
[`libibverbs`](https://github.com/linux-rdma/rdma-core/blob/master/Documentation/libibverbs.md)
via `uverbs` character devices.

<figure>
<img src="/assets/images/2026-07-27-rdma-in-gvisor-updated-rdma.png" alt="RDMA architecture in gVisor">
<figcaption>Figure 1: <code>uverbs</code> provides direct access to the NIC hardware. In a RDMA transfer, a work queue element (WQE) is created by the application, the message gets sent over the NIC, acknowledged by the peer, and propogated back to the application as a completion queue element (CQE). RDMA sets up persistent send queues (SQ) and receive queues (RQ) that together form a queue pair (QP).</figcaption>
</figure>

## The gVisor Container Runtime

[gVisor](https://gvisor.dev/) is a container runtime for sandboxed
applications. Containers run user application code as a guest process and
intercept all syscalls to the kernel. gVisor traps syscalls and emulates them
in a user-space kernel called the Sentry. For example, memory management,
networking, and fetching files from the host filesystem (via
[gofer](https://gvisor.dev/docs/user_guide/filesystem/)) are all handled in the
Sentry process: nothing has to go directly to the host kernel.

Proxies for devices like GPUs are an exception to the emulation rule: they pass
syscalls through to the host kernel. For example, a containerized application
calls `cudaMemcpy()`, which issues an `ioctl` on a GPU device. gVisor:

1.  Traps syscall and routes it to the correct handler based on command number.
2.  Translates the application's GPU device
    [file descriptor](https://en.wikipedia.org/wiki/File_descriptor) (FD) to a
    host GPU device FD.
3.  Issues the `ioctl` against the kernel and copied the result back out to the
    application.

<figure>
<img src="/assets/images/2026-07-27-rdma-in-gvisor-gvisor-space.png" alt="gVisor spaces">
<figcaption>Figure 2: The "Sentry" runs as a separate process in the gVisor sandbox. gVisor's sentry traps syscalls from the containerized application to the host kernel. Most of these syscalls are emulated in the Sentry; however, ioctls to GPU devices are forwarded to the host.</figcaption>
</figure>

## Supporting GPUDirect RDMA in gVisor

[Supporting RDMA with InfiniBand](https://github.com/google/gvisor/issues/10906)
is a highly-requested feature. Our target implementation adds a `RDMAProxy`
syscall interface to gVisor and forwards RDMA syscalls through to the host
kernel.

My goal is to match the peak bandwidth performance of gVisor RDMA to
[`runc`](https://github.com/opencontainers/runc) with a 10% margin. `runc` is a
popular container runtime that lacks the security isolation of gVisor, and all
RDMA syscalls work out of the box.

In default operation, CUDA applications use
[GPUDirect RDMA](https://docs.nvidia.com/cuda/gpudirect-rdma/index.html#overview),
which allows for true P2P data transfer between GPUs. GPUDirect RDMA skips
copying data from CPU to GPU. Instead, the NIC writes its data directly to GPU
device memory via a shared PCI bridge between the NIC and GPU. You should see a
10x increase in bandwidth when using this mode of operation.

## Memory Registration in RDMA

After a gVisor container receives all information about the host's RDMA
hardware, the application registers memory for the data transfer, whether from
host or GPU RAM. An RDMA-enabled NIC receives a
[scatter-gather](http://osr600doc.sco.com/en/HDK_concepts/ddT_scgth.html) list
containing the physically contiguous regions of memory. The "scatter" comes
from how the OS page table works: virtual regions of memory may be scattered
across many different physical pages. "Gather" refers to a NIC grouping these
physical pages into one logical range for transmission or reception of data.

<figure>
<img src="/assets/images/2026-07-27-rdma-in-gvisor-scatter_gather.png" alt="Scatter-gather list">
<figcaption>Figure 3: The RDMA NICs map 1:1 to every GPU on the host. During memory registration, <code>uverbs</code> programs the NIC with a scatter-gather list of memory regions to be used in RDMA. The scatter-gather list contains virtual addresses and the corresponding length of physically contiguous memory starting at that address.</figcaption>
</figure>

RDMA is designed to bypass the kernel in the data-path (hot-path) of a RDMA
transfer. However, an application cannot simply map some memory, program it
into the NIC, and start the RDMA transfer. What happens if the kernel realizes
that these pages are no longer being referenced or written to and decides to
evict the memory pages from RAM? To keep the kernel completely out of the hot
path, most RDMA applications "pin" the virtual regions of memory to prevent the
kernel from moving the underlying physical backing of memory critical in the
RDMA hot-path.

For gVisor, the RDMA application process picks the virtual address regions it
wants to pin, `uverbs` receives an
[`ibv_reg_mr()`](https://man7.org/linux/man-pages/man3/ibv_reg_mr.3.html) call,
and gVisor forwards any
[`ioctl()`](https://man7.org/linux/man-pages/man2/ioctl.2.html) calls to the
kernel-mode RDMA driver.

<figure>
<img src="/assets/images/2026-07-27-rdma-in-gvisor-address-resolution-gvisor.png" alt="Address resolution in gVisor">
<figcaption>Figure 4: The sentry translates application virtual addresses to an internal virtual address backed by host memory. An application issues a call to <code>ibv_reg_mr()</code>, but the virtual address can overlap between separate CUDA processes. The sentry now maps process-specific addresses to a single host address, causing a fatal collision when <code>ibv_reg_mr()</code> gets forwarded to the NVIDIA kernel module.</figcaption>
</figure>

## Using DMABUF to Bypass Memory Collisions

In my initial implementation, NCCL gets wedged during memory registration:

<figure>
<pre><code>NCCL Couldn't register memory region with regattr. RC: -14, ERROR: Bad address</code></pre>
<figcaption>Figure 5: NCCL is the NVIDIA Collective Communications Library, commonly used in multi-node training.</figcaption>
</figure>

On a machine with multiple GPUs, each GPU device has its own virtual address
(VA) range, which may be the same across different devices. To identify the
right device for a VA range, CUDA creates a separate application process for
each GPU, and the NVIDIA kernel module checks the calling process's identifier
(PID).

In gVisor, the sentry traps all syscalls and passes them through to the kernel.
`ibv_reg_mr()` calls from logically different processes get multiplexed into a
single process's syscalls, causing a fatal address collision.

One solution is to transform the Sentry from a single process architecture to a
multi-process architecture, which is a massive rewrite. NVIDIA's main RDMA
documentation mentions only a single mechanism, the
[`nvidia-peermem`](https://docs.nvidia.com/cuda/gpudirect-rdma/index.html#using-nvidia-peermem)
kernel module, for performing GPUDirect RDMA. However, I did a little digging
into the NCCL environment variables for RDMA and noticed a second, hidden
flavor of GPUDirect RDMA:
[DMABUF](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/env.html#nccl-dmabuf-enable).

DMABUF leverages the existing
[`dma-buf`](https://docs.kernel.org/driver-api/dma-buf.html#shared-dma-buffers)
Linux subsystem for sharing DMA memory between processes. An "exporter" creates
the DMABUF object containing a scatter-gather list, and an "importer" receives
the file descriptor pointing to this object. We can create a DMABUF object via
the CUDA user-space `libcuda.so`, receive the object's file handle upon a
successful syscall to the NVIDIA kernel module `nvidia.ko`, and share the file
handle with [`uverbs`](https://github.com/linux-rdma/rdma-core), the NIC's RDMA
user-interface library. Most importantly, the DMABUF exporter in NVIDIA's
kernel module does not depend on the PID of the calling process, and we can use
sentry without rewriting any architecture.

<figure>
<img src="/assets/images/2026-07-27-rdma-in-gvisor-dmabuf.png" alt="DMABUF">
<figcaption>Figure 6: The exporter creates a DMABUF object and installs it in the kernel using the <code>dma-buf</code> subsystem. A file descriptor is shared to the application and then the <code>uverbs</code> subsystem, which can import the DMABUF object.</figcaption>
</figure>

## Networking Challenges

When do two hosts connect to set up RDMA? What data gets exchanged during the
bootstrap (handshake) step? How are network devices identified within a cluster
of nodes?

To address other devices, `uverbs` relies on a GID (Global Identifier), which
is a 128-bit number like an IPv6 address. The
[`rdma_cm`](https://linux.die.net/man/7/rdma_cm) (RDMA Connection Manager) uses
these GIDs to perform the bootstrap step. This step exchanges queue pair (QP)
numbers, which tell the NICs where to post RDMA work requests. Without
`rdma_cm`, all bootstrap happens via TCP over standard ethernet devices. NVIDIA
applications do not use `rdma_cm` and choose the TCP path instead.

Between
[RoCE](https://networking-docs.nvidia.com/mlnxofedswum/23070512/rdma-over-converged-ethernet-roce)
and regular InfiniBand, the GIDs are derived differently. On InfiniBand, the
vendor burns a GUID (Globally Unique Identifier) into the NIC firmware, but the
RoCE GIDs are assigned dynamically. GIDs for InfiniBand look like
`<subnet-prefix>:<mac-address>` while the GIDs for RoCE are either an IPv6
address derived from the MAC address or an IPv6 formatted IPv4 address like
`<80-zeros:ffff:<ipv4-address>`. Per NIC on both transports, a GID table
contains the mapping of ports on the NIC to GIDs.

One problem arises due to moving RDMA interfaces between network namespaces.
RoCE relies on the IPv4 addresses of these interfaces to populate the device's
GID. A background service, such as the machine vendor's startup process, will
assign static IPs to the interfaces upon boot. When the interfaces are moved
out of the host namespace, the kernel clears the IP addresses. Nothing in the
container assigns IP addresses to the interfaces, causing GIDs to be
unpopulated and `ibv_modify_qp()` to fail.

Our solution requires manually assigning the IP addresses if a user decides to
move RDMA interfaces into the container. The problem was particularly
challenging to debug: as IP addresses disappear, moving them back into the host
namespace fails to restore them, and your testing nodes are cooked!

## Questions

**1. How do RDMA and NCCL differ between GPU instance types (e.g. AWS EFA vs
Mellanox, Blackwell vs Hopper, IPoIB vs RoCE)?**

[EFA](https://aws.amazon.com/hpc/efa/) resembles InfiniBand `uverbs` devices
but uses Amazon's custom RDMA provider implementation. The
[whitepaper](https://assets.amazon.science/a6/34/41496f64421faafa1cbe301c007c/a-cloud-optimized-transport-protocol-for-elastic-and-scalable-hpc.pdf)
discusses preventing head-of-line delays by allowing messages to arrive
out-of-order, which reduces congestion for large AWS datacenters.

Since the EFA interface is quite similar to InfiniBand, replicating the syscall
shim was easy except for a few issues with the
[`aws-ofi-nccl` plugin](https://github.com/aws/aws-ofi-nccl). AWS only started
allowing DMABUF two months before this post, and my image's NCCL version
pre-dated the release that removed the
[feature gate](https://github.com/aws/aws-ofi-nccl/commit/0f285d5670cd6b38bd742def645979041ac373b6).
Next, the kernel version gVisor presents was gated by the plugin, but
hard-coding a version `>= 5.12` fixed the issue.

Regarding GPU architecture, Blackwell chips are shipped with 2x higher
bandwidth networking cards than Hopper chips. NCCL support is quite fragile for
B200s, but setting
[`NVIDIA_CUMEM_ENABLE=0`](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/env.html#nccl-cumem-enable)
seems to
[pop the bubbles](https://docs.vllm.ai/en/v0.6.6/getting_started/debugging.html#known-issues).

Most cloud providers are using RoCE with their NVIDIA chips, and InfiniBand
consumers set
[IPoIB inactive](https://support.crusoecloud.com/hc/en-us/articles/38559194513691-How-To-Validate-InfiniBand-Hardware-and-Test-RDMA-Connectivity-for-GPU-VMs-in-Crusoe-Cloud)
for their virtual machines.

**2. What is the length of a RDMA transfer? How often does memory registration
occur?**

For a single all-reduce operation, the RDMA setup happens once upfront and NCCL
can reuse this setup for multiple collective operations. Below, I am running a
[multi-node benchmark](https://github.com/modal-labs/multinode-training-guide/tree/main/benchmark)
on an all-reduce operation transferring 4.0 GB of data over 50 trials.

<figure>
<img src="/assets/images/2026-07-27-rdma-in-gvisor-perfetto-trace.png" alt="CUDA trace">
<figcaption>Figure 7: Perfetto trace of an all-reduce benchmark profiling gVisor syscalls, <code>uverbs</code> <code>ioctl()</code> calls, and CUDA calls. <code>RM_ALLOC</code> is called in the first group of <code>uverbs</code> <code>ioctl()</code> calls but not in the second group, hinting that all 50 trials executed during the ~250ms gap in <code>uverbs</code>/CUDA <code>ioctl()</code> calls.</figcaption>
</figure>

The span of setup + transfer + teardown takes about 2s in total. RDMA setup
reduces end-to-end latency for large, steady workloads but not for small,
bursty workloads.

## Results

Below are benchmark results for the RDMA implementation on instance types from
various cloud providers. All metrics match `runc` performance 1:1 within a
couple of Gbps of variance.

Instance Type    | Busbw         | Algbw
---------------- | ------------- | -------------
Crusoe B200s     | `873.1 Gbps`  | `465.7 Gbps`
Oracle B200s     | `5536.8 Gbps` | `2953.0 Gbps`
GCP B200s        | `4931.7 Gbps` | `2630.3 Gbps`
Whitefiber H200s | `3836.4 Gbps` | `2046.1 Gbps`

Here are our team's PRs for those interested:

1.  [Mounting RDMA files from `sysfs` in the container](https://github.com/google/gvisor/pull/13712)
2.  [Supporting DMABUF in `nvproxy`](https://github.com/google/gvisor/pull/13736)
3.  [Adding `RDMAProxy` interface and plugin for Mellanox ConnectX devices](https://github.com/google/gvisor/pull/13779)

I predict that RDMA network cards will continue to increase in bandwidth, and
my hope is that hardware production expands across multiple manufacturers.
Google is partnering with Intel to manufacture custom
[NICs](https://cloud.google.com/blog/topics/systems/introducing-falcon-a-reliable-low-latency-hardware-transport)
for their TPUs. gVisor is already working on
[supporting Falcon hardware](https://github.com/google/gvisor/issues/13686),
which is very exciting!

I want to thank the team at [Modal](https://modal.com) who collaborated with me
on this project: Ayush Ranjan, the gVisor maintainer, and Peyton Walters, my
internship mentor. Thank you Ayush, Erik Dunteman, Marmik Chaudhari, Abinaya
Dinesh, Ben O'Keefe, and Rahul Chalamala for providing helpful feedback on this
post.
