# RDMA Support

[TOC]

gVisor supports RDMA (Remote Direct Memory Access) networking, allowing
sandboxed applications to use high-performance InfiniBand/RoCE hardware — for
example, multi-node NCCL collectives in distributed AI/ML training — while
keeping the host isolated from the workload.

To achieve this, gVisor implements a proxy driver inside the sandbox, henceforth
referred to as `rdmaproxy`. `rdmaproxy` proxies the application's interactions
with the host's RDMA driver, giving the sandboxed application access to the RDMA
verbs devices (`/dev/infiniband/uverbs*`) declared in its OCI spec. The
application — and libraries such as `libibverbs` and NCCL — can run unmodified
inside the sandbox and interact transparently with these devices. gVisor also
constructs a faithful view of the host's RDMA topology under `/sys` so that
device-discovery and topology-detection logic behaves the same inside the
sandbox as on the host.

RDMA support is enabled with the `--rdmaproxy` flag and applies to containers
whose OCI spec lists one or more `/dev/infiniband/uverbs*` devices.

When combined with GPUs (see [GPU Support](gpu.md)), gVisor supports GPUDirect
RDMA, allowing the NIC to transfer data directly to and from GPU memory.

## Limitations

RDMA support is under active development. The following limitations apply:

*   **Mellanox and AWS EFA NICs only.** Only Mellanox ConnectX (`mlx5`) adapters
    and AWS Elastic Fabric Adapters (`efa`) are currently supported. Support for
    additional vendors is planned.

*   **Host kernel 5.12 or newer.** `rdmaproxy` proxies the modern
    `RDMA_VERBS_IOCTL` interface only; the legacy `write(2)` command interface
    is not supported. The newest uverbs ioctl method it relies on, dma-buf
    memory registration for GPUDirect RDMA, landed in Linux 5.12.

*   **GPUDirect uses dma-buf only.** GPU memory is registered with the NIC
    through the dma-buf mechanism, which is the modern default. The legacy
    `nvidia-peermem` kernel-module path is not supported.

*   **EFA needs a dma-buf-capable NCCL plugin.** Because GPUDirect works only
    through dma-buf (above), AWS EFA requires `aws-ofi-nccl` v1.19.2 or newer:
    earlier releases hard-disable dma-buf on EFA device generations 1-3 and
    register GPU memory by virtual address instead, which is not supported.

*   **Single-container sandboxes only.** The RDMA devices must be declared in
    the OCI spec of the sandbox's root container. Deployments where the devices
    appear only in a sub-container's spec — such as a Kubernetes pod where the
    RDMA devices belong to an application container rather than the pod's root —
    are not yet supported.

*   **Device lifecycle at sandbox creation.** The RDMA network devices must
    still reside in the host network namespace when the sandbox is created
    (`runsc create`), and must not be pre-placed into the sandbox's network
    namespace beforehand. They should then be moved, fully configured, into the
    sandbox's network namespace before the application connects RDMA queue pairs
    — for example via an OCI `createRuntime` hook or between `runsc create` and
    `runsc start`. Such setup is not unusual; Docker seems to be doing this as
    well.

*   **RoCE requires shared RDMA namespace mode.** For RoCE (RDMA over Converged
    Ethernet) devices, the host's RDMA subsystem must be in the shared
    network-namespace mode (`rdma system set netns shared`), which is the
    default on most systems.

*   **No checkpoint/restore.** Sandboxes using RDMA devices cannot be
    checkpointed.
