# AMD GPU proxy

`amdgpuproxy` implements `/dev/kfd` and `/dev/dri/renderD*` for ROCm compute
on top of the host's AMDGPU/KFD driver. It is experimental. Enable it with
`--amdgpuproxy=compute`, which requires `--platform=kvm`, and grant `/dev/kfd` plus the
desired render nodes in the OCI spec (for Docker, `--device=/dev/kfd
--device=/dev/dri/renderD128`). Only gfx942 (MI300) and gfx950 (MI355) GPUs are
admitted; they are the ones this has been tested on.

Applications must run with the following settings, which disable the ROCm
features the proxy does not forward:

```
HSA_ENABLE_SDMA=0 HSA_USE_SVM=0 HSA_XNACK=0
HIP_MEM_POOL_USE_VM=0 DEBUG_HIP_MEM_POOL_VMHEAP=0 HIP_VMEM_MANAGE_SUPPORT=0
```

## Design

The proxy trusts the host driver to handle what an unprivileged native process
could ask of it, as nvproxy does. Its job is to keep the application's pointers
and descriptors out of the sentry's address space:

-   The 21 ioctl requests that ROCm uses are forwarded; everything else, in
    particular SVM, dma-buf, IPC and debugging, fails with `ENOTTY`. The host
    seccomp filter admits exactly the same requests.
-   Arguments are copied through sentry memory. Nested buffers (device ID
    lists, apertures, event arrays, DRM strings) are bounced the same way.
-   `USERPTR` allocations name application memory that the driver keeps
    faulting in through its MMU notifier. The proxy pins the application's
    pages and registers a contiguous sentry alias of them, released when the
    allocation is freed.
-   `ACQUIRE_VM` receives the application's render node FD and passes the
    host FD behind it.
-   XNACK is turned off for the sentry's KFD process before applications run.
    With it on, GPU page faults are resolved through SVM against the KFD
    process's address space, which is the sentry's.
-   SDMA queues are refused: the driver's `sdma_activity` statistic reads a
    queue's read pointer as a CPU address of the KFD process.
-   A signal page supplied to `CREATE_EVENT` must hold the 4096 event slots
    the driver initializes in it. Older driver releases do not check this
    and overrun a smaller buffer's kernel mapping.
-   KFD hides the GPUs whose render node the device cgroup denies to a
    process. The sentry is not subject to the container's device cgroup, so
    the proxy stands in for it: apertures are filtered to the granted GPUs and
    requests naming other GPUs fail with `EINVAL`, as they do natively.

KFD binds its per-process state to the host address space that opened
`/dev/kfd`, so the sentry opens it itself, in the final sentry process, and
every application open duplicates that FD. Consequently there is one GPU
context per sandbox: the first application address space to open a GPU device
owns it, other processes get `EBUSY`, and a process's GPU resources are only
released with the sandbox. `kfd_mmap` likewise requires the mapping process to
be the KFD process, which is why the KVM platform, whose application mappings
are made by the sentry itself, is required.

Render node mappings use the CPU memory type the driver uses for the
allocation, write-combining for VRAM and cached for GTT, while doorbell and
MMIO mappings through `/dev/kfd` are uncached.

The sandbox's `/sys` carries a snapshot of the host's KFD topology, taken
whole, plus the PCI identity of each granted render node. ROCm's thunk
enumerates the topology by index and itself hides the GPUs whose render node
it cannot open, as it does under native device cgroups.
