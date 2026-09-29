# AMD GPU Support

[TOC]

gVisor can run ROCm compute workloads, such as HIP applications and PyTorch, on
AMD Instinct GPUs. To achieve this, gVisor implements a proxy driver inside the
sandbox, henceforth referred to as `amdgpuproxy`. `amdgpuproxy` proxies the
application's interactions with the host's AMDGPU/KFD driver through the
compute device `/dev/kfd` and the DRM render nodes `/dev/dri/renderD*` granted
to the container. ROCm userspace runs unmodified inside the sandbox. gVisor also
reproduces the host's KFD topology under `/sys`, so ROCm's device discovery
behaves the same inside the sandbox as on the host.

AMD GPU support is **experimental**. It has been validated with HIP and PyTorch
workloads on MI300X (gfx942) and MI355X (gfx950) GPUs, and `runsc` refuses
other GPU models. For NVIDIA GPUs, see [NVIDIA GPU Support](gpu.md).

## Enabling AMD GPU support

Pass `--amdgpuproxy=compute` to `runsc`. The [KVM platform](platforms.md) is
required (see [Limitations](#limitations)). The container's OCI spec must list
`/dev/kfd` and the render node of every GPU the container may use; GPUs whose
render node is not listed are not exposed, and `runsc` verifies that each
listed device is the host's KFD device or an `amdgpu` render node. Display
nodes (`/dev/dri/card*`) are never exposed.

ROCm has no equivalent of the NVIDIA container toolkit's library injection, so
the container image must contain the ROCm userspace, or bind-mount the host's
installation. Sandboxed applications must also run with the following
environment, which disables the ROCm features that `amdgpuproxy` does not
forward (see [Limitations](#limitations)):

```
HSA_ENABLE_SDMA=0
HSA_USE_SVM=0
HSA_XNACK=0
HIP_MEM_POOL_USE_VM=0
DEBUG_HIP_MEM_POOL_VMHEAP=0
HIP_VMEM_MANAGE_SUPPORT=0
```

With Docker, register a runtime whose `runsc` is invoked with
`--platform=kvm --amdgpuproxy=compute`, then grant the devices with `--device`:

```
$ docker run --runtime=runsc --rm \
    --device=/dev/kfd --device=/dev/dri/renderD128 \
    -e HSA_ENABLE_SDMA=0 -e HSA_USE_SVM=0 -e HSA_XNACK=0 \
    -e HIP_MEM_POOL_USE_VM=0 -e DEBUG_HIP_MEM_POOL_VMHEAP=0 \
    -e HIP_VMEM_MANAGE_SUPPORT=0 \
    rocm/pytorch python3 -c 'import torch; print(torch.cuda.get_device_name())'
AMD Instinct MI300X
```

Granting several render nodes exposes several GPUs to the same application;
peer-to-peer copies between them are supported.

## Limitations

*   **One GPU process per sandbox.** KFD binds all of a process's GPU state to
    the host address space that opened `/dev/kfd`, which in gVisor is the
    sentry's. A sandbox therefore has a single GPU context: the first
    application process to open a GPU device owns it for the lifetime of the
    sandbox, other processes, including forked children, get `EBUSY`, and the
    GPU memory of a process that exits is only released when the sandbox exits.
    Frameworks that run one process per GPU, such as `torchrun`, are not
    supported; run one GPU process per sandbox.
*   **KVM platform only.** KFD only maps its doorbell pages into the process
    that opened `/dev/kfd`. Of gVisor's platforms, only KVM maps device memory
    for the application from the sentry itself.
*   **Unsupported ROCm features.** Shared virtual memory (SVM) and XNACK retry
    faults, SDMA engines, DMA-BUF export and import, GPU IPC, the runtime
    debugger, and checkpoint/restore are not supported. `hipMallocManaged()`
    works through ROCm's non-SVM path, that is without GPU page migration.
*   **Supported GPUs.** Only gfx942 (MI300) and gfx950 (MI355) GPUs are
    admitted, on the AMDGPU/KFD driver versions they were validated with. Other
    models fail at sandbox start.

## Security

`amdgpuproxy` follows the same model as `nvproxy`; the
[discussion of GPU security](gpu.md#security) applies. The proxy forwards a
fixed set of 21 KFD and DRM `ioctl`s, mirrored in the sandbox's seccomp filter,
and the host driver is trusted to handle those requests as it would for any
unprivileged native process. The proxy's own job is to keep the application's
pointers and file descriptors out of the sentry's address space: `ioctl`
arguments and their nested buffers are copied through the sentry, registered
application memory is pinned, and XNACK is kept off so that GPU page faults can
never be resolved against the sentry's memory. Vulnerabilities in the host
driver's handling of the forwarded requests are not mitigated, so **AMD driver
updates must be part of any security plan with or without gVisor**. The
[design notes](https://github.com/google/gvisor/blob/master/pkg/sentry/devices/amdgpuproxy/README.md)
describe the proxy in more detail.
