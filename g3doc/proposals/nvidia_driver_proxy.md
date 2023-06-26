# Nvidia Driver Proxy

Status as of 2023-06-23: Under review

## Synopsis

Allow applications running within gVisor sandboxes to use CUDA on GPUs by
providing implementations of Nvidia GPU kernel driver files that proxy ioctls to
their host equivalents.

Non-goals:

-   Provide additional isolation of, or multiplexing between, GPU workloads
    beyond that provided by the driver and hardware.

-   Support use of GPUs for graphics rendering.

## Background

### gVisor, Platforms, and Memory Mapping

gVisor executes unmodified Linux applications in a sandboxed environment.
Application system calls are intercepted by gVisor and handled by (in essence) a
Go implementation of the Linux kernel called the *sentry*, which in turn
executes as a sandboxed userspace process running on a Linux host.

gVisor can execute application code via a variety of mechanisms, referred to as
"platforms". Most platforms can broadly be divided into process-based (ptrace,
systrap) and KVM-based (kvm). Process-based platforms execute application code
in sandboxed host processes, and establish application memory mappings by
invoking the `mmap` syscall from application process context; sentry and
application processes share a file descriptor (FD) table, allowing application
`mmap` to use sentry FDs. KVM-based platforms execute application code in the
guest userspace of a virtual machine, and establish application memory mappings
by establishing mappings in the sentry's address space, then forwarding those
mappings into the guest physical address space using KVM memslots and finally
setting guest page table entries to point to the relevant guest physical
addresses.

### Nvidia Userspace API

[`libnvidia-container`](https://github.com/NVIDIA/libnvidia-container) provides
code for preparing a container for GPU use, and serves as a useful reference for
the environment that applications using GPUs expect. In particular,
[`nvc_internal.h`](https://github.com/NVIDIA/libnvidia-container/blob/main/src/nvc_internal.h)
contains a helpful list of relevant filesystem paths, while
[`configure_command()`](https://github.com/NVIDIA/libnvidia-container/blob/main/src/cli/configure.c)
is the primary entry point into container configuration. Of these paths,
`/dev/nvidiactl`, `/dev/nvidia#` (per-device, numbering from 0),
`/dev/nvidia-uvm`, and `/proc/driver/nvidia/params` are kernel-driver-backed and
known to be required.

Most "control" interactions between applications and the driver consist of
invocations of the `ioctl` syscall on `/dev/nvidiactl`, `/dev/nvidia#`, or
`/dev/nvidia-uvm`. Application data generally does not flow through ioctls;
instead, applications access driver-provided memory mappings.
`/proc/driver/nvidia/params` is informational and read-only.

`/dev/nvidiactl` and `/dev/nvidia#` are backed by the same `struct
file_operations nv_frontend_fops` in kernel module `nvidia.ko`, rooted in
`kernel-open/nvidia` in the
[Nvidia Linux OSS driver source](https://github.com/NVIDIA/open-gpu-kernel-modules.git).
The top-level `ioctl` implementation for both,
`kernel-open/nvidia/nv.c:nvidia_ioctl()`, handles a small number of ioctl
commands but delegates the majority to the "resource manager" (RM) subsystem,
`src/nvidia/arch/nvalloc/unix/src/escape.c:RmIoctl()`. Both functions constrain
most commands to either `/dev/nvidiactl` or `/dev/nvidia#`, as indicated by the
presence of the `NV_CTL_DEVICE_ONLY` or `NV_ACTUAL_DEVICE_ONLY` macros
respectively.

`/dev/nvidia-uvm` is implemented in kernel module `nvidia-uvm.ko`, rooted in
`kernel-open/nvidia-uvm` in the OSS driver source; its `ioctl` implementation is
`kernel-open/nvidia-uvm/uvm.c:uvm_ioctl()`.

The driver API models a collection of objects, using numeric handles as
references (akin to the relationship between file descriptions and file
descriptors). Objects are instances of classes, which exist in a C++-like
inheritance hierarchy that is implemented in C via code generation; for example,
the `RsResource` class inherits from the `Object` class, which is the
hierarchy's root. Objects exist in a tree of parent-child relationships, defined
by methods on the `Object` class. API-accessed objects are most frequently
created by invocations of `ioctl(NV_ESC_RM_ALLOC)`, which is parameterized by
`hClass`. `src/nvidia/src/kernel/rmapi/resource_list.h` specifies the mapping
from `hClass` to instantiated ("internal") class, as well as the type of the
pointee of `NVOS21_PARAMETERS::pAllocParms` or `NVOS64_PARAMETERS::pAllocParms`
which the object's constructor takes as input ("alloc param info").

## Key Issues

Most application ioctls to GPU drivers can be *proxied* straightforwardly by the
sentry: The sentry copies the ioctl's parameter struct, and the transitive
closure of structs it points to, from application to sentry memory; reissues the
ioctl to the host, passing pointers in the sentry's address space rather than
the application's; and copies updated fields (or whole structs for simplicity)
back to application memory. Below we consider complications to this basic idea.

### Unified Virtual Memory (UVM)

GPUs are equipped with "device" memory that is much faster for the GPU to access
than "system" memory (as used by CPUs). CUDA supports two basic memory models:

-   `cudaMalloc()` allocates device memory, which is not generally usable by the
    CPU; instead `cudaMemcpy()` is used to copy between system and device
    memory.

-   `cudaMallocManaged()` allocates "unified memory", which can be used by both
    CPU and GPU. `nvidia-uvm.ko` backs mappings returned by
    `cudaMallocManaged()`, migrating pages from system to device memory on GPU
    page faults and from device to system memory on CPU page faults.

We cannot implement UVM by substituting a sentry-controlled buffer and copying
to/from UVM-controlled memory mappings "on demand", since GPU-side demand is
driven by GPU page faults which the sentry cannot intercept directly; instead,
we must map `/dev/nvidia-uvm` into application address spaces as in native
execution.

UVM requires that the virtual addresses of all mappings of `nvidia-uvm` match
their respective mapped file offset, which in conjunction with the FD uniquely
identify a shared memory segment[^cite-uvm-mmap]. Since this constraint also
applies to *sentry* mappings of `nvidia-uvm`, if an application happens to
request a mapping of `nvidia-uvm` at a virtual address that overlaps with an
existing sentry memory mapping, then `memmap.File.MapInternal()` is
unimplementable. On KVM-based platforms, this means that we cannot implement the
application mapping, since `MapInternal` is a required step to propagating the
mapping into application address spaces. On process-based platforms, this only
means that we cannot support e.g. `read(2)` syscalls targeting UVM memory; if
this is required, we can perform buffered copies from/to UVM memory using
`ioctl(UVM_TOOLS_READ/WRITE_PROCESS_MEMORY)`, at the cost of requiring
`MapInternal` users to explicitly indicate fill/flush points before/after I/O.

The extent to which applications use `cudaMallocManaged()` is unclear; use of
`cudaMalloc()` and explicit copying appears to predominate in
performance-sensitive code. PyTorch contains one non-test use of
`cudaMallocManaged()`[^cite-pytorch-uvm], but it is not immediately clear what
circumstances cause the containing function to be invoked. Tensorflow does not
appear to use `cudaMallocManaged()` outside of test code.

### Device Memory Caching

For both `cudaMalloc()` and "control plane" purposes, applications using CUDA
map some device memory into application address spaces, as follows:

1.  The application opens a new `/dev/nvidiactl` or `/dev/nvidia#` FD, depending
    on the memory being mapped.

2.  The application invokes `ioctl(NV_ESC_RM_MAP_MEMORY)` on an *existing*
    `/dev/nvidiactl` FD, passing the *new* FD as an ioctl parameter
    (`nv_ioctl_nvos33_parameters_with_fd::fd`). This ioctl stores information
    for the mapping in the new FD (`nv_linux_file_private_t::mmap_context`), but
    does not modify the application's address space.

3.  The application invokes `mmap` on the *new* FD to actually establish the
    mapping into its address space.

Conveniently, it is apparently permissible for the `ioctl` in step 2 to be
invoked from a different process than the `mmap` in step 3, so no gVisor changes
are required to support this pattern in general; we can invoke the `ioctl` in
the sentry and implement `mmap` as usual.

However, mappings of device memory often need to disable or constrain processor
caching for correct behavior. In modern x86 processors, caching behavior is
specified by page table entry flags[^cite-sdm-pat]. On process-based platforms,
application page tables are defined by the host kernel, whose `mmap` will choose
the correct caching behavior by delegating to the driver's implementation. On
KVM-based platforms, the sentry maintains guest page tables and consequently
must set caching behavior correctly.

Caching behavior for mappings obtained as described above is decided during
`NV_ESC_RM_MAP_MEMORY`, by the "method `RsResource::resMap`" for the driver
object specified by ioctl parameter `NVOS33_PARAMETERS::hMemory`. In most cases,
this eventually results in a call to
[`src/nvidia/src/kernel/rmapi/mapping_cpu.c:memMap_IMPL()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/4397463e738d2d90aa1164cc5948e723701f7b53/src/nvidia/src/kernel/rmapi/mapping_cpu.c#L167)
on an associated `Memory` object. Caching behavior thus depends on the logic of
that function and the `MEMORY_DESCRIPTOR` associated with the `Memory` object,
which is typically determined during object creation. Therefore, to support
KVM-based platforms, the sentry could track allocated driver objects and emulate
the driver's logic to determine appropriate caching behavior.

Alternatively, could we replicate the caching behavior of the host kernel's
mapping in the sentry's address space (in `vm_area_struct::vm_page_prot`)? There
is no apparent way for userspace to obtain this information, so this would
necessitate a Linux kernel patch or upstream change.

### OS-Described Memory

`ioctl(NV_ESC_RM_ALLOC_MEMORY, hClass=NV01_MEMORY_SYSTEM_OS_DESCRIPTOR)` and
`ioctl(NV_ESC_RM_VID_HEAP_CONTROL,
function=NVOS32_FUNCTION_ALLOC_OS_DESCRIPTOR)` create `OsDescMem` objects, which
are `Memory` objects backed by application anonymous memory. The ioctls treat
`NVOS02_PARAMETERS::pMemory` or `NVOS32_PARAMETERS::data.AllocOsDesc.descriptor`
respectively as an application virtual address and call Linux's
`pin_user_pages()` or `get_user_pages()` to get `struct page` pointers
representing pages starting at that address[^cite-osdesc-rmapi]. Pins are held
on those pages for the lifetime of the `OsDescMem` object.

The proxy driver will need to replicate this behavior in the sentry, though
doing so should not require major changes outside of the driver. When one of
these ioctls is invoked by an application:

-   Invoke `mmap` to create a temporary `PROT_NONE` mapping in the sentry's
    address space of the size passed by the application.

-   Call `mm.MemoryManager.Pin()` to acquire file-page references on the given
    application memory.

-   Call `memmap.File.MapInternal()` to get sentry mappings of pinned
    file-pages.

-   Use `mremap(old_size=0, flags=MREMAP_FIXED)` to replicate mappings returned
    by `MapInternal()` into the temporary mapping, resulting in a
    virtually-contiguous sentry mapping of the application-specified address
    range.

-   Invoke the host ioctl using the sentry mapping.

-   `munmap` the temporary mapping, which is no longer required after the host
    ioctl.

-   Hold the file-page references returned by `mm.MemoryManager.Pin()` until an
    application ioctl is observed freeing the corresponding `OsDescMem`, then
    call `mm.Unpin()`.

### Security Considerations

Since ioctl parameter structs must be copied into the sentry in order to proxy
them, gVisor implicitly restrict the set of application requests to those that
are explicitly implemented. We can impose additional restrictions based on
parameter values in order to further reduce attack surface, although possibly at
the cost of reduced development velocity; introducing new restrictions after
launch is difficult due to the risk of regressing existing users. Intuitively,
limiting the scope of our support to GPU compute should allow us to narrow API
usage to that of the CUDA runtime. [Nvidia GPU driver CVEs are published in
moderately large batches every ~3-4
months](https://www.nvidia.com/en-us/security/), but insufficient information
regarding these CVEs is available for us to determine how many of these
vulnerabilities we could mitigate via parameter filtering.

By default, the driver prevents a `/dev/nvidiactl` FD from using objects created
by other `/dev/nvidiactl` FDs[^cite-rm-validate], providing driver-level
resource isolation between applications. Since we need to track at least a
subset of object allocations for OS-described memory, and possibly for
determining memory caching type, we can optionally track *all* objects and
further constrain ioctls to using valid object handles if driver-level isolation
is believed inadequate.

While `seccomp-bpf` filters allow us to limit the set of ioctl requests that the
sentry can make, they cannot filter based on ioctl parameters passed via memory
such as allocation `hClass`, `NV_ESC_RM_CONTROL` command, or
`NV_ESC_RM_VID_HEAP_CONTROL` function, limiting the extent to which they can
protect the host from a compromised sentry.

### `runsc` Container Configuration

The
[Nvidia Container Toolkit](https://github.com/NVIDIA/nvidia-container-toolkit)
contains code to configure an unstarted container based on
[the GPU support requested by its OCI runtime spec](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/user-guide.html#environment-variables-oci-spec),
[invoking `nvidia-container-cli` from `libnvidia-container` (described above) to
do most of the actual
work](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/arch-overview.html).
It is used ubiquitously for this purpose, including by the
[Nvidia device plugin for Kubernetes](https://github.com/NVIDIA/k8s-device-plugin).

The simplest way for `runsc` to obtain Nvidia Container Toolkit's behavior is
obviously to use it, either by invoking `nvidia-container-runtime-hook` or by
using the Toolkit's code (which is written in Go) directly. However, filesystem
modifications made to the container's `/dev` and `/proc` directories on the host
will not be application-visible since `runsc` necessarily injects sentry
`devtmpfs` and `procfs` mounts at these locations, requiring that `runsc`
internally replicate the effects of `libnvidia-container` in these directories.
Note that host filesystem modifications are still necessary, since the sentry
itself needs access to relevant host device files and MIG capabilities.

Conversely, we can attempt to emulate the behavior of `nvidia-container-toolkit`
and `libnvidia-container` within `runsc`; however, note that
`libnvidia-container` executes `ldconfig` to regenerate the container's runtime
linker cache after mounting the driver's shared libraries into the
container[^cite-nvc-ldcache_update], which is more difficult if said mounts
exist within the sentry's VFS rather than on the host.

### Proprietary Driver Differences

When running on the proprietary kernel driver, applications invoke
`ioctl(NV_ESC_RM_CONTROL)` commands that do not appear to exist in the OSS
driver. The OSS driver lacks support for GPU virtualization[^cite-oss-vgpu];
however, Google Compute Engine (GCE) GPUs are exposed to VMs in passthrough
mode[^cite-oss-gce], and Container-Optimized OS (COS) switched to the OSS driver
in Milestone 105[^cite-oss-cos], suggesting that OSS-driver-only support may be
sufficient. If support for the proprietary driver is required, we can request
documentation from Nvidia.

### API/ABI Stability

Nvidia requires that the kernel and userspace components of the driver match
versions[^cite-abi-readme], and does not guarantee kernel ABI
stability[^cite-abi-discuss], so we may need to support multiple ABI versions in
the proxy. It is not immediately clear if this will be a problem in practice.

## Proposed Work

To simplify the initial implementation, we will focus immediate efforts on
process-based platforms and defer support for KVM-based platforms to future
work.

In the sentry:

-   Add structure and constant definitions from the Nvidia open-source kernel
    driver to new package `//pkg/abi/nvidia`.

-   Implement the proxy driver under `//pkg/sentry/devices/nvproxy`, initially
    comprising `FileDescriptionImpl` implementations proxying `/dev/nvidiactl`,
    `/dev/nvidia#`, and `/dev/nvidia-uvm`.

-   `/proc/driver/nvidia/params` can probably be (optionally) read once during
    startup and implemented as a static file in the sentry.

Each ioctl command and object class is associated with its own parameters type
and logic; thus, each needs to be implemented individually. We can generate
lists of required commands/classes by running representative applications under
[`cuda_ioctl_sniffer`](https://github.com/geohot/cuda_ioctl_sniffer) on a
variety of GPUs; a list derived from a minimal CUDA workload run on a single VM
follows below. The proxy driver itself should also log unimplemented
commands/classes for iterative development. For the most part, known-required
commands/classes should be implementable incrementally and in parallel.

Concurrently, at the API level, i.e. within `//runsc`:

-   Add an option to enable Nvidia GPU support. When this option is enabled, and
    `runsc` detects that GPU support is requested by the container, it enables
    the proxy driver (by calling `nvproxy.Register(vfsObj)`) and configures the
    container consistently with `nvidia-container-toolkit` and
    `libnvidia-container`.

    Since setting the wrong caching behavior for device memory mappings will
    fail in unpredictable ways, `runsc` must ensure that GPU support cannot be
    enabled when an unsupported platform is selected.

To support Nvidia Multi-Process Service (MPS), we need:

-   Support for `SCM_CREDENTIALS` on host Unix domain sockets; already
    implemented as part of previous MPS investigation, but not merged.

-   Optional pass-through of `statfs::f_type` through `fsimpl/gofer`; needed for
    a runsc bind mount of the host's `/dev/shm`, through which MPS shares
    memory; previously hacked in (optionality not implemented).

Features required to support Nvidia Persistence Daemon and Nvidia Fabric Manager
are currently unknown, but these are not believed to be critical, and we may
choose to deliberately deny access to them (and/or MPS) to reduce attack
surface.
[MPS provides "memory protection" but not "error isolation"](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/#cuda-concurrency),
so it is not clear that granting MPS access to sandboxed containers is safe.

Implementation notes:

-   Each application `open` of `/dev/nvidictl`, `/dev/nvidia#`, or
    `/dev/nvidia-uvm` must be backed by a distinct host FD. Furthermore, the
    proxy driver cannot go through sentry VFS to obtain this FD since doing so
    would recursively attempt to open the proxy driver. Instead, we must allow
    the proxy driver to invoke host `openat`, and ensure that the mount
    namespace in which the sentry executes contains the required device special
    files.

-   `/dev/nvidia-uvm` FDs may need to be `UVM_INITIALIZE`d with
    `UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE` to be used from both sentry and
    application processes[^cite-uvm-va_space_mm_enabled].

-   Known-used `nvidia.ko` ioctls: `NV_ESC_CHECK_VERSION_STR`,
    `NV_ESC_SYS_PARAMS`, `NV_ESC_CARD_INFO`, `NV_ESC_NUMA_INFO`,
    `NV_ESC_REGISTER_FD`, `NV_ESC_RM_ALLOC`, `NV_ESC_RM_ALLOC_MEMORY`,
    `NV_ESC_RM_ALLOC_OS_EVENT`, `NV_ESC_RM_CONTROL`, `NV_ESC_RM_FREE`,
    `NV_ESC_RM_MAP_MEMORY`, `NV_ESC_RM_VID_HEAP_CONTROL`,
    `NV_ESC_RM_DUP_OBJECT`, `NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO`

-   `NV_ESC_RM_CONTROL` is essentially another level of ioctls. Known-used
    `NVOS54_PARAMETERS::cmd`: `NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION`,
    `NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY`,
    `NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS`,
    `NV0000_CTRL_CMD_GPU_GET_PROBED_IDS`,
    `NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO`,
    `NV0000_CTRL_CMD_GPU_ATTACH_IDS`, `NV0000_CTRL_CMD_GPU_GET_ID_INFO`,
    `NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS`,
    `NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS`,
    `NV2080_CTRL_CMD_GPU_GET_GID_INFO`,
    `NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE`,
    `NV2080_CTRL_CMD_FB_GET_INFO`, `NV2080_CTRL_CMD_GPU_GET_INFO`,
    `NV0080_CTRL_CMD_MC_GET_ARCH_INFO`, `NV2080_CTRL_CMD_BUS_GET_INFO`,
    `NV2080_CTRL_CMD_BUS_GET_PCI_INFO`, `NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO`,
    `NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS`, `NV0080_CTRL_FIFO_GET_CAPS`,
    `NV0080_CTRL_CMD_GPU_GET_CLASSLIST`, `NV2080_CTRL_CMD_GPU_GET_ENGINES`,
    `NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO`,
    `NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE`, `NV2080_CTRL_CMD_GR_GET_INFO`,
    `NV2080_CTRL_CMD_GR_GET_GPC_MASK`, `NV2080_CTRL_CMD_GR_GET_TPC_MASK`,
    `NV2080_CTRL_CMD_GR_GET_CAPS_V2`, `NV2080_CTRL_CMD_CE_GET_CAPS`,
    `NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG`,
    `NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER`, `NV0080_CTRL_CMD_FB_GET_CAPS`,
    `NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE`,
    `NV2080_CTRL_CMD_GSP_GET_FEATURES`,
    `NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING`,
    `NV2080_CTRL_CMD_GPU_GET_NAME_STRING`,
    `NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES`,
    `NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS`,
    `NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG`,
    `NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS`,
    `NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO`, `NV2080_CTRL_CMD_PERF_BOOST`,
    `NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST`, `NVC36F_CTRL_GET_CLASS_ENGINEID`,
    `NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN`,
    `NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE`, `NVA06F_CTRL_CMD_GPFIFO_SCHEDULE`

-   Known-used `NVOS54_PARAMETERS::cmd` that are apparently unimplemented and
    may be proprietary-driver-only (or just well-hidden?): 0x20800159,
    0x20800161, 0x20801001, 0x20801009, 0x2080100a, 0x20802016, 0x20802084,
    0x503c0102, 0x90e60102

-   Known-used `nvidia-uvm.ko` ioctls: `UVM_INITIALIZE`,
    `UVM_PAGEABLE_MEM_ACCESS`, `UVM_REGISTER_GPU`, `UVM_CREATE_RANGE_GROUP`,
    `UVM_REGISTER_GPU_VASPACE`, `UVM_CREATE_EXTERNAL_RANGE`,
    `UVM_MAP_EXTERNAL_ALLOCATION`, `UVM_REGISTER_CHANNEL`,
    `UVM_ALLOC_SEMAPHORE_POOL`, `UVM_VALIDATE_VA_RANGE`

-   Known-used `NV_ESC_RM_ALLOC` `hClass`, i.e. allocated object classes:
    `NV01_ROOT_CLIENT`, `MPS_COMPUTE`, `NV01_DEVICE_0`, `NV20_SUBDEVICE_0`,
    `TURING_USERMODE_A`, `FERMI_VASPACE_A`, `NV50_THIRD_PARTY_P2P`,
    `FERMI_CONTEXT_SHARE_A`, `TURING_CHANNEL_GPFIFO_A`, `TURING_COMPUTE_A`,
    `TURING_DMA_COPY_A`, `NV01_EVENT_OS_EVENT`, `KEPLER_CHANNEL_GROUP_A`

## References

[^cite-abi-discuss]: "[The] RMAPI currently does not have any ABI stability
    guarantees whatsoever, and even API compatibility breaks
    occasionally." -
    https://github.com/NVIDIA/open-gpu-kernel-modules/discussions/157#discussioncomment-2757388
[^cite-abi-readme]: "This is the source release of the NVIDIA Linux open GPU
    kernel modules, version 530.41.03. ... Note that the kernel
    modules built here must be used with GSP firmware and
    user-space NVIDIA GPU driver components from a corresponding
    530.41.03 driver release." -
    https://github.com/NVIDIA/open-gpu-kernel-modules/blob/6dd092ddb7c165fb1ec48b937fa6b33daa37f9c1/README.md
[^cite-nvc-ldcache_update]: [`src/nvc_ldcache.c:nvc_ldcache_update()`](https://github.com/NVIDIA/libnvidia-container/blob/eb0415c458c5e5d97cb8ac08b42803d075ed73cd/src/nvc_ldcache.c#L355)
[^cite-osdesc-rmapi]: [`src/nvidia/arch/nvalloc/unix/src/escape.c:RmCreateOsDescriptor()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/4397463e738d2d90aa1164cc5948e723701f7b53/src/nvidia/arch/nvalloc/unix/src/escape.c#L120)
    =>
    [`kernel-open/nvidia/os-mlock.c:os_lock_user_pages()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/758b4ee8189c5198504cb1c3c5bc29027a9118a3/kernel-open/nvidia/os-mlock.c#L214)
[^cite-oss-cos]: "Upgraded Nvidia latest drivers from v510.108.03 to v525.60.13
    (OSS)." -
    https://cloud.google.com/container-optimized-os/docs/release-notes/m105#cos-beta-105-17412-1-2_vs_milestone_101_.
    Also see b/235364591, go/cos-oss-gpu.
[^cite-oss-gce]: "Compute Engine provides NVIDIA GPUs for your VMs in
    passthrough mode so that your VMs have direct control over the
    GPUs and their associated memory." -
    https://cloud.google.com/compute/docs/gpus
[^cite-oss-vgpu]: "The currently published driver does not support
    virtualization, neither as a host nor a guest." -
    https://github.com/NVIDIA/open-gpu-kernel-modules/discussions/157#discussioncomment-2752052
[^cite-pytorch-uvm]: [`c10/cuda/CUDADeviceAssertionHost.cpp:c10::cuda::CUDAKernelLaunchRegistry::get_uvm_assertions_ptr_for_current_device()`](https://github.com/pytorch/pytorch/blob/3f5d768b561e3edd17e93fd4daa7248f9d600bb2/c10/cuda/CUDADeviceAssertionHost.cpp#L268)
[^cite-rm-validate]: See calls to `clientValidate()` in
    [`src/nvidia/src/libraries/resserv/src/rs_server.c`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/6dd092ddb7c165fb1ec48b937fa6b33daa37f9c1/src/nvidia/src/libraries/resserv/src/rs_server.c)
    =>
    [`src/nvidia/src/kernel/rmapi/client.c:rmclientValidate_IMPL()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/4397463e738d2d90aa1164cc5948e723701f7b53/src/nvidia/src/kernel/rmapi/client.c#L728).
    `API_SECURITY_INFO::clientOSInfo` is set by
    [`src/nvidia/arch/nvalloc/unix/src/escape.c:RmIoctl()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/4397463e738d2d90aa1164cc5948e723701f7b53/src/nvidia/arch/nvalloc/unix/src/escape.c#L300).
    Both `PDB_PROP_SYS_VALIDATE_CLIENT_HANDLE` and
    `PDB_PROP_SYS_VALIDATE_CLIENT_HANDLE_STRICT` are enabled by
    default by
    [`src/nvidia/generated/g_system_nvoc.c:__nvoc_init_dataField_OBJSYS()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/4397463e738d2d90aa1164cc5948e723701f7b53/src/nvidia/generated/g_system_nvoc.c#L84).
[^cite-sdm-pat]: Intel SDM Vol. 3, Sec. 12.12 "Page Attribute Table (PAT)"
[^cite-uvm-mmap]: [`kernel-open/nvidia-uvm/uvm.c:uvm_mmap()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/758b4ee8189c5198504cb1c3c5bc29027a9118a3/kernel-open/nvidia-uvm/uvm.c#L557)
[^cite-uvm-va_space_mm_enabled]: [`kernel-open/nvidia-uvm/uvm_va_space_mm.c:uvm_va_space_mm_enabled()`](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/758b4ee8189c5198504cb1c3c5bc29027a9118a3/kernel-open/nvidia-uvm/uvm_va_space_mm.c#L188)
