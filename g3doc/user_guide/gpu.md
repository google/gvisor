# GPU Support

[TOC]

gVisor adds a layer of security to your AI/ML applications or other GPU
workloads while adding negligible overhead. By running these applications in a
sandboxed environment, you can isolate your host system from potential
vulnerabilities in AI code. This is crucial for handling sensitive data or
deploying untrusted AI workloads.

gVisor supports running most CUDA applications on preselected versions of
[NVIDIA's open source driver](https://github.com/NVIDIA/open-gpu-kernel-modules).
To achieve this, gVisor implements a proxy driver inside the sandbox, henceforth
referred to as `nvproxy`. `nvproxy` proxies the application's interactions with
NVIDIA's driver on the host. It provides access to NVIDIA GPU-specific devices
to the sandboxed application. The GPU application can run unmodified inside the
sandbox and interact transparently with these devices.

## Environments

The `runsc` flag `--nvproxy` must be specified to enable GPU support. gVisor
supports GPUs in the following environments.

### NVIDIA Container Runtime

The
[`nvidia-container-runtime`](https://github.com/NVIDIA/nvidia-container-toolkit/tree/main/cmd/nvidia-container-runtime)
is packaged as part of the
[NVIDIA GPU Container Stack](https://github.com/NVIDIA/nvidia-container-toolkit).
This runtime is just a shim and delegates all commands to the configured low
level runtime (which defaults to `runc`). To use gVisor, specify `runsc` as the
low level runtime in `/etc/nvidia-container-runtime/config.toml`
[via the `runtimes` option](https://github.com/NVIDIA/nvidia-container-toolkit/tree/main/cmd/nvidia-container-runtime#low-level-runtime-path)
and then run GPU containers with `nvidia-container-runtime`. The `runtimes`
option allows to specify an executable path or executable name that is
searchable in `$PATH`. To specify `runsc` with specific flags, the following
executable can be used:

```
# !/bin/bash

exec /path/to/runsc --nvproxy <other runsc flags> "$@"
```

NOTE: gVisor currently only supports
[legacy mode](https://github.com/NVIDIA/nvidia-container-toolkit/tree/main/cmd/nvidia-container-runtime#legacy-mode).
The alternative,
[csv mode](https://github.com/NVIDIA/nvidia-container-toolkit/tree/main/cmd/nvidia-container-runtime#csv-mode),
is not yet supported.

### Docker

The "legacy" mode of `nvidia-container-runtime` is directly compatible with the
`--gpus` flag implemented by the docker CLI. So with Docker, `runsc` can be used
directly (without having to go through `nvidia-container-runtime`).

```
$ docker run --runtime=runsc --gpus=all --rm -it nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda11.7.1-ubi8
[Vector addition of 50000 elements]
Copy input data from the host memory to the CUDA device
CUDA kernel launch with 196 blocks of 256 threads
Copy output data from the CUDA device to the host memory
Test PASSED
Done
```

### GKE Device Plugin

[GKE](https://cloud.google.com/kubernetes-engine) uses a different GPU container
stack than NVIDIA's. GKE has
[its own device plugin](https://github.com/GoogleCloudPlatform/container-engine-accelerators/tree/master/cmd/nvidia_gpu)
(which is different from
[`k8s-device-plugin`](https://github.com/NVIDIA/k8s-device-plugin)). GKE's
plugin modifies the container spec in a different way than the above-mentioned
methods.

NOTE: `nvproxy` does not have integration support for `k8s-device-plugin` yet.
So k8s environments other than GKE might not be supported.

## Compatibility

gVisor supports a wide range of CUDA workloads, including PyTorch and various
generative models like LLMs. Check out
[this blog post about running Stable Diffusion with gVisor](/blog/2023/06/20/gpu-pytorch-stable-diffusion/).
gVisor also supports Vulkan and NVENC/NVDEC workloads. gVisor undergoes
continuous tests to ensure this functionality remains robust.
[Real-world usage](https://github.com/google/gvisor/issues?q=is%3Aissue+label%3A%22area%3A+gpu%22+)
of gVisor across different GPU workloads helps discover and address potential
compatibility or performance issues in `nvproxy`.

`nvproxy` is a passthrough driver that forwards `ioctl(2)` calls made to NVIDIA
devices by the containerized application directly to the host NVIDIA driver.
This forwarding is straightforward: `ioctl` parameters are copied from the
application's address space to the sentry's address space, and then a host
`ioctl` syscall is made. `ioctl`s are passed through with minimal intervention;
`nvproxy` does not emulate NVIDIA kernel-mode driver (KMD) logic. This design
translates to minimal overhead for GPU operations, ensuring that GPU bound
workloads experience negligible performance impact.

However, the presence of pointers and file descriptors within some `ioctl`
structs forces `nvproxy` to perform appropriate translations. This requires
`nvproxy` to be aware of the KMD's ABI, specifically the layout of `ioctl`
structs. The challenge is compounded by the lack of ABI stability guarantees in
NVIDIA's KMD, meaning `ioctl` definitions can change arbitrarily between
releases. While the NVIDIA installer ensures matching KMD and user-mode driver
(UMD) component versions, a single gVisor version might be used with multiple
NVIDIA drivers. As a result, `nvproxy` must understand the ABI for each
supported driver version, necessitating internal versioning logic for `ioctl`s.

As a result, `nvproxy` has the following limitations:

1.  Supports selected GPU models.
2.  Supports selected NVIDIA driver versions.
3.  Supports selected NVIDIA driver capabilities.
4.  Supports selected NVIDIA device files.
5.  Supports selected `ioctl`s on each device file.
6.  Supports selected platforms.

### Supported GPUs {#gpu-models}

gVisor currently supports NVIDIA GPUs:

*   **T4**, based on the
    [Turing microarchitecture](https://en.wikipedia.org/wiki/Turing_\(microarchitecture\))
*   **A100** and **A10G**, based on the
    [Ampere microarchitecture](https://en.wikipedia.org/wiki/Ampere_\(microarchitecture\))
*   **L4**, based on the
    [Ada Lovelace microarchitecture](https://en.wikipedia.org/wiki/Ada_Lovelace_\(microarchitecture\))
*   **H100**, based on the
    [Hopper microarchitecture](https://en.wikipedia.org/wiki/Hopper_\(microarchitecture\))

While not officially supported, other NVIDIA GPUs based on the same
microarchitectures as the above will likely work as well. This includes
consumer-oriented GPUs such as **RTX 3090** (Ampere) and **RTX 4090** (Ada
Lovelace).

Therefore, if you encounter an incompatible workload on a GPU on one of the
above microarchitectures, even if on an unsupported GPU, chances are that this
workload is also incompatible in the same manner on one of the officially
supported GPUs. Please
[open a GitHub issue](https://github.com/google/gvisor/issues/new?labels=type%3A+enhancement,area%3A+gpu&template=bug_report.yml)
with reproduction instructions so that it can be tested against an officially
supported GPU.

### Rolling Version Support Window {#driver-versions}

The range of driver versions supported by `nvproxy` directly aligns with those
available within GKE. As GKE incorporates newer drivers, `nvproxy` will extend
support accordingly. Conversely, to manage versioning complexity, `nvproxy` will
drop support for drivers removed from GKE. This strategy ensures a streamlined
process and avoids unbounded growth in `nvproxy`'s versioning.

To see what drivers a given `runsc` version supports, run:

```
$ runsc nvproxy list-supported-drivers
```

**NOTE**: `runsc`'s driver version is a strict version match because `runsc`
cannot assume ABI compatibility between driver versions. You may force `runsc`
to use a given supported ABI version with the `--nvproxy-driver-version` even
when running on a host that has an unsupported driver version. However, doing so
is **not officially supported**, and running old drivers is generally not secure
as many driver updates address security bugs. Bug reports with the
`--nvproxy-driver-version` flag set will be treated as invalid.

### Supported Driver Capabilities {#driver-capabilities}

The `NVIDIA_DRIVER_CAPABILITIES` environment variable defined in the container
spec controls which driver libraries/binaries will be mounted inside the
container. Different GPU workloads may have varying requirements. For instance,
Vulkan requires `graphics` capability, CUDA requires `compute`, while
NVENC/NVDEC requires `video`.

`nvproxy` supports the following driver capabilities: `compute`, `utility`,
`graphics` and `video`. By default, `nvproxy` only allows `compute` and
`utility`. If additional capabilities are required, then please set runsc flag
`--nvproxy-allowed-driver-capabilities` with a comma-separated list of
capabilities to allow. Allowing additional capabilities broadens the host driver
surface exposed to the sandbox, so provision this flag conservatively. Passing
"all" will allow all supported capabilities. If `NVIDIA_DRIVER_CAPABILITIES=all`
then all allowed capabilities will be used.

### Supported Device Files {#device-files}

gVisor only exposes `/dev/nvidiactl`, `/dev/nvidia-uvm` and `/dev/nvidia#`.

Some unsupported NVIDIA device files are:

-   `/dev/nvidia-caps/*`: Controls `nvidia-capabilities`, which is mainly used
    by Multi-instance GPUs (MIGs).
-   `/dev/nvidia-drm`: Plugs into Linux's Direct Rendering Manager (DRM)
    subsystem.
-   `/dev/nvidia-modeset`: Enables `DRIVER_MODESET` capability in `nvidia-drm`
    devices.

### Supported `ioctl` Set {#ioctls}

To minimize maintenance overhead across supported driver versions, the set of
supported NVIDIA device `ioctl`s is intentionally limited. This set was
generated by running a large number of GPU workloads in gVisor. As `nvproxy` is
adapted to more use cases, this set will continue to evolve.

Currently, `nvproxy` focuses on supporting compute, graphics and video workloads
(like CUDA, Vulkan and NVENC/NVDEC). If your GPU compute workload fails with
gVisor, it might be because some `ioctl` commands are still be unimplemented.
Please
[open a GitHub issue](https://github.com/google/gvisor/issues/new?labels=type%3A+bug,area%3A+gpu&template=bug_report.yml)
to describe about your use case. If a missing `ioctl` implementation is the
problem, then the [debug logs](/docs/user_guide/debugging/) will contain
warnings with prefix `nvproxy: handler is undefined *`. See below on how to run
the `ioctl_sniffer` tool.

### Supported Platforms {#platforms}

All nvproxy functionality is supported on systrap and ptrace platforms.
[cudaMallocManaged() is currently flaky on the KVM platform due to limitations
regarding virtual memory layout](https://github.com/google/gvisor/issues/11436);
all other nvproxy functionality is supported on the KVM platform.

### Debugging

There are a few methods to try when debugging GPU workloads. The first step to
try should be gVisor's
[ioctl_sniffer](https://github.com/google/gvisor/tree/master/tools/ioctl_sniffer)
tool; if your GPU workload fails due to unimplemented `ioctl` commands in
gVisor, this tool will provide a list of the specific ones.

Occasionally, you may also need to dig into the Nvidia GPU Driver itself. To do
so, you can install the OSS Driver repo and checkout the appropriate driver
version.

```bash
DRIVER_VERSION=550.54.15
git clone https://github.com/NVIDIA/open-gpu-kernel-modules.git
cd open-gpu-kernel-modules
git checkout tags/$DRIVER_VERSION
```

For `printk()` debugging, it is advised to use `portDbgPrintf()`. See more
discussion
[here](https://github.com/NVIDIA/open-gpu-kernel-modules/discussions/347). You
should be able to see the prints via `dmesg(1)`.

Then uninstall the existing Nvidia driver, build kernel module from local source
files and reinstall it.

```bash
sudo /usr/bin/nvidia-uninstall
make modules -j$(nproc)
sudo make modules_install -j$(nproc)
sudo insmod kernel-open/nvidia.ko
sudo insmod kernel-open/nvidia-uvm.ko
sudo insmod kernel-open/nvidia-drm.ko
sudo insmod kernel-open/nvidia-modeset.ko

# Install the user-space NVIDIA GPU driver components using the .run file.
sudo sh NVIDIA-Linux-x86_64-$DRIVER_VERSION.run --no-kernel-modules
```

### Host Configurations

<!---
TODO(b/324257702): Remove this section once this is fixed.
-->

When downloading large models within gVisor, you might encounter application
segmentation faults due to host VMA exhaustion. To workaround this, you can set
the value of `/proc/sys/vm/max_map_count` to a large number.

```bash
echo 1000000 | sudo tee /proc/sys/vm/max_map_count
```

Alternatively, you can also just pass the runsc flag `--host-settings=enforce`.

## Security

While GPU support enables important use cases for gVisor, it is important for
users to understand the security model around the use of GPUs in sandboxes. In
short, while gVisor will protect the host from the sandboxed application,
**NVIDIA driver updates must be part of any security plan with or without
gVisor**.

First, a short discussion on
[gvisor's security model](../architecture_guide/security.md). gVisor protects
the host from sandboxed applications by providing several layers of defense. The
layers most relevant to this discussion are the redirection of application
syscalls to the gVisor sandbox and use of
[seccomp-bpf](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html)
on gVisor sandboxes.

gVisor uses a "platform" to tell the host kernel to reroute system calls to the
sandbox process, known as the sentry. The sentry implements a syscall table,
which services all application syscalls. The Sentry *may* make syscalls to the
host kernel if it needs them to fulfill the application syscall, but it doesn't
merely pass an application syscall to the host kernel.

On sandbox boot, seccomp filters are applied to the sandbox. Seccomp filters
applied to the sandbox constrain the set of syscalls that it can make to the
host kernel, blocking access to most host kernel vulnerabilities even if the
sandbox becomes compromised.

For example, [CVE-2022-0185](https://nvd.nist.gov/vuln/detail/CVE-2022-0185) is
mitigated because gVisor itself handles the syscalls required to use namespaces
and capabilities, so the application is using gVisor's implementation, not the
host kernel's. For a compromised sandbox, the syscalls required to exploit the
vulnerability are blocked by seccomp filters.

In addition, seccomp-bpf filters can filter by argument names allowing us to
allowlist granularly by `ioctl(2)` arguments. `ioctl(2)` is a source of many
bugs in any kernel due to the complexity of its implementation. As of writing,
gVisor does
[allowlist some `ioctl`s](https://github.com/google/gvisor/blob/ccc3c2cbd26d3514885bd665b0a110150a6e8c53/runsc/boot/filter/config/config_main.go#L111)
by argument for things like terminal support.

For example, [CVE-2024-21626](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)
is mitigated by gVisor because the application would use gVisor's implementation
of `ioctl(2)`. For a compromised sentry, `ioctl(2)` calls with the needed
arguments are not in the seccomp filter allowlist, blocking the attacker from
making the call. gVisor also mitigates similar vulnerabilities that come with
device drivers
([CVE-2023-33107](https://nvd.nist.gov/vuln/detail/CVE-2023-33107)).

### nvproxy Security

Recall that "nvproxy" allows applications to directly interact with supported
ioctls defined in the NVIDIA driver.

gVisor's seccomp filter rules are modified such that `ioctl(2)` calls can be
made
[*only for supported ioctls*](https://github.com/google/gvisor/blob/be9169a6ce095a08b99940a97db3f58e5c5bd2ce/pkg/sentry/devices/nvproxy/seccomp_filters.go#L1).
The allowlisted rules aligned with each
[driver version](https://github.com/google/gvisor/blob/c087777e37a186e38206209c41178e92ef1bbe81/pkg/sentry/devices/nvproxy/version.go#L152).
This approach is similar to the allowlisted ioctls for terminal support
described above. This allows gVisor to retain the vast majority of its
protection for the host while allowing access to GPUs. All of the above CVEs
remain mitigated even when "nvproxy" is used.

However, gVisor is much less effective at mitigating vulnerabilities within the
NVIDIA GPU drivers themselves, *because* gVisor passes through calls to be
handled by the kernel module. If there is a vulnerability in a given driver for
a given GPU `ioctl` (read feature) that gVisor passes through, then gVisor will
also be vulnerable. If the vulnerability is in an unimplemented feature, gVisor
will block the required calls with seccomp filters.

In addition, gVisor doesn't introduce any additional hardware-level isolation
beyond that which is configured by by the NVIDIA kernel-mode driver. There is no
validation of things like DMA buffers. The only checks are done in seccomp-bpf
rules to ensure `ioctl(2)` calls are made on supported and allowlisted `ioctl`s.

Therefore, **it is imperative that users update NVIDIA drivers in a timely
manner with or without gVisor**. To see the latest drivers gVisor supports, you
can run the following with your runsc release:

```
$ runsc nvproxy list-supported-drivers
```

Alternatively you can view the
[source code](https://github.com/google/gvisor/blob/be9169a6ce095a08b99940a97db3f58e5c5bd2ce/pkg/sentry/devices/nvproxy/version.go#L1)
or download it and run:

```
$ make run TARGETS=runsc:runsc ARGS="nvproxy list-supported-drivers"
```

### So, if you don't protect against all the things, why even?

While gVisor doesn't protect against *all* NVIDIA driver vulnerabilities, it
*does* protect against a large set of general vulnerabilities in Linux.
Applications don't just use GPUs, they use them as a part of a larger
application that may include third party libraries. For example, Tensorflow
[suffers from the same kind of vulnerabilities](https://nvd.nist.gov/vuln/detail/CVE-2022-29216)
that every application does. Designing and implementing an application with
security in mind is hard and in the emerging AI space, security is often
overlooked in favor of getting to market fast. There are also many services that
allow users to run external users' code on the vendor's infrastructure. gVisor
is well suited as part of a larger security plan for these and other use cases.
