# GPU Support

[TOC]

gVisor adds a layer of security to your AI/ML applications or other CUDA
workloads while adding negligible overhead. By running these applications in a
sandboxed environment, you can isolate your host system from potential
vulnerabilities in AI code. This is crucial for handling sensitive data or
deploying untrusted AI workloads.

gVisor supports running most CUDA applications on preselected versions of
[NVIDIA's open source driver](https://github.com/NVIDIA/open-gpu-kernel-modules).
To achieve this, gVisor implements a proxy driver inside the sandbox, henceforth
referred to as `nvproxy`. `nvproxy` proxies the application's interactions with
NVIDIA's driver on the host. It provides access to NVIDIA GPU-specific devices
to the sandboxed application. The CUDA application can run unmodified inside the
sandbox and interact transparently with these devices.

<!-- TODO(b/316211943): Add section on security properties of nvproxy. -->

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
and then run CUDA containers with `nvidia-container-runtime`.

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
gVisor undergoes continuous tests to ensure this functionality remains robust.
[Real-world usage](https://github.com/google/gvisor/issues?q=is%3Aissue+label%3A%22area%3A+gpu%22+)
of gVisor across different CUDA workloads helps discover and address potential
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
3.  Supports selected NVIDIA device files.
4.  Supports selected `ioctl`s on each device file.

### Supported GPUs {#gpu-models}

gVisor currently supports NVIDIA GPUs: T4, L4, A100, A10G and H100. Please
[open a GitHub issue](https://github.com/google/gvisor/issues/new?labels=type%3A+enhancement,area%3A+gpu&template=bug_report.yml)
if you want support for another GPU model.

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
generated by running a large number of CUDA workloads in gVisor. As `nvproxy` is
adapted to more use cases, this set will continue to evolve.

Currently, `nvproxy` focuses on supporting compute workloads (like CUDA).
Graphics and video capabilities are not yet supported due to missing `ioctl`s.
If your GPU compute workload fails with gVisor, please note that some `ioctl`
commands might still be unimplemented. Please
[open a GitHub issue](https://github.com/google/gvisor/issues/new?labels=type%3A+bug,area%3A+gpu&template=bug_report.yml)
to describe about your use case. If a missing `ioctl` implementation is the
problem, then the [debug logs](/docs/user_guide/debugging/) will contain
warnings with prefix `nvproxy: unknown *`.
