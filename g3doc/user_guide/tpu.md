# TPU Support

[TOC]

gVisor can add a layer of security to your TPU-based applications. By running
these applications in a sandboxed environment, you can isolate your host system
from potential vulnerabilities in code. This is crucial for handling sensitive
data or deploying untrusted workloads.

gVisor supports running workloads that leverage TPU accelerators by proxying
hardware driver commands to the host with a feature called `tpuproxy`.
`tpuproxy` exposes host TPU devices to the sandbox so users can run their TPU
applications without any modifications.

## Enabling

The `runsc` flag `--tpuproxy` must be specified to enable TPU support. In GKE
this is done automatically for any sandbox node using a supported TPU machine
type.

## Compatibility

gVisor supports a wide range of workloads, including PyTorch and various
generative models like LLMs. Check out
[this blog post about running Stable Diffusion with gVisor](/blog/2023/06/20/gpu-pytorch-stable-diffusion/).
gVisor undergoes continuous tests to ensure this functionality remains robust.

`tpuproxy` is a passthrough driver that forwards `ioctl(2)` calls made to TPU
devices by the containerized application directly to the host TPU driver. This
forwarding is straightforward: `ioctl` parameters are copied from the
application's address space to the sentry's address space, and then a host
`ioctl` syscall is made. `ioctl`s are passed through with minimal intervention.
`tpuproxy` also sets up a proxy sysfs filesystem that enables reading
configuration and status information of TPU devices on the host PCI bus. This
design translates to minimal overhead and maximal compatibility for TPU
operations, ensuring that TPU bound workloads experience negligible performance
impact.

### Supported TPUs {#tpu-models}

gVisor currently supports TPU models: V4, V4lite, V4pod, V5e, V5p, V6e, and V6p.
[open a GitHub issue](https://github.com/google/gvisor/issues/new?labels=type%3A+enhancement,area%3A+gpu&template=bug_report.yml)
if you want support for another TPU model. gVisor only supports "1VM" TPU
shapes.

### Supported Device Files {#device-files}

gVisor exposes `/dev/accel[0-9]+` for TPU V4 and below. For TPU V5 and beyond,
gVisor exposes `/dev/vfio` and `/dev/vfio/[0-9]+`. For all versions, `tpuproxy`
exposes a read-only copy of the contents of TPU PCI device files located in the
host's sysfs directory.

## Security

Although `tpuproxy` enables sandboxed applications to run TPU accelerated
workloads, it does not provide the same level of isolation from host hardware
that it does for traditional CPU workloads. At a high level this is because
gVisor emulates the Linux kernel, which itself has limited control over the
memory isolation and compute scheduling of external devices. A more detailed
discussion follows:

First, a short overview of
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

### tpuproxy Security

Recall that `tpuproxy` allows applications to directly interact with supported
ioctls used by the TPU driver.

gVisor's seccomp filter rules are modified such that `ioctl(2)` calls can be
made
[*only for supported ioctls*](https://github.com/google/gvisor/blob/be9169a6ce095a08b99940a97db3f58e5c5bd2ce/pkg/sentry/devices/accel/seccomp_filters.go).
This approach is similar to the allowlisted ioctls for terminal support
described above. This allows gVisor to retain the vast majority of its
protection for the host while allowing access to TPUs. All of the above CVEs
remain mitigated even when `tpuproxy` is used.

However, gVisor is much less effective at mitigating vulnerabilities within the
TPU drivers themselves, *because* gVisor passes through calls to be handled by
the kernel driver. If there is a vulnerability in the TPU driver for a given
`ioctl` that gVisor passes through, then gVisor will also be vulnerable.

In addition, gVisor doesn't introduce any additional hardware-level isolation
beyond that which is configured by the host. There is no validation of things
like DMA buffers. The only checks are done in seccomp-bpf rules to ensure
`ioctl(2)` calls are made on supported and allowlisted `ioctl`s.

NOTE: TPU V5 and beyond uses the
[VFIO Linux interface](https://docs.kernel.org/driver-api/vfio.html) to drive
TPU hardware. Theoretically VFIO could be used to configure memory isolation
using the host IOMMU. However, this requires manual setup by the user
application and does not come configured out of the box by gVisor.

### So, if you don't protect against all the things, why even?

While gVisor doesn't protect against *all* TPU driver vulnerabilities, it *does*
protect against a large set of general vulnerabilities in Linux. Applications
don't just use TPUs, they use them as a part of a larger application that may
include third party libraries. For example, Tensorflow
[suffers from the same kind of vulnerabilities](https://nvd.nist.gov/vuln/detail/CVE-2022-29216)
that every application does. Designing and implementing an application with
security in mind is hard and in the emerging AI space, security is often
overlooked in favor of getting to market fast. There are also many services that
allow users to run external users' code on the vendor's infrastructure. gVisor
is well suited as part of a larger security plan for these and other use cases.
