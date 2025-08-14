# Applications

[TOC]

gVisor implements a large portion of the Linux surface and while we strive to
make it broadly compatible, there are (and always will be) unimplemented
features and bugs. The only real way to know if it will work is to try. If you
find a container that doesn’t work and there is no known issue, please
[file a bug][bug] indicating the full command you used to run the image. You can
view open issues related to compatibility [here][issues].

If you're able to provide the [debug logs](../debugging/), the problem likely to
be fixed much faster.

## What works?

gVisor is widely used as a container runtime supporting arbitrary user-provided
workloads in Cloud products such as
[DigitalOcean's App Platform](https://docs.digitalocean.com/products/app-platform/)
or [Google's Cloud Run](https://cloud.google.com/run/). See the [Users](/users)
page for more. The decision to use gVisor for these products means that
compatibility issues are not a common problem for most workloads in practice.

While gVisor only implements a subset of the Linux syscall ABI, the
unimplemented part of the ABI is mostly comprised of alternatives to existing
syscalls that gVisor does support. For example, gVisor does not fully support
`io_uring`-related syscalls (as seen below), but does support other I/O-related
syscalls. In practice, most language runtimes and libraries that do I/O will
automatically probe and determine which syscall variant for I/O they can use, so
they will effectively work in gVisor even if they would use `io_uring` when
running on Linux. For this reason, looking through the
[list of supported syscalls](linux/amd64) is not necessarily a good measure of
how widely compatible gVisor is in practice.

gVisor releases go through the regression tests of popular language runtimes
(Python, Java, Node.js, PHP, Go) to ensure continued compatibility with the base
libraries of these languages. This means most programs written in these
languages will work.

## What **doesn't** work?

While gVisor aims to support a wide variety of workloads and to achieve
near-parity with Linux, it will never be perfect. Notably:

-   There are known gaps in the implementations of some kernel subsystems:
    -   While in-sandbox cgroups (CPU, memory) exist and can be used for
        resource *accounting*, resource *limits* are not enforced within the
        sandbox. It is possible to restrict a sandbox's resources by placing
        gVisor in a Linux-native host cgroup, however gVisor cannot currently
        enforce resource limits between competing processes within the *same*
        sandbox.
    -   Block device filesystems like `fat32`, `ext3`, `ext4` are not natively
        supported inside the gVisor kernel. As such, it is not possible to mount
        block devices from within the sandbox. It is however possible to mount
        such devices on a host Linux machine, and expose the mounted filesystem
        to the sandbox.
    -   `iptables` are only partially supported. The general goal is to support
        the featureset necessary to be able to run
        [Docker in gVisor](../../tutorials/docker-in-gvisor/), but not
        necessarily further.
    -   Device files for custom hardware is generally not supported, with the
        notable exceptions of [NVIDIA GPUs](../gpu/) and [TPU devices](../tpu/).
        Patches are welcome to expand this to other hardware devices as
        necessary.
    -   `io_uring` is disabled by default. When enabled, its implementation is
        limited to basic I/O operations. Similar for `nftables` rules support.
    -   Usage of KVM from *within* the sandbox is not supported. Note that this
        limitation is not related to whether gVisor itself uses the
        [KVM platform](../platforms/). In addition, gVisor works well when
        running within a KVM-based virtual machine.
-   There exist known feature gaps when gVisor is integrated as a container
    runtime within a Kubernetes cluster. Refer to the
    [GKE Sandbox incompatible features list](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods#limitations-incompatible).

<!-- mdformat on -->

[bug]: https://github.com/google/gvisor/issues/new?title=Compatibility%20Issue:
[issues]: https://github.com/google/gvisor/issues?q=is%3Aissue+is%3Aopen+label%3A%22area%3A+compatibility%22
