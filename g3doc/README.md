# What is gVisor?

gVisor is a user-space kernel, written in Go, that implements a substantial
portion of the [Linux system call interface][linux]. It provides an additional
layer of isolation between running applications and the host operating system.

gVisor includes an [Open Container Initiative (OCI)][oci] runtime called `runsc`
that makes it easy to work with existing container tooling. The `runsc` runtime
integrates with Docker and Kubernetes, making it simple to run sandboxed
containers.

gVisor takes a distinct approach to container sandboxing and makes a different
set of technical trade-offs compared to existing sandbox technologies, thus
providing new tools and ideas for the container security landscape.

gVisor can be used with Docker, Kubernetes, or directly using `runsc`. Use the
links below to see detailed instructions for each of them:

*   [Docker](./user_guide/quick_start/docker/): The quickest and easiest way to
    get started.
*   [Kubernetes](./user_guide/quick_start/kubernetes/): Isolate Pods in your K8s
    cluster with gVisor.
*   [OCI Quick Start](./user_guide/quick_start/oci/): Expert mode. Customize
    gVisor for your environment.

[linux]: https://en.wikipedia.org/wiki/Linux_kernel_interfaces
[oci]: https://www.opencontainers.org
