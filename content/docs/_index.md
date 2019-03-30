+++
title = "gVisor Documentation"
+++
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

Check out the [gVisor Quick Start](./user_guide/docker/) to get started
using gVisor.

## How this documentation is organized

-   The [User Guide](./user_guide/) contains info on how to use gVisor
    and integrate it into your application or platform.
-   The [Architecture Guide](./architecture_guide/) explains about
    gVisor's architecture & design philosophy. Start here if you would like to
    know more about how gVisor works and why it was created.

[linux]: https://en.wikipedia.org/wiki/Linux_kernel_interfaces
[oci]: https://www.opencontainers.org
