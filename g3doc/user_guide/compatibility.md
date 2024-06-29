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
`io_uring`-related syscalls, but does support other I/O-related syscalls. Most
language runtimes and libraries will automatically determine which syscall
variant they should use, so they will work in gVisor. For this reason, looking
through the [list of supported syscalls](linux/amd64) is not necessarily a good
measure of how widely compatible gVisor is in practice.

gVisor releases go through the regression tests of popular language runtimes
(Python, Java, Node.js, PHP, Go) to ensure continued compatibility with the base
libraries of these languages. This means most programs written in these
languages will work.

<!-- mdformat on -->

[bug]: https://github.com/google/gvisor/issues/new?title=Compatibility%20Issue:
[issues]: https://github.com/google/gvisor/issues?q=is%3Aissue+is%3Aopen+label%3A%22area%3A+compatibility%22
