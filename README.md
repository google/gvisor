![gVisor](g3doc/logo.png)

[![Build status](https://badge.buildkite.com/3b159f20b9830461a71112566c4171c0bdfd2f980a8e4c0ae6.svg?branch=master)](https://buildkite.com/gvisor/pipeline)
[![Issue reviver](https://github.com/google/gvisor/actions/workflows/issue_reviver.yml/badge.svg)](https://github.com/google/gvisor/actions/workflows/issue_reviver.yml)
[![CodeQL](https://github.com/google/gvisor/actions/workflows/codeql.yml/badge.svg)](https://github.com/google/gvisor/actions/workflows/codeql.yml)
[![gVisor chat](https://badges.gitter.im/gvisor/community.png)](https://gitter.im/gvisor/community)
[![code search](https://img.shields.io/badge/code-search-blue)](https://cs.opensource.google/gvisor/gvisor)

## What is gVisor?

**gVisor** provides a strong layer of isolation between running applications and
the host operating system. It is an application kernel that implements a
[Linux-like interface][linux]. Unlike Linux, it is written in a memory-safe
language (Go) and runs in userspace.

gVisor includes an [Open Container Initiative (OCI)][oci] runtime called `runsc`
that makes it easy to work with existing container tooling. The `runsc` runtime
integrates with Docker and Kubernetes, making it simple to run sandboxed
containers.

## What **isn't** gVisor?

*   gVisor is **not a syscall filter** (e.g. `seccomp-bpf`), nor a wrapper over
    Linux isolation primitives (e.g. `firejail`, AppArmor, etc.).
*   gVisor is also **not a VM** in the everyday sense of the term (e.g.
    VirtualBox, QEMU).

**gVisor takes a distinct third approach**, providing many security benefits of
VMs while maintaining the lower resource footprint, fast startup, and
flexibility of regular userspace applications.

## Why does gVisor exist?

Containers are not a [**sandbox**][sandbox]. While containers have
revolutionized how we develop, package, and deploy applications, using them to
run untrusted or potentially malicious code without additional isolation is not
a good idea. While using a single, shared kernel allows for efficiency and
performance gains, it also means that container escape is possible with a single
vulnerability.

gVisor is an application kernel for containers. It limits the host kernel
surface accessible to the application while still giving the application access
to all the features it expects. Unlike most kernels, gVisor does not assume or
require a fixed set of physical resources; instead, it leverages existing host
kernel functionality and runs as a normal process. In other words, gVisor
implements Linux by way of Linux.

gVisor should not be confused with technologies and tools to harden containers
against external threats, provide additional integrity checks, or limit the
scope of access for a service. One should always be careful about what data is
made available to a container.

## Documentation

User documentation and technical architecture, including quick start guides, can
be found at [gvisor.dev][gvisor-dev].

## Installing from source

gVisor builds on x86_64 and ARM64. Other architectures may become available in
the future.

For the purposes of these instructions, [bazel][bazel] and other build
dependencies are wrapped in a build container. It is possible to use
[bazel][bazel] directly, or type `make help` for standard targets.

### Requirements

Make sure the following dependencies are installed:

*   Linux 4.14.77+ ([older linux][old-linux])
*   [Docker version 17.09.0 or greater][docker]

### Building

Build and install the `runsc` binary:

```sh
mkdir -p bin
make copy TARGETS=runsc DESTINATION=bin/
sudo cp ./bin/runsc /usr/local/bin
```

To build specific libraries or binaries, you can specify the target:

```sh
make build TARGETS="//pkg/tcpip:tcpip"
```

### Building directly with Bazel (without Docker)

Using Bazel directly isn't recommended due to the extra overhead, but in order
to get started:

-   Look at the [build dockerfile](images/default/Dockerfile) for the canonical
    list of needed dependencies.
-   Install and use [bazelisk][bazelisk]. Otherwise, make sure your bazel
    version matches the one listed in the [.bazelversion](.bazelversion) file.

After setting up dependencies, using Bazel is similar to the Makefile:

```sh
bazel build //runsc:runsc
```

### Testing

To run standard test suites, you can use:

```sh
make unit-tests
make tests
```

To run specific tests, you can specify the target:

```sh
# Makefile
make test TARGETS="//runsc:version_test"
# Bazel
bazel test //runsc:version_test
```

### Mac OS

Some packages support running tests directly on macOS. At the time of this
writing, gVisor requires bazel 8, which you can install via homebrew:

```sh
brew install bazel@8

# You can then run the tests, e.g.:
$(brew --prefix bazel@8)/bin/bazel test --macos_sdk_version=$(xcrun --show-sdk-version) -- //tools/nogo/... //tools/check{aligned,const,escape,linkname,locks,unsafe}/...
```

### Using `go get`

This project uses [bazel][bazel] to build and manage dependencies. A synthetic
`go` branch is maintained that is compatible with standard `go` tooling for
convenience.

For example, to build and install `runsc` directly from this branch:

```sh
echo "module runsc" > go.mod
GO111MODULE=on go get gvisor.dev/gvisor/runsc@go
CGO_ENABLED=0 GO111MODULE=on sudo -E go build -o /usr/local/bin/runsc gvisor.dev/gvisor/runsc
```

Subsequently, you can build and install the shim binary for `containerd`:

```sh
GO111MODULE=on sudo -E go build -o /usr/local/bin/containerd-shim-runsc-v1 gvisor.dev/gvisor/shim
```

Note that this branch is supported in a best effort capacity, and direct
development on this branch is not supported. Development should occur on the
`master` branch, which is then reflected into the `go` branch.

## Community & Governance

See [GOVERNANCE.md](GOVERNANCE.md) for project governance information.

The [gvisor-users mailing list][gvisor-users-list] and
[gvisor-dev mailing list][gvisor-dev-list] are good starting points for
questions and discussion.

## Security Policy

See [SECURITY.md](SECURITY.md).

## Contributing

See [Contributing.md](CONTRIBUTING.md).

[bazel]: https://bazel.build
[docker]: https://www.docker.com
[gvisor-users-list]: https://groups.google.com/forum/#!forum/gvisor-users
[gvisor-dev]: https://gvisor.dev
[gvisor-dev-list]: https://groups.google.com/forum/#!forum/gvisor-dev
[linux]: https://en.wikipedia.org/wiki/Linux_kernel_interfaces
[oci]: https://www.opencontainers.org
[old-linux]: https://gvisor.dev/docs/user_guide/networking/#gso
[sandbox]: https://en.wikipedia.org/wiki/Sandbox_(computer_security)
[bazelisk]: https://github.com/bazelbuild/bazelisk
