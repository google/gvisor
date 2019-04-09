![gVisor](g3doc/logo.png)

## What is gVisor?

**gVisor** is a user-space kernel, written in Go, that implements a substantial
portion of the Linux system surface. It includes an
[Open Container Initiative (OCI)][oci] runtime called `runsc` that provides an
isolation boundary between the application and the host kernel. The `runsc`
runtime integrates with Docker and Kubernetes, making it simple to run sandboxed
containers.

## Why does gVisor exist?

Containers are not a [**sandbox**][sandbox]. While containers have
revolutionized how we develop, package, and deploy applications, running
untrusted or potentially malicious code without additional isolation is not a
good idea. The efficiency and performance gains from using a single, shared
kernel also mean that container escape is possible with a single vulnerability.

gVisor is a user-space kernel for containers. It limits the host kernel surface
accessible to the application while still giving the application access to all
the features it expects. Unlike most kernels, gVisor does not assume or require
a fixed set of physical resources; instead, it leverages existing host kernel
functionality and runs as a normal user-space process. In other words, gVisor
implements Linux by way of Linux.

gVisor should not be confused with technologies and tools to harden containers
against external threats, provide additional integrity checks, or limit the
scope of access for a service. One should always be careful about what data is
made available to a container.

## Documentation

User documentation and technical architecture, including quick start guides, can
be found at [gvisor.dev][gvisor-dev].

## Installing from source

gVisor currently requires x86\_64 Linux to build, though support for other
architectures may become available in the future.

### Requirements

Make sure the following dependencies are installed:

*   [git][git]
*   [Bazel][bazel] 0.18+
*   [Python][python]
*   [Docker version 17.09.0 or greater][docker]
*   Gold linker (e.g. `binutils-gold` package on Ubuntu)

### Getting the source

Clone the repository:

```
git clone https://gvisor.googlesource.com/gvisor gvisor
cd gvisor
```

### Building

Build and install the `runsc` binary:

```
bazel build runsc
sudo cp ./bazel-bin/runsc/linux_amd64_pure_stripped/runsc /usr/local/bin
```

### Testing

The test suite can be run with Bazel:

```
bazel test ...
```

### Using remote execution

If you have a [Remote Build Execution][rbe] environment, you can use it to speed
up build and test cycles.

You must authenticate with the project first:

```
gcloud auth application-default login --no-launch-browser
```

Then invoke bazel with the following flags:

```
--config=remote
--project_id=$PROJECT
--remote_instance_name=projects/$PROJECT/instances/default_instance
```

You can also add those flags to your local ~/.bazelrc to avoid needing to
specify them each time on the command line.

## Community & Governance

The governance model is documented in our [community][community] repository.

The [gvisor-users mailing list][gvisor-users-list] and
[gvisor-dev mailing list][gvisor-dev-list] are good starting points for
questions and discussion.

## Security

Sensitive security-related questions, comments and disclosures can be sent to
the [gvisor-security mailing list][gvisor-security-list]. The full security
disclosure policy is defined in the [community][community] repository.

## Contributing

See [Contributing.md](CONTRIBUTING.md).

[bazel]: https://bazel.build
[community]: https://gvisor.googlesource.com/community
[docker]: https://www.docker.com
[git]: https://git-scm.com
[gvisor-security-list]: https://groups.google.com/forum/#!forum/gvisor-security
[gvisor-users-list]: https://groups.google.com/forum/#!forum/gvisor-users
[gvisor-dev-list]: https://groups.google.com/forum/#!forum/gvisor-dev
[oci]: https://www.opencontainers.org
[python]: https://python.org
[rbe]: https://blog.bazel.build/2018/10/05/remote-build-execution.html
[sandbox]: https://en.wikipedia.org/wiki/Sandbox_(computer_security)
[gvisor-dev]: https://gvisor.dev
