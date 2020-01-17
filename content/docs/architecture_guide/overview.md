+++
title = "Overview & Platforms"
weight = 10
+++
A gVisor sandbox consists of multiple processes when running. These processes
collectively comprise a shared environment in which one or more containers can
be run.

Each sandbox has its own isolated instance of:

* The **Sentry**, A user-space kernel that runs the container and intercepts
  and responds to system calls made by the application.

Each container running in the sandbox has its own isolated instance of:

* A **Gofer** which provides file system access to the container.

![gVisor architecture diagram](../Sentry-Gofer.png "gVisor architecture diagram")

## runsc

The entrypoint to running a sandboxed container is the `runsc` executable.
`runsc` implements the [Open Container Initiative (OCI)][oci] runtime
specification. This means that OCI compatible _filesystem bundles_ can be run by
`runsc`.  Filesystem bundles are comprised of a `config.json` file containing
container configuration, and a root filesystem for the container.  Please see
the [OCI runtime spec][runtime-spec] for more information on filesystem bundles.
`runsc` implements multiple commands that perform various functions such as
starting, stopping, listing, and querying the status of containers.

## Sentry

The Sentry is the largest component of gVisor. It can be thought of as a
userspace OS kernel. The Sentry implements all the kernel functionality needed
by the untrusted application. It implements all of the supported system calls,
signal delivery, memory management and page faulting logic, the threading
model, and more.

When the untrusted application makes a system call, the currently used platform
redirects the call to the Sentry, which will do the necessary work to service
it. It is important to note that the Sentry will not simply pass through system
calls to the host kernel. As a userspace application, the Sentry will make some
host system calls to support its operation, but it will not allow the
application to directly control the system calls it makes.

The Sentry aims to present an equivalent environment to (upstream) Linux v4.4.

File system operations that extend beyond the sandbox (not internal /proc
files, pipes, etc) are sent to the Gofer, described below.

## Platforms

gVisor requires a platform to implement interception of syscalls, basic context
switching, and memory mapping functionality.

### ptrace

The ptrace platform uses `PTRACE_SYSEMU` to execute user code without allowing
it to execute host system calls. This platform can run anywhere that ptrace
works (even VMs without nested virtualization).

### KVM (experimental)

The KVM platform allows the Sentry to act as both guest OS and VMM, switching
back and forth between the two worlds seamlessly. The KVM platform can run on
bare-metal or in a VM with nested virtualization enabled. While there is no
virtualized hardware layer -- the sandbox retains a process model -- gVisor
leverages virtualization extensions available on modern processors in order to
improve isolation and performance of address space switches.

## Gofer

The Gofer is a normal host Linux process. The Gofer is started with each sandbox
and connected to the Sentry. The Sentry process is started in a restricted
seccomp container without access to file system resources. The Gofer provides
the Sentry access to file system resources via the 9P protocol and provides an
additional level of isolation.

## Application

The application (aka the untrusted application) is a normal Linux binary
provided to gVisor in an OCI runtime bundle. gVisor aims to provide an
environment equivalent to Linux v4.4, so applications should be able to run
unmodified. However, gVisor does not presently implement every system call,
/proc file, or /sys file so some incompatibilities may occur.

[oci]: https://www.opencontainers.org
[runtime-spec]: https://github.com/opencontainers/runtime-spec
