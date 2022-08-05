# Platform Guide

[TOC]

gVisor requires a platform to implement interception of syscalls, basic context
switching, and memory mapping functionality. Internally, gVisor uses an
abstraction sensibly called [`Platform`][platform]. A simplified version of this
interface looks like:

```golang
type Platform interface {
    NewAddressSpace() (AddressSpace, error)
    NewContext() Context
}

type Context interface {
    Switch(as AddressSpace, ac arch.Context) (..., error)
}

type AddressSpace interface {
    MapFile(addr hostarch.Addr, f File, fr FileRange, at hostarch.AccessType, ...) error
    Unmap(addr hostarch.Addr, length uint64)
}
```

There are a number of different ways to implement this interface that come with
various trade-offs, generally around performance and hardware requirements.

## Implementations

The choice of platform depends on the context in which `runsc` is executing. In
general, when running on bare-metal (not inside a VM), the KVM platform will
provide the best performance. The `ptrace` platform is a better choice when
running inside a VM, or on a machine without virtualization support.

![Platforms](platforms.png "Platform examples.")

### ptrace

The ptrace platform uses [`PTRACE_SYSEMU`][ptrace] to execute user code without
allowing it to execute host system calls. This platform can run anywhere that
`ptrace` works (even VMs without nested virtualization), which is ubiquitous.

Unfortunately, the ptrace platform has high context switch overhead, so system
call-heavy applications may pay a [performance penalty](./performance.md).

### KVM

The KVM platform uses the kernel's [KVM][kvm] functionality to allow the Sentry
to act as both guest OS and VMM. The KVM platform can run on bare-metal, or in a
VM with nested virtualization enabled. While there is no virtualized hardware
layer -- the sandbox retains a process model -- gVisor leverages virtualization
extensions available on modern processors in order to improve isolation and
performance of address space switches.

Note that while running within a nested VM is feasible with the KVM platform,
the `ptrace` platform will often provide better performance in such a setup, due
to the overhead of nested virtualization.

### GKE Sandbox

[GKE Sandbox] uses a custom gVisor platform implementation which provides better
performance than `ptrace` and KVM.

## Changing Platforms

See [Changing Platforms](../user_guide/platforms.md).

[kvm]: https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt
[platform]: https://cs.opensource.google/gvisor/gvisor/+/release-20190304.1:pkg/sentry/platform/platform.go;l=33
[ptrace]: http://man7.org/linux/man-pages/man2/ptrace.2.html
[GKE Sandbox]: https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods
