# Platform Portability

Hardware virtualization is often seen as a requirement to provide an additional
isolation layer for untrusted applications. However, hardware virtualization
requires expensive bare-metal machines or cloud instances to run safely with
good performance, increasing cost and complexity for Cloud users. gVisor,
however, takes a more flexible approach.

One of the pillars of gVisor's architecture is portability, allowing it to run
anywhere that runs Linux. Modern Cloud-Native applications run in containers in
many different places, from bare metal to virtual machines, and can't always
rely on nested virtualization. It is important for gVisor to be able to support
the environments where you run containers.

gVisor achieves portability through an abstraction called a _Platform_.
Platforms can have many implementations, and each implementation can cover
different environments, making use of available software or hardware features.

## Background

Before we can understand how gVisor achieves portability using platforms, we
should take a step back and understand how applications interact with their
host.

Container sandboxes can provide an isolation layer between the host and
application by virtualizing one of the layers below it, including the hardware
or operating system. Many sandboxes virtualize the hardware layer by running
applications in virtual machines. gVisor takes a different approach by
virtualizing the OS layer.

When an application is run in a normal situation the host operating system loads
the application into user memory and schedules it for execution. The operating
system scheduler eventually schedules the application to a CPU and begins
executing it. It then handles the application's requests, such as for memory and
the lifecycle of the application. gVisor virtualizes these interactions, such as
system calls, and context switching that happen between an application and OS.

[System calls](https://en.wikipedia.org/wiki/System_call) allow applications to
ask the OS to perform some task for it. System calls look like a normal function
call in most programming languages though works a bit differently under the
hood. When an application system call is encountered some special processing
takes place to do a
[context switch](https://en.wikipedia.org/wiki/Context_switch) into kernel mode
and begin executing code in the kernel before returning a result to the
application. Context switching may happen in other situations as well. For
example, to respond to an interrupt.

## The Platform Interface

gVisor provides a sandbox which implements the Linux OS interface, intercepting
OS interactions such as system calls and implements them in the sandbox kernel.

It does this to limit interactions with the host, and protect the host from an
untrusted application running in the sandbox. The Platform is the bottom layer
of gVisor which provides the environment necessary for gVisor to control and
manage applications. In general, the Platform must:

1.  Provide the ability to create and manage memory address spaces.
2.  Provide execution contexts for running applications in those memory address
    spaces.
3.  Provide the ability to change execution context and return control to gVisor
    at specific times (e.g. system call, page fault)

This interface is conceptually simple, but very powerful. Since the Platform
interface only requires these three capabilities, it gives gVisor enough control
for it to act as the application's OS, while still allowing the use of very
different isolation technologies under the hood. You can learn more about the
Platform interface in the
[Platform Guide](https://gvisor.dev/docs/architecture_guide/platforms/).

## Implementations of the Platform Interface

While gVisor can make use of technologies like hardware virtualization, it
doesn't necessarily rely on any one technology to provide a similar level of
isolation. The flexibility of the Platform interface allows for implementations
that use technologies other than hardware virtualization. This allows gVisor to
run in VMs without nested virtualization, for example. By providing an
abstraction for the underlying platform, each implementation can make various
tradeoffs regarding performance or hardware requirements.

Currently gVisor provides two gVisor Platform implementations; the Ptrace
Platform, and the KVM Platform, each using very different methods to implement
the Platform interface.

![gVisor Platforms](../../../../../docs/architecture_guide/platforms/platforms.png "Platforms")

The Ptrace Platform uses
[PTRACE\_SYSEMU](http://man7.org/linux/man-pages/man2/ptrace.2.html) to trap
syscalls, and uses the host for memory mapping and context switching. This
platform can run anywhere that ptrace is available, which includes most Linux
systems, VMs or otherwise.

The KVM Platform uses virtualization, but in an unconventional way. gVisor runs
in a virtual machine but as both guest OS and VMM, and presents no virtualized
hardware layer. This provides a simpler interface that can avoid hardware
initialization for fast start up, while taking advantage of hardware
virtualization support to improve memory isolation and performance of context
switching.

The flexibility of the Platform interface allows for a lot of room to improve
the existing KVM and ptrace platforms, as well as the ability to utilize new
methods for improving gVisor's performance or portability in future Platform
implementations.

## Portability

Through the Platform interface, gVisor is able to support bare metal, virtual
machines, and Cloud environments while still providing a highly secure sandbox
for running untrusted applications. This is especially important for Cloud and
Kubernetes users because it allows gVisor to run anywhere that Kubernetes can
run and provide similar experiences in multi-region, hybrid, multi-platform
environments.

Give gVisor's open source platforms a try. Using a Platform is as easy as
providing the `--platform` flag to `runsc`. See the documentation on
[changing platforms](https://gvisor.dev/docs/user_guide/platforms/) for how to
use different platforms with Docker. We would love to hear about your experience
so come chat with us in our
[Gitter channel](https://gitter.im/gvisor/community), or send us an
[issue on Github](https://gvisor.dev/issue) if you run into any problems.
