+++
title = "Security Model"
weight = 20
+++
gVisor was created in order to provide additional defense against the
exploitation of kernel bugs by untrusted userspace code. In order to understand
how gVisor achieves this goal, it is first necessary to understand the basic
threat model.

## Threats: The Anatomy of an Exploit

An exploit takes advantage of a software or hardware bug in order to escalate
privileges, gain access to privileged data, or disrupt services. All of the
possible interactions that a malicious application can have with the rest of the
system (attack vectors) define the attack surface. We categorize these attack
vectors into several common classes.

### System API

An operating system or hypervisor exposes an abstract System API in the form of
system calls and traps. This API may be documented and stable, as with Linux, or
it may be abstracted behind a library, as with Windows (i.e. win32.dll or
ntdll.dll). The System API includes all standard interfaces that application
code uses to interact with the system. This includes high-level abstractions
that are derived from low-level system calls, such as system files, sockets and
namespaces.

Although the System API is exposed to applications by design, bugs and race
conditions within the kernel or hypervisor may occasionally be exploitable via
the API. This is common in part due to the fact that most kernels and hypervisors
are written in [C][clang], which is well-suited to interfacing with hardware but
often prone to security issues. In order to exploit these issues, a typical attack
might involve some combination of the following:

1.  Opening or creating some combination of files, sockets or other descriptors.
1.  Passing crafted, malicious arguments, structures or packets.
1.  Racing with multiple threads in order to hit specific code paths.

For example, for the [Dirty Cow][dirtycow] privilege escalation bug, an
application would open a specific file in `/proc` or use a specific `ptrace`
system call, and use multiple threads in order to trigger a race condition when
touching a fresh page of memory. The attacker then gains control over a page of
memory belonging to the system. With additional privileges or access to
privileged data in the kernel, an attacker will often be able to employ
additional techniques to gain full access to the rest of the system.

While bugs in the implementation of the System API are readily fixed, they are
also the most common form of exploit. The exposure created by this class of
exploit is what gVisor aims to minimize and control, described in detail below.

### System ABI

Hardware and software exploits occasionally exist in execution paths that are
not part of an intended System API. In this case, exploits may be found as part
of implicit actions the hardware or privileged system code takes in response to
certain events, such as traps or interrupts. For example, the recent
[POPSS][popss] flaw required only native code execution (no specific system call
or file access). In that case, the Xen hypervisor was similarly vulnerable,
highlighting that hypervisors are not immune to this vector.

### Side Channels

Hardware side channels may be exploitable by any code running on a system:
native, sandboxed, or virtualized. However, many host-level mitigations against
hardware side channels are still effective with a sandbox. For example, kernels
built with retpoline protect against some speculative execution attacks
(Spectre) and frame poisoning may protect against L1 terminal fault (L1TF)
attacks. Hypervisors may introduce additional complications in this regard, as
there is no mitigation against an application in a normally functioning Virtual
Machine (VM) exploiting the L1TF vulnerability for another VM on the sibling
hyperthread.

### Other Vectors

The above categories in no way represent an exhaustive list of exploits, as we
focus only on running untrusted code from within the operating system or
hypervisor.  We do not consider other ways that a more generic adversary
may interact with a system, such as inserting a portable storage device with a
malicious filesystem image, using a combination of crafted keyboard or touch
inputs, or saturating a network device with ill-formed packets.

Furthermore, high-level systems may contain exploitable components. An attacker
need not escalate privileges within a container if there’s an exploitable
network-accessible service on the host or some other API path. *A sandbox is not
a substitute for a secure architecture*.

## Goals: Limiting Exposure

gVisor’s primary design goal is to minimize the System API attack vector while
still providing a process model. There are two primary security principles that
inform this design. First, the application’s direct interactions with the host
System API are intercepted by the Sentry, which implements the System API
instead. Second, the System API accessible to the Sentry itself is minimized to
a safer, restricted set. The first principle minimizes the possibility of direct
exploitation of the host System API by applications, and the second principle
minimizes indirect exploitability, which is the exploitation by an exploited or
buggy Sentry (e.g. chaining an exploit).

The first principle is similar to the security basis for a Virtual Machine (VM).
With a VM, an application’s interactions with the host are replaced by
interactions with a guest operating system and a set of virtualized hardware
devices. These hardware devices are then implemented via the host System API by
a Virtual Machine Monitor (VMM). The Sentry similarly prevents direct interactions
by providing its own implementation of the System API that the application
must interact with. Applications are not able to to directly craft specific
arguments or flags for the host System API, or interact directly with host
primitives.

For both the Sentry and a VMM, it’s worth noting that while direct interactions
are not possible, indirect interactions are still possible. For example, a read
on a host-backed file in the Sentry may ultimately result in a host read system
call (made by the Sentry, not by passing through arguments from the application),
similar to how a read on a block device in a VM may result in the VMM issuing
a corresponding host read system call from a backing file.

An important distinction from a VM is that the Sentry implements a System API based
directly on host System API primitives instead of relying on virtualized hardware
and a guest operating system. This selects a distinct set of trade-offs, largely
in the performance, efficiency and compatibility domains. Since transitions in
and out of the sandbox are relatively expensive, a guest operating system will
typically take ownership of resources. For example, in the above case, the
guest operating system may read the block device data in a local page cache,
to avoid subsequent reads. This may lead to better performance but lower
efficiency, since memory may be wasted or duplicated. The Sentry opts instead
to defer to the host for many operations during runtime, for improved efficiency
but lower performance in some use cases.

### What can a sandbox do?

An application in a gVisor sandbox is permitted to do most things a standard
container can do: for example, applications can read and write files mapped
within the container, make network connections, etc. As described above,
gVisor's primary goal is to limit exposure to bugs and exploits while still
allowing most applications to run. Even so, gVisor will limit some operations
that might be permitted with a standard container. Even with appropriate
capabilities, a user in a gVisor sandbox will only be able to manipulate
virtualized system resources (e.g. the system time, kernel settings or
filesystem attributes) and not underlying host system resources.

While the sandbox virtualizes many operations for the application, we limit the
sandbox's own interactions with the host to the following high-level operations:

1.  Communicate with a Gofer process via a connected socket. The sandbox may
    receive new file descriptors from the Gofer process, corresponding to opened
    files. These files can then be read from and written to by the sandbox.
1.  Make a minimal set of host system calls. The calls do not include the
    creation of new sockets (unless host networking mode is enabled) or opening
    files. The calls include duplication and closing of file descriptors,
    synchronization, timers and signal management.
1.  Read and write packets to a virtual ethernet device. This is not required if
    host networking is enabled (or networking is disabled).

### System ABI, Side Channels and Other Vectors

gVisor relies on the host operating system and the platform for defense against
hardware-based attacks. Given the nature of these vulnerabilities, there is
little defense that gVisor can provide (there’s no guarantee that additional
hardware measures, such as virtualization, memory encryption, etc. would
actually decrease the attack surface). Note that this is true even when using
hardware virtualization for acceleration, as the host kernel or hypervisor is
ultimately responsible for defending against attacks from within malicious
guests.

gVisor similarly relies on the host resource mechanisms (cgroups) for defense
against resource exhaustion and denial of service attacks. Network policy
controls should be applied at the container level to ensure appropriate network
policy enforcement. Note that the sandbox itself is not capable of altering or
configuring these mechanisms, and the sandbox itself should make an attacker
less likely to exploit or override these controls through other means.

## Principles: Defense-in-Depth

For gVisor development, there are several engineering principles that are
employed in order to ensure that the system meets its design goals.

1.  No system call is passed through directly to the host. Every supported call
    has an independent implementation in the Sentry, that is unlikely to suffer
    from identical vulnerabilities that may appear in the host. This has the
    consequence that all kernel features used by applications require an
    implementation within the Sentry.
1.  Only common, universal functionality is implemented. Some filesystems,
    network devices or modules may expose specialized functionality to user
    space applications via mechanisms such as extended attributes, raw sockets
    or ioctls. Since the Sentry is responsible for implementing the full system
    call surface, we do not implement or pass through these specialized APIs.
1.  The host surface exposed to the Sentry is minimized. While the system call
    surface is not trivial, it is explicitly enumerated and controlled. The
    Sentry is not permitted to open new files, create new sockets or do many
    other interesting things on the host.

Additionally, we have practical restrictions that are imposed on the project to
minimize the risk of Sentry exploitability. For example:

1.  Unsafe code is carefully controlled. All unsafe code is isolated in files
    that end with "unsafe.go", in order to facilitate validation and auditing.
    No file without the unsafe suffix may import the unsafe package.
1.  No CGo is allowed. The Sentry must be a pure Go binary.
1.  External imports are not generally allowed within the core packages. Only
    limited external imports are used within the setup code. The code available
    inside the Sentry is carefully controlled, to ensure that the above rules
    are effective.

Finally, we recognize that security is a process, and that vigilance is
critical. Beyond our security disclosure process, the Sentry is fuzzed
continuously to identify potential bugs and races proactively, and production
crashes are recorded and triaged to similarly identify material issues.

## FAQ

### Is this more or less secure than a Virtual Machine?

The security of a VM depends to a large extent on what is exposed from the host
kernel and user space support code. For example, device emulation code in the
host kernel (e.g. APIC) or optimizations (e.g. vhost) can be more complex than a
simple system call, and exploits carry the same risks. Similarly, the user space
support code is frequently unsandboxed, and exploits, while rare, may allow
unfettered access to the system.

Some platforms leverage the same virtualization hardware as VMs in order to
provide better system call interception performance. However, gVisor does not
implement any device emulation, and instead opts to use a sandboxed host System
API directly. Both approaches significantly reduce the original attack surface.
Ultimately, since gVisor is capable of using the same hardware mechanism, one
should not assume that the mere use of virtualization hardware makes a system
more or less secure, just as it would be a mistake to make the claim that the
use of a unibody alone makes a car safe.

### Does this stop hardware side channels?

In general, gVisor does not provide protection against hardware side channels,
although it may make exploits that rely on direct access to the host System API
more difficult to use. To minimize exposure, you should follow relevant guidance
from vendors and keep your host kernel and firmware up-to-date.

### Is this just a ptrace sandbox?

No: the term “ptrace sandbox” generally refers to software that uses the Linux
ptrace facility to inspect and authorize system calls made by applications,
enforcing a specific policy. These commonly suffer from two issues. First,
vulnerable system calls may be authorized by the sandbox, as the application
still has direct access to some System API. Second, it’s impossible to avoid
time-of-check, time-of-use race conditions without disabling multi-threading.

In gVisor, the platforms that use ptrace operate differently. The stubs that are
traced are never allowed to continue execution into the host kernel and complete
a call directly. Instead, all system calls are interpreted and handled by the
Sentry itself, who reflects resulting register state back into the tracee before
continuing execution in user space. This is very similar to the mechanism used
by User-Mode Linux (UML).

[dirtycow]: https://en.wikipedia.org/wiki/Dirty_COW
[clang]: https://en.wikipedia.org/wiki/C_(programming_language)
[popss]: https://nvd.nist.gov/vuln/detail/CVE-2018-8897
