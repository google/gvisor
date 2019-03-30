+++
title = "Performance"
weight = 30
+++
gVisor is designed to provide a secure, virtualized environment while preserving
key benefits of containerization such as small fixed overheads and a dynamic
resource footprint. For containerized infrastructure, this can provide an “easy
button” for sandboxing untrusted workloads: there are no changes to the
fundamental resource model.

However, there are clear trade-offs in this approach. gVisor does not fully
implement the system call surface provided by an upstream Linux kernel. We are
always working to improve this support, and current limitations are described
[Compatibility](../../user_guide/compatibility).

gVisor also imposes runtime costs over native containers. These costs come in
two forms: additional cycles and memory usage, and they come from two different
sources. First, the existence of the Sentry itself means that additional memory
will be required, and application system calls generally traverse additional
layers. We place an emphasis on [Security](../security/) and therefore chose to
use a language for the Sentry that provides lots of benefits in this domain, but
may not offer the raw performance of other choices. Costs imposed by this design
are structural costs.

Second, as gVisor is a fresh implementation of the system call surface, many of
the subsystems or specific calls are not as optimized as more mature
implementations. A good example here is the network stack, which is continuing
to evolve but does not support all the advanced recovery mechanisms offered by
other stacks and is less CPU efficient. This an implementation cost and should
not be confused with structural costs. Improvements here are ongoing and largely
driven by the workloads that matter to gVisor contributors and users.

## Structural Costs

The structural costs of gVisor are heavily influenced by the platform choice,
which implements system call interception. Today, gVisor supports a variety of
platforms. These platforms present distinct performance, compatibility and
security trade-offs. For example, the KVM platform low overhead system call
interception but runs poorly with nested virtualization.
