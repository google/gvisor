# Project Ideas for Google Summer of Code 2021

This is a collection of project ideas for
[Google Summer of Code 2021][gsoc-2021-site]. These projects are intended to be
relatively self-contained and should be good starting projects for new
contributors to gVisor. We expect individual contributors to be able to make
reasonable progress on these projects over the course of several weeks.
Familiarity with Golang and knowledge about systems programming in Linux will be
helpful.

If you're interested in contributing to gVisor through Google Summer of Code
2021, but would like to propose your own idea for a project, please see our
[roadmap](../roadmap.md) for areas of development, and get in touch through our
[mailing list][gvisor-mailing-list] or [chat][gvisor-chat]!

## Implement `io_uring`

`io_uring` is the lastest asynchronous I/O API in Linux. This project will
involve implementing the system interfaces required to support `io_uring` in
gVisor. A successful implementation should have similar relatively performance
and scalability characteristics compared to synchronous I/O syscalls, as in
Linux.

The core of the `io_uring` interface is deceptively simple, involving only three
new syscalls:

-   `io_uring_setup(2)` creates a new `io_uring` instance represented by a file
    descriptor, including a set of request submission and completion queues
    backed by shared memory ring buffers.

-   `io_uring_register(2)` optionally binds kernel resources such as files and
    memory buffers to handles, which can then be passed to `io_uring`
    operations. Pre-registering resources in this way moves the cost of looking
    up and validating these resources to registration time rather than paying
    the cost during the operation.

-   `io_uring_enter(2)` is the syscall used to submit queued operations and wait
    for completions. This is the most complex part of the mechanism, requiring
    the kernel to process queued request from the submission queue, dispatching
    the appropriate I/O operation based on the request arguments and blocking
    for the requested number of operations to be completed before returning.

An `io_uring` request is effectively an opcode specifying the I/O operation to
perform, and corresponding arguments. The opcodes and arguments closely relate
to the the corresponding synchronous I/O syscall. In addition, there are some
`io_uring`-specific arguments that specify things like how to process requests,
how to interpret the arguments and communicate the status of the ring buffers.

For a detailed description of the `io_uring` interface, see the
[design doc][io-uring-doc] by the `io_uring` authors.

Due to the complexity of the full `io_uring` mechanism and the numerous
supported operations, it should be implemented in two stages:

In the first stage, a simplified version of the `io_uring_setup` and
`io_uring_enter` syscalls should be implemented, which will only support a
minimal set of arguments and just one or two simple opcodes. This simplified
implementation can be used to figure out how to integreate `io_uring` with
gVisor's virtual filesystem and memory management subsystems, as well as
benchmark the implementation to ensure it has the desired performance
characteristics. The goal in this stage should be to implement the smallest
subset of features required to perform a basic operation through `io_uring`s.

In the second stage, support can be added for all the I/O operations supported
by Linux, as well as advanced `io_uring` features such as fixed files and
buffers (via `io_uring_register`), polled I/O and kernel-side request polling.

[gsoc-2021-site]: https://summerofcode.withgoogle.com
[gvisor-chat]: https://gitter.im/gvisor/community
[gvisor-mailing-list]: https://groups.google.com/g/gvisor-dev
[io-uring-doc]: https://kernel.dk/io_uring.pdf
