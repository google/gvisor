This package defines primitives for sentry access to application memory.

Major types:

-   The `IO` interface represents a virtual address space and provides I/O
    methods on that address space. `IO` is the lowest-level primitive. The
    primary implementation of the `IO` interface is `mm.MemoryManager`.

-   `IOSequence` represents a collection of individually-contiguous address
    ranges in a `IO` that is operated on sequentially, analogous to Linux's
    `struct iov_iter`.

Major usage patterns:

-   Access to a task's virtual memory, subject to the application's memory
    protections and while running on that task's goroutine, from a context that
    is at or above the level of the `kernel` package (e.g. most syscall
    implementations in `syscalls/linux`); use the `kernel.Task.Copy*` wrappers
    defined in `kernel/task_usermem.go`.

-   Access to a task's virtual memory, from a context that is at or above the
    level of the `kernel` package, but where any of the above constraints does
    not hold (e.g. `PTRACE_POKEDATA`, which ignores application memory
    protections); obtain the task's `mm.MemoryManager` by calling
    `kernel.Task.MemoryManager`, and call its `IO` methods directly.

-   Access to a task's virtual memory, from a context that is below the level of
    the `kernel` package (e.g. filesystem I/O); clients must pass I/O arguments
    from higher layers, usually in the form of an `IOSequence`. The
    `kernel.Task.SingleIOSequence` and `kernel.Task.IovecsIOSequence` functions
    in `kernel/task_usermem.go` are convenience functions for doing so.
