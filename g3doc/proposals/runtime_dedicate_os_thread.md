# `runtime.DedicateOSThread`

Status as of 2020-09-18: Deprioritized; initial studies in #2180 suggest that
this may be difficult to support in the Go runtime due to issues with GC.

## Summary

Allow goroutines to bind to kernel threads in a way that allows their scheduling
to be kernel-managed rather than runtime-managed.

## Objectives

*   Reduce Go runtime overhead in the gVisor sentry (#2184).

*   Minimize intrusiveness of changes to the Go runtime.

## Background

In Go, execution contexts are referred to as goroutines, which the runtime calls
Gs. The Go runtime maintains a variably-sized pool of threads (called Ms by the
runtime) on which Gs are executed, as well as a pool of "virtual processors"
(called Ps by the runtime) of size equal to `runtime.GOMAXPROCS()`. Usually,
each M requires a P in order to execute Gs, limiting the number of concurrently
executing goroutines to `runtime.GOMAXPROCS()`.

The `runtime.LockOSThread` function temporarily locks the invoking goroutine to
its current thread. It is primarily useful for interacting with OS or non-Go
library facilities that are per-thread. It does not reduce interactions with the
Go runtime scheduler: locked Ms relinquish their P when they become blocked, and
only continue execution after another M "chooses" their locked G to run and
donates their P to the locked M instead.

## Problems

### Context Switch Overhead

Most goroutines in the gVisor sentry are task goroutines, which back application
threads. Task goroutines spend large amounts of time blocked on syscalls that
execute untrusted application code. When invoking said syscall (which varies by
gVisor platform), the task goroutine may interact with the Go runtime in one of
three ways:

*   It can invoke the syscall without informing the runtime. In this case, the
    task goroutine will continue to hold its P during the syscall, limiting the
    number of application threads that can run concurrently to
    `runtime.GOMAXPROCS()`. This is problematic because the Go runtime scheduler
    is known to scale poorly with `GOMAXPROCS`; see #1942 and
    https://github.com/golang/go/issues/28808. It also means that preemption of
    application threads must be driven by sentry or runtime code, which is
    strictly slower than kernel-driven preemption (since the sentry must invoke
    another syscall to preempt the application thread).

*   It can call `runtime.entersyscallblock` before invoking the syscall, and
    `runtime.exitsyscall` after the syscall returns. In this case, the task
    goroutine will release its P while the syscall is executing. This allows the
    number of threads concurrently executing application code to exceed
    `GOMAXPROCS`. However, this incurs additional latency on syscall entry (to
    hand off the released P to another M, often requiring a `futex(FUTEX_WAKE)`
    syscall) and on syscall exit (to acquire a new P). It also drastically
    increases the number of threads that concurrently interact with the runtime
    scheduler, which is also problematic for performance (both in terms of CPU
    utilization and in terms of context switch latency); see #205.

-   It can call `runtime.entersyscall` before invoking the syscall, and
    `runtime.exitsyscall` after the syscall returns. In this case, the task
    goroutine "lazily releases" its P, allowing the runtime's "sysmon" thread to
    steal it on behalf of another M after a 20us delay. This mitigates the
    context switch latency problem when there are few task goroutines and the
    interval between switches to application code (i.e. the interval between
    application syscalls, page faults, or signal delivery) is short. (Cynically,
    this means that it's most effective in microbenchmarks). However, the delay
    before a P is stolen can also be problematic for performance when there are
    both many task goroutines switching to application code (lazily releasing
    their Ps) *and* many task goroutines switching to sentry code (contending
    for Ps), which is likely in larger heterogeneous workloads.

### Blocking Overhead

Task goroutines block on behalf of application syscalls like `futex` and
`epoll_wait` by receiving from a Go channel. (Future work may convert task
goroutine blocking to use the `syncevent` package to avoid overhead associated
with channels and `select`, but this does not change how blocking interacts with
the Go runtime scheduler.)

If `runtime.LockOSThread()` is not in effect when a task goroutine blocks, then
when the task goroutine is unblocked (by e.g. an application `FUTEX_WAKE`,
signal delivery, or a timeout) by sending to the blocked channel,
`runtime.ready` migrates the unblocked G to the unblocking P. In most cases,
this implies that every application thread block/unblock cycle results in a
migration of the thread between Ps, and therefore Ms, and therefore cores,
resulting in reduced application performance due to loss of CPU caches.
Furthermore, in most cases, the unblocking P cannot immediately switch to the
unblocked G (instead resuming execution of its current application thread after
completing the application's `futex(FUTEX_WAKE)`, `tgkill`, etc. syscall), often
requiring that another P steal the unblocked G before it can resume execution.

If `runtime.LockOSThread()` is in effect when a task goroutine blocks, then the
G will remain locked to its M, avoiding the core migration described above;
however, wakeup latency is significantly increased since, as described in
"Background", the G still needs to be selected by the scheduler before it can
run, and the M that selects the G then needs to transfer its P to the locked M,
incurring an additional `FUTEX_WAKE` syscall and round of kernel scheduling.

## Proposal

We propose to add a function, tentatively called `DedicateOSThread`, to the Go
`runtime` package, documented as follows:

```go
// DedicateOSThread wires the calling goroutine to its current operating system
// thread, and exempts it from counting against GOMAXPROCS. The calling
// goroutine will always execute in that thread, and no other goroutine will
// execute in it, until the calling goroutine has made as many calls to
// UndedicateOSThread as to DedicateOSThread. If the calling goroutine exits
// without unlocking the thread, the thread will be terminated.
//
// DedicateOSThread should only be used by long-lived goroutines that usually
// block due to blocking system calls, rather than interaction with other
// goroutines.
func DedicateOSThread()
```

Mechanically, `DedicateOSThread` implies `LockOSThread` (i.e. it locks the
invoking G to a M), but additionally locks the invoking M to a P. Ps locked by
`DedicateOSThread` are not counted against `GOMAXPROCS`; that is, the actual
number of Ps in the system (`len(runtime.allp)`) is `GOMAXPROCS` plus the number
of bound Ps (plus some slack to avoid frequent changes to `runtime.allp`).
Corollaries:

*   If `runtime.ready` observes that a readied G is locked to a M locked to a P,
    it immediately wakes the locked M without migrating the G to the readying P
    or waiting for a future call to `runtime.schedule` to select the readied G
    in `runtime.findrunnable`.

*   `runtime.stoplockedm` and `runtime.reentersyscall` skip the release of
    locked Ps; the latter also skips sysmon wakeup. `runtime.stoplockedm` and
    `runtime.exitsyscall` skip re-acquisition of Ps if one is locked.

*   sysmon does not attempt to preempt Gs that are locked to Ps, avoiding
    fruitless overhead from `tgkill` syscalls and signal delivery.

*   `runtime.findrunnable`'s work stealing skips locked Ps (suggesting that
    unlocked Ps be tracked in a separate array). `runtime.findrunnable` on
    locked Ps skip the global run queue, work stealing, and possibly netpoll.

*   New goroutines created by goroutines with locked Ps are enqueued on the
    global run queue rather than the invoking P's local run queue.

While gVisor's use case does not strictly require that the association is
reversible (with `runtime.UndedicateOSThread`), such a feature is required to
allow reuse of locked Ms, which is likely to be critical for performance.

## Alternatives Considered

*   Make the runtime scale well with `GOMAXPROCS`. While we are also
    concurrently investigating this problem, this would not address the issues
    of increased preemption cost or blocking overhead.

*   Make the runtime scale well with number of Ms. It is unclear if this is
    actually feasible, and would not address blocking overhead.

*   Make P-locking part of `LockOSThread`'s behavior. This would likely
    introduce performance regressions in existing uses of `LockOSThread` that do
    not fit this usage pattern. In particular, since `DedicateOSThread`
    transitions the invoker's P from "counted against `GOMAXPROCS`" to "not
    counted against `GOMAXPROCS`", it may need to wake another M to run a new P
    (that is counted against `GOMAXPROCS`), and the converse applies to
    `UndedicateOSThread`.

*   Rewrite the gVisor sentry in a language that does not force userspace
    scheduling. This is a last resort due to the amount of code involved.

## Related Issues

The proposed functionality is directly analogous to `spawn_blocking` in Rust
async runtimes
[`async_std`](https://docs.rs/async-std/1.8.0/async_std/task/fn.spawn_blocking.html)
and [`tokio`](https://docs.rs/tokio/0.3.5/tokio/task/fn.spawn_blocking.html).

Outside of gVisor:

*   https://github.com/golang/go/issues/21827#issuecomment-595152452 describes a
    use case for this feature in go-delve, where the goroutine that would use
    this feature spends much of its time blocked in `ptrace` syscalls.

*   This feature may improve performance in the use case described in
    https://github.com/golang/go/issues/18237, given the prominence of
    syscall.Syscall in the profile given in that bug report.
