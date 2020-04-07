# Proposal: Adopt `syncevent`

-   Status: Draft as of 2020-04-06
-   Author: jamieliu@google.com

## Summary

Replace most uses of Go channels, and all uses of the `waiter` and `sleep`
packages, with use of the `syncevent` package.

## Objectives

-   Avoid overhead associated with Go channels and `select`.

-   Reduce synchronization primitive proliferation.

## Background

Within the gVisor sentry, Go channels are used in three cases:

1.  When a goroutine must block pending one of many asynchronous events. For
    example, task interruptible sleep states block in a `select` statement (in
    `kernel.Task.block`) that waits for completion, a signal-delivery
    interrupt, or timeout expiry, whichever comes first.

2.  Interactions with the Go `time` package, which only supports notifications
    in the form of channel sends.

3.  Interactions with the Go `os/signal` package, which has the same property.

"Sources" of interruptible sleeps, notably blocking I/O, are correspondingly
modeled using channels, usually via the `//pkg/waiter` package.

`//pkg/tcpip` ("netstack") is instead heavily dependent on the `//pkg/sleep`
package for wakeup multiplexing. To quote from cl/154112611, which implemented
the `sleep` package:

> Here we introduce a new [notification primitive], which is to "select" as epoll is to poll.
> A caller adds all sources of wake ups once, and sleeps on them in O(1).
> It is implemented in a lock-free manner, and even when sleep is involved,
> there are no allocations. (Selects with multiple channels have to
> allocate pseudoG objects for each channel being waited on, they also
> require all locks to held at the same time, so they have to *sort*
> channels on each select call, and finally they also shuffle the order).

This motivation still holds today; `runtime.selectgo` still does all of the
things described in this quote, and benchmarks still measure a ~2x difference
in overhead between waiting using the `sleep` package vs. waiting using
`select`, even with relatively few (3-4) wakeup sources. This `select` overhead
is readily observable in paths that cause task goroutines to block; for
example, modulo Go scheduler overhead (which often dominates, but is the topic
of another proposal), `runtime.selectgo` makes up approximately 45% of the cost
of `linux.futexWaitDuration`, which handles application `futex(FUTEX_WAIT)`
syscalls.

Unfortunately, the `sleep` package cannot trivially replace most uses of
channel in the sentry; in particular, the efficient implementation of blocking
I/O depends on the ability to notify multiple waiters of a single event, which
would require per-waiter memory allocation to support in the `sleep` package.

## Proposal

`//pkg/syncevent` is internally similar to `//pkg/sleep`, but uses event
bitmasks rather than per-waiter/event-pair objects, allowing it to support
efficient event broadcast. This makes it suitable as a replacement for both the
`waiter` and `sleep` packages. To achieve this:

-   Implement a `syncevent.ReceiverCallback` that performs a non-blocking send
    to a `chan struct{}`, and embed such a callback (along with a corresponding
    `syncevent.Receiver`) in each `kernel.Task`. This makes it possible to shim
    `syncevent` event sources to channel-based event receivers at minimal cost,
    allowing us to convert `kernel.Task.block` from channels to `syncevent`
    only after all event sources have been converted. (Note that the reverse is
    not possible: there is no way for a channel send to notify a
    `syncevent.Receiver` without a waiting goroutine, which is extremely
    expensive. This is another advantage of `syncevent` over channels.)

-   Assign `syncevent.Set` bits to events. This allocation will likely be
    hierarchical in nature. For example, the two most significant bits may be
    globally assigned to timeouts and task signal-delivery interrupts
    respectively, the bottom 16 bits allowed to be event-source-specific, and
    the remaining 46 bits reserved for future use. Then when a task goroutine
    blocks on I/O, the bottom 16 bits represent `EPOLL*` event masks; when a
    task goroutine blocks in `waitpid(2)`, the bottom 16 bits are assigned to
    task state changes like `kernel.EventExit`; etc.

-   Remove the `syncevent.Source` type. This was added in imitation of the
    `waiter` package; however, in hindsight, different kinds of event sources
    are likely to have different inputs and outputs. In particular,
    registration for I/O events from file descriptions should take
    `context.Context` and be able to return an error to support a correct
    implementation of signalfds.

-   Correspondingly, replace `vfs.FileDescriptionImpl`'s embedding of the
    `waiter.Waitable` interface with an appropriate set of methods for polling
    I/O readiness and readiness event subscription/unsubscription. (We do not
    currently believe that converting VFS1 in the same way is worthwhile;
    instead, the `waiter` package will be dropped once VFS1 is obsolete.)

-   Implement a `sentry/kernel/time.TimerListener` that notifies a
    `syncevent.Receiver`, to replace `sentry/kernel/time.ChannelNotifier`.
    Since ~all interactions with the `time` package in the sentry should
    already be mediated by the `sentry/kernel/time` package, in order to ensure
    that the syscall view of time is consistent with the application view of
    time (i.e. uses kernel-managed clocks), this substantially mitigates the
    `time` package's dependence on channels (e.g. for syscall timeouts).

-   Clarify whether there is ongoing work to make netstack TCP packet
    processing (the primary user of the `sleep` package) synchronous in the
    near future. If so, then this work will naturally reduce the amount of work
    required to migrate netstack off of the `sleep` package.

-   Once all event sources have been converted to `syncevent`, replace the
    per-`kernel.Task` `syncevent.Receiver` and channel shim with a
    `syncevent.Waiter`, and reimplement `kernel.Task.block` in terms of
    `syncevent.Waiter.Wait`.

## Alternatives Considered

-   Improve the performance of `select` to match that of the `syncevent`
    package. This is considered infeasible since the `syncevent` package
    requires external assignment of event bits to events and limits the number
    of distinct events to the size of the bitmask (64), both of which are
    completely acceptable for our use case but neither of which seems feasible
    for `select`.
