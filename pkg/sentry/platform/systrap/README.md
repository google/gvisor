# The systrap platform

This platform is similar with the ptrace platform but differs on how system
calls, page-faults and other exceptions are handled.

Linux allows setting seccomp filters with `SECCOMP_RET_TRAP`, such that when a
thread tries to call a system call caught by the seccomp filter, this thread
will receive the `SIGSYS` signal.

gVisor's systrap platform uses this kernel feature to have all thread events
that have to be handled in the sentry trigger signals.

The systrap platform implements a stub signal handler (as part of the `sysmsg`
module), and communication protocol between this stub signal handler and the
Sentry.

The initialization of a new stub thread involves:

*   Installing seccomp filters to trap all user system calls.
*   Setting up an alternate signal stack which is shared with the Sentry.
*   Setting up the sysmsg signal handler for `SIGSYS`, `SIGSEGV`, `SIGBUS`,
    `SIGFPE`, `SIGTRAP`, and `SIGILL`.

User code is executed in the context of a stub thread. When it calls a system
call or triggers a page-fault, the stub signal handler code executes. It
notifies the Sentry of this new signal. The Sentry handles this, and calls back
the system thread so that it can resume running.

When the kernel prepares to execute the signal handler, it generates a signal
frame which contains the process state (registers, FPU state, etc). Then, when
the kernel resumes the process, the process state is restored from this frame.
The signal frame is saved on the signal handler stack. This memory region is
shared with the Sentry process. This allows gVisor to read and modify the thread
state from the Sentry.
