# The systrap platform

This platform is similar with the ptrace platform with the difference how system
calls, page-faults and other exceptions handled.

The kernel allows setting seccomp filters (SECCOMP_RET_TRAP), so that each time
when a thread tries to call a filtered system call, it will receive the SIGSYS
signal.

With this kernel feature, all stub thread events what have to be handled in the
sentry triggers signals. This means that they can be handled from a signal
handler.

The systrap platform includes the sysmsg module which implements a stub signal
handler and a protocol of communications of stub threads and the Sentry.

The initializations of a new stub thread includes next steps:

*   installing seccomp filters to trap all user system calls.
*   setting an alternate signal stack which is shared with the Sentry.
*   setting the sysmsg signal handler for SIGSYS, SIGSEGV, SIGBUS, SIGFPE,
    SIGTRAP, SIGILL.

User code is executed in context of a stub thread. When it calls a system call
or triggers page-fault, the signal handler is started. It notifies the Sentry
about a new signal, then the Sentry handles this event and notifies the system
thread back that it can continue running.

When the kernel prepares to execute the signal handler, it generates a signal
frame which contains a process state (registers, FPU state, etc). Then when the
kernel resumes a process, the process state is restored from this frame. The
signal frame is saved on a signal handler stack which is shared with the Sentry.
This allows us to read and modify the thread state from the Sentry.
