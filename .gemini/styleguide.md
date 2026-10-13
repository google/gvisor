# gVisor review guide

gVisor is an application kernel, written in Go, that implements a large part of
the Linux system call interface in user space. It is a security boundary between
sandboxed applications and the host kernel, so focus reviews on security,
correctness and Linux compatibility before style.

## Priorities

*   **Sandbox security.** Treat everything that comes from the sandboxed
    application as untrusted: system call arguments, application memory, file
    contents, ioctl payloads and network packets. Flag missing validation of
    sizes, offsets, counts and flags, integer overflow in size or offset
    arithmetic, and unchecked copies to or from application memory. Point out
    new host system calls, changes to seccomp filters, and host file access made
    on behalf of the application.
*   **Linux compatibility.** Behavior visible to applications, such as system
    call semantics, errno values, ABI structure layouts and `/proc` or `/sys`
    contents, must match Linux. Any change to the ABI implementation must be
    verified against the equivalent Linux kernel behavior. When the behavior is
    not obvious, ask for a reference to the Linux source or a test that shows
    it.
*   **Concurrency.** Check lock ordering, locks held across blocking calls, and
    fields accessed without the lock that protects them. Fields protected by a
    mutex have a checklocks annotation, such as `// +checklocks:mu`.

## Coding guidelines

Read the Coding Guidelines section of `CONTRIBUTING.md`, at the root of the
repository, and flag code that breaks its rules.

Don't comment on formatting, whitespace or line length. Formatters and linters
already enforce them.

## Style

*   Prefer early exits from loops and functions.
*   Name mutexes `mu` or `xxxMu` and do not export them. Declare a mutex as a
    sibling field before the fields it protects.
*   Document locking with checklocks annotations, not comments. Annotate each
    field protected by a mutex with `// +checklocks:mu`, and each function that
    must be called with a lock held with an annotation such as
    `+checklocks:f.mu` (`+checklocksread` if a read lock is enough). Functions
    that acquire or release a lock for their caller use `+checklocksacquire` or
    `+checklocksrelease`. These annotations supersede the mutex comment and
    `Preconditions:` rules in `g3doc/style.md`.
*   Question new `+checklocksignore` and `+checklocksforce` annotations. The
    code can usually be restructured so that they aren't needed.

## Testing

gVisor has to behave like Linux, so the tests that matter most check gVisor
against Linux, not against itself. The main ones are the system call tests in
`test/syscalls`: C++ programs, written with Google Test, that call the system
call interface directly. Each test runs both on Linux (the `native` target) and
in gVisor (the `runsc_*` targets), so a passing test shows that gVisor matches
real Linux behavior rather than the author's idea of it.

Don't accept Go unit tests for behavior that applications can observe, such as
system call results, errno values, `/proc` and `/sys` contents, ioctls, socket
options and file system semantics. A Go unit test of a system call
implementation only exercises gVisor's code and can't run against Linux, so it
can only check that the code does what its author expected. If that expectation
is wrong, the test passes anyway and the bug stays. These tests also depend on
sentry internals and break when the code is refactored. Ask for a system call
test instead. For network behavior on the wire, packetimpact
(`test/packetimpact`) and packetdrill (`test/packetdrill`) tests also run
against both Linux and gVisor.

Go unit tests are appropriate for gVisor internals that have no Linux behavior
to compare against, such as data structures and other self-contained library
code.

When reviewing system call tests:

*   A change that adds support for a system call, or for a new argument or
    option, should add a test for it.
*   Tests should pass on Linux (the `native` target), not only on gVisor. Man
    pages can be wrong, so tests should check actual Linux behavior.
*   Check system call results with the syscall matchers: `SyscallSucceeds()`,
    `SyscallSucceedsWithValue(...)`, `SyscallFails()` and
    `SyscallFailsWithErrno(...)`.
*   Prefer the RAII test utilities over custom test harnesses, and local class
    instances over full test fixtures. Add a shared test utility only when more
    than one test needs it.

## Performance

The following code is particularly performance-sensitive:

*   The system call hot path: entry and dispatch in `pkg/sentry/kernel`
    (`task_run.go`, `task_syscall.go`), the handlers in
    `pkg/sentry/syscalls/linux`, and the layers that copy data to and from
    application memory (`pkg/usermem`, `pkg/safemem`, `pkg/safecopy`,
    `pkg/marshal`).
*   Platform code (`pkg/sentry/platform`, `pkg/ring0`).
*   Sandbox startup (`runsc/boot`, `runsc/container`, `runsc/sandbox`).
*   Netstack (`pkg/tcpip`).
*   Checkpoint/restore (`pkg/state`, `pkg/sentry/state`).
*   File I/O (`pkg/sentry/vfs`, `pkg/sentry/fsimpl`).
*   Memory management (`pkg/sentry/mm`, `pkg/sentry/pgalloc`).
*   Inter-process communication with the gofer (`pkg/lisafs`, `runsc/fsgofer`).

Point out changes that slow these paths down. In particular:

*   **Allocations.** Avoid heap allocations where possible, and annotate
    functions that must not allocate with `// +checkescape` so that the
    checkescape analyzer enforces it. In netstack, use the pooled,
    reference-counted buffers in `pkg/buffer` instead of allocating and copying
    packet data.
*   **Gofer round trips.** Each gofer RPC is a round trip to another process.
    Avoid adding RPCs to frequent file system operations; use the Sentry's
    cached file system state, or combined RPCs such as `WalkStat`.
*   **Startup work.** Don't add work to sandbox startup, such as building large
    tables during initialization. Seccomp programs are precompiled
    (`pkg/seccomp/precompiledseccomp`) for this reason.
*   **Saved state.** Checkpoint time and image size grow with what is saved.
    Don't save state that can be rebuilt on restore; tag it `state:"nosave"` and
    rebuild it in `afterLoad`.
