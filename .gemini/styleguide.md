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

This section is copied from the Coding Guidelines in `CONTRIBUTING.md`.

All code should comply with the style guide in `g3doc/style.md`. Note that code
may be automatically formatted per the guidelines when merged.

As a secure runtime, we need to maintain the safety of all code included in
gVisor. The following rules help mitigate issues.

Definitions for the rules below:

`core`:

*   `//pkg/sentry/...`
*   Transitive dependencies in `//pkg/...`, etc.

`runsc`:

*   `//runsc/...`

Rules:

*   No cgo in `core` or `runsc`. The final binary must be a statically-linked
    pure Go binary.

*   Any files importing "unsafe" must have a name ending in `_unsafe.go`.

*   `core` may only depend on the following packages:

    *   Itself.
    *   Go standard library.
    *   `@org_golang_x_sys//unix:go_default_library` (Go import
        `golang.org/x/sys/unix`).
    *   `@org_golang_x_time//rate:go_default_library` (Go import
        `golang.org/x/time/rate`).
    *   `@com_github_google_btree//:go_default_library` (Go import
        `github.com/google/btree`).
    *   Generated Go protobuf packages.
    *   `@org_golang_google_protobuf//proto:go_default_library` (Go import
        `google.golang.org/protobuf`).

*   `runsc` may only depend on the following packages:

    *   All packages allowed for `core`.
    *   `@com_github_google_subcommands//:go_default_library` (Go import
        `github.com/google/subcommands`).
    *   `@com_github_opencontainers_runtime_spec//specs_go:go_default_library`
        (Go import `github.com/opencontainers/runtime-spec/specs_go`).

*   For performance reasons, `runsc boot` may not run the `netpoller` goroutine.

## Style

Go code follows Go Code Review Comments, Effective Go and the gVisor style guide
in `g3doc/style.md`. In particular:

*   Prefer early exits from loops and functions.
*   Name mutexes `mu` or `xxxMu` and do not export them. Declare a mutex as a
    sibling field before the fields it protects, and note on each protected
    field that the mutex protects it.
*   Don't declare mutexes as global variables; put them in a struct (an
    anonymous struct is fine).
*   If a mutex has ordering requirements, its declaration should have a comment
    that explains them or points to where they are documented.
*   Document entry conditions, such as a lock that must be held, in a
    `Preconditions:` comment block with one condition per line.
*   Explicitly ignore unused return values with `_`, except the result of
    `testing.T.Run`.
*   Format built-in types with their own verbs (for example, `%d` for integers)
    and other types with a `%v` variant, even if they implement `fmt.Stringer`.
    Use `%w` only for errors passed to `fmt.Errorf`.
*   Wrap comments at 80 columns, counting a tab as 2 columns.

## System call tests

The system call tests in `test/syscalls` are written in C++ with Google Test.

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
