---
description: >
  Add or extend a Linux syscall in gvisor. Handles two cases:
  (1) Adding a brand-new syscall that currently returns ENOSYS or is missing from the table.
  (2) Adding missing flags/options to an existing partially-supported syscall (e.g., a new prctl option, ioctl command, or socket option).
  Use when asked to implement a syscall, add a flag, or improve compatibility for a specific syscall.
argument-hint: <syscall-name-or-flag>
arguments: [target]
allowed-tools:
  - Bash
  - Read
  - Edit
  - Write
  - Grep
  - Glob
  - WebSearch
  - WebFetch
  - Agent
---

# Add or extend syscall: `$target`

You are adding or extending Linux syscall support in gvisor. The target is:
**$target**

## Phase 1: Understand the current state

1.  **Check the syscall table** — search `pkg/sentry/syscalls/linux/linux64.go`
    for the syscall name. Determine:

    -   Is it registered? (has a table entry)
    -   What is its support level? (`Supported`, `PartiallySupported`,
        `ErrorWithEvent`, `Error`)
    -   What handler function is it mapped to?

2.  **Read the existing implementation** (if any) — find the handler in
    `pkg/sentry/syscalls/linux/sys_*.go`. Look for:

    -   Which flags/options are already handled
    -   Which flags fall through to `default:` / return `EINVAL` / `ENOSYS`
    -   The function signature pattern: `func Name(t *kernel.Task, sysno
        uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl,
        error)`

3.  **Check existing ABI constants** — look in `pkg/abi/linux/` for the relevant
    constants file (e.g., `prctl.go`, `ioctl.go`, `socket.go`)

4.  **Read the Linux man page / kernel source** — use WebSearch or WebFetch to
    look up the exact Linux behavior for the syscall or flag. This is critical
    for correctness. Search for the man page (e.g., `man 2 prctl`) and/or
    relevant kernel source.

## Phase 2: Plan the changes

Present the user a summary before writing code:

-   What the target syscall/flag does in Linux
-   What changes are needed in gvisor (list files)
-   Any kernel subsystems that need new support (e.g., new task fields, VFS
    operations)
-   Whether this can be a simple implementation or needs deeper infrastructure

Wait for user confirmation before proceeding.

## Phase 3: Implement

Follow this checklist — not all steps apply to every change:

### A. ABI Constants (`pkg/abi/linux/`)

-   Add any missing constants to the appropriate file
-   Follow the existing naming convention (e.g., `PR_` prefix for prctl,
    `CLONE_` for clone flags)
-   Add a one-line comment matching the Linux kernel comment style: `// PR_FOO
    does bar.`
-   If adding a new struct, use `pkg/marshal` for user-space copying

### B. Syscall Implementation (`pkg/sentry/syscalls/linux/sys_*.go`)

-   **New syscall**: Create `sys_<name>.go` with the handler function. Follow
    the standard signature:

    ```go
    func SyscallName(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
    ```

-   **New flag on existing syscall**: Add a `case` to the existing switch
    statement

-   Use `linuxerr` package for errors (e.g., `linuxerr.EINVAL`,
    `linuxerr.EPERM`)

-   Use `t.CopyIn*` / `t.CopyOut*` or `primitive.Copy*` for userspace memory
    access

-   Use `hostarch.Addr` for user pointers: `args[N].Pointer()`

-   Use `args[N].Int()`, `args[N].Uint()`, `args[N].Uint64()` for scalar
    arguments

### C. Syscall Table (`pkg/sentry/syscalls/linux/linux64.go`)

-   **New syscall**: Change from `syscalls.ErrorWithEvent(...)` or
    `syscalls.Error(...)` to `syscalls.Supported("name", HandlerFunc)` or
    `syscalls.PartiallySupported("name", HandlerFunc, "note about limitations",
    nil)`
-   **Improved existing**: Update `PartiallySupported` note to reflect newly
    supported options, or upgrade to `Supported` if fully implemented
-   The table has entries for both AMD64 and ARM64 — update both if the syscall
    applies to both architectures

### D. BUILD files

-   Add new `.go` files to `srcs` in `pkg/sentry/syscalls/linux/BUILD`
-   Add any new package dependencies to `deps`
-   Add new ABI files to `pkg/abi/linux/BUILD` if created

### E. Kernel/Sentry Support (if needed)

-   New task-level state → `pkg/sentry/kernel/task.go` or related
-   New filesystem operations → `pkg/sentry/vfs/` or `pkg/sentry/fsimpl/`
-   New network features → `pkg/tcpip/`

### F. Tests (`test/syscalls/linux/`)

-   Add or extend C++ tests in `test/syscalls/linux/<syscall>.cc`
-   Use the gtest framework with gvisor's test utilities:
    -   `SyscallSucceeds()`, `SyscallFailsWithErrno(EINVAL)`, etc. from
        `test/util/test_util.h`
    -   `ASSERT_NO_ERRNO_AND_VALUE()` for operations that return PosixErrorOr
-   Add test to `test/syscalls/linux/BUILD` if it's a new file
-   Test both the happy path and error cases

## Phase 4: Test-driven verification against native Linux

The test MUST pass on native Linux first. This ensures the test itself is
correct before running it inside gvisor. Native test targets run the C++ test
binary directly on the host kernel.

### Step 1: Run the native test

The native test target naming convention is:

```
bazel test //test/syscalls:<syscall>_test_native
```

For example:

```
bazel test //test/syscalls:access_test_native
bazel test //test/syscalls:prctl_test_native
bazel test //test/syscalls:eventfd_test_native
```

The native target is auto-generated by the `syscall_test()` macro in
`test/syscalls/BUILD` from the `cc_binary` in `test/syscalls/linux/BUILD`. It
runs with `--platform=native` (directly on the host kernel, no gvisor sandbox).

**Run the native test FIRST and iterate until it passes.** If the native test
fails, the test itself is buggy — fix the test before touching the gvisor
implementation.

```bash
bazel test //test/syscalls:<syscall>_test_native --test_output=errors
```

To run a specific test case:

```bash
bazel test //test/syscalls:<syscall>_test_native --test_output=errors --test_arg=--gtest_filter='TestSuite.TestCase'
```

### Step 2: Build the gvisor implementation

After the native test passes, verify the gvisor code compiles:

```bash
bazel build //pkg/sentry/syscalls/linux/...
```

If ABI constants changed:

```bash
bazel build //pkg/abi/linux/...
```

### Step 3: Run the gvisor (runsc) test

After the native test passes and the gvisor implementation compiles, run the
test under gvisor to verify the implementation is correct:

```bash
bazel test //test/syscalls:<syscall>_test_runsc_ptrace_shared --test_output=errors
```

This test MUST pass. If it fails, the gvisor implementation has a bug — fix the
implementation and re-run until it passes.

### Iterative workflow

The expected loop is:

1.  Write/update the C++ test in `test/syscalls/linux/<syscall>.cc`
2.  Run `bazel test //test/syscalls:<syscall>_test_native --test_output=errors`
3.  If it fails → fix the test (it's a bug in the test, not Linux)
4.  Once native passes → implement/update the gvisor handler
5.  Build gvisor: `bazel build //pkg/sentry/syscalls/linux/...`
6.  Run `bazel test //test/syscalls:<syscall>_test_runsc_ptrace_shared
    --test_output=errors`
7.  If it fails → fix the gvisor implementation and repeat from step 5

## Key patterns to follow

### Error handling

```go
// Return Linux error codes from linuxerr package
return 0, nil, linuxerr.EINVAL
return 0, nil, linuxerr.EPERM
return 0, nil, linuxerr.ENOSYS
```

### Copying data to/from userspace

```go
// Copy a single int32 to userspace
_, err := primitive.CopyInt32Out(t, args[1].Pointer(), value)

// Copy a struct from userspace
var s SomeStruct
_, err := s.CopyIn(t, args[0].Pointer())

// Copy a string from userspace
name, err := t.CopyInString(addr, maxLen)
```

### Unimplemented options pattern

```go
// For options you deliberately don't implement, emit an event:
t.Kernel().EmitUnimplementedEvent(t, sysno)
return 0, nil, linuxerr.ENOSYS
```

### Credential checks

```go
creds := t.Credentials()
if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, creds.UserNamespace) {
    return 0, nil, linuxerr.EPERM
}
```

## Important notes

-   Match Linux behavior exactly — check the man page and kernel source for edge
    cases
-   gvisor does NOT have a real kernel, so some things (hardware access, kernel
    modules) cannot be implemented — stub them with appropriate errors
-   Always handle the `default:` case in switch statements
-   Use `t.Kernel().EmitUnimplementedEvent(t, sysno)` before returning ENOSYS
    for deliberate non-implementation — this enables tracking of missing
    features
-   Prefer returning errors over panicking
-   Consider both amd64 and arm64 when the syscall exists on both architectures
