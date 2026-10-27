---
name: gvisor-kernel-development
description: >
  Use when modifying gVisor application kernel behavior:
  adding a new system call, adding new flags to an existing
  system call, editing the syscall tests in `//test/syscalls`.
---

When modifying or expanding the way the gVisor kernel works, such as when
implementing a new system call, adding a new flag to an existing system call, or
modifying the way an existing system call works, you should generally follow
this approach:

1.  Repeat your understanding of this aspect of the Linux kernel functionality.
2.  If applicable, come up with a way to quickly test and exercise the relevant
    kernel functionality by using a shell command or a short Python script. For
    example, if asked to change the way the `stat(2)` system call works on a
    specific device file like `/dev/zero`, you can use `stat /dev/zero` as a
    representative command for which the output can guide your understanding of
    the way the kernel works. See the "Running a C program in gVisor" section
    below for how to run it. Syscall tests are also appropriate and excellent at
    establishing coverage of all the edge cases a syscall may have; during
    development, both are useful.
3.  Before you look at any gVisor code, start by establishing a black-box
    understanding of the current behavior of both Linux and gVisor for the
    representative command or script you have come up with. Use the tools
    available at your disposal to verify this.
4.  If asked to modify the behavior of a specific system call, look for existing
    syscall tests that cover this syscall. Read the syscall test file, and run
    it under both Linux and gVisor at least once to make sure it is starting
    from a good state to begin with.
5.  Only after you have done the above, start reading gVisor kernel source code.
    Do not stop at the first file you think is most likely to implement the
    functionality you want to implement; look for multiple such files and only
    settle on a decision once you are confident about your decision.
6.  Make code changes, running your representative command or script or syscall
    tests as often as necessary.

While Linux `man` pages are the ABI spec, they are also often wrong or
out-of-date, hence gVisor's use of black-box syscall tests to assert Linux
behavior.

### Running gVisor development workflows

#### Running a C program in gVisor

During development, to verify more complex syscall behavior in gVisor, it may be
useful to write a custom program in C that calls system calls directly, then to
compile it, and to run it in Linux and in gVisor.

To do so, generate a dependency-free C program, compile it with `gcc`, move it
to a temporary directory such as `/tmp` (important: gVisor cannot directly run
from special directories such as `bazel-bin` due to uninteresting permission
issues), then use `runsc`'s `do` helper as follows:

```
# Recompile and extract to a world-accessible directory:
$ make release-tarball DESTINATION=out/ && mkdir -p /tmp/gvisor && tar -C /tmp/gvisor -xf out/gvisor.tar.bz2

# Run:
$ /tmp/gvisor/runsc --rootless=true --network=none --debug-log=/dev/stderr --strace=true do /absolute/path/to/the/binary
```

This will run `/absolute/path/to/the/binary` inside gVisor, with debug logs and
the syscall trace (strace) output included. Don't forget to also run it under
Linux so that you can compare its behavior.

#### Running syscall tests

As gVisor is a kernel meant to replicate Linux-like behavior,
**application-observable kernel behavior is not tested with Go unit tests**, and
you should not add such tests for it. Go unit tests are only appropriate for
self-contained internals with no Linux behavior to compare against. Instead, the
gVisor kernel behavior is tested by "syscall tests", which are C++ test binaries
which can be run either in Linux and in gVisor. These syscall test binaries call
some system calls in the kernel they are run in (either Linux or gVisor), and
verify that the system call behaves in the same expected way.

These tests are defined in `//test/syscalls/linux` as `.cc`.

If you change or add a syscall test, you should first run it under Linux to make
sure that the syscall test works properly under Linux. A syscall test that fails
under Linux reflects a problem with the test itself, not a problem in gVisor. If
this happens, fix the syscall test C++ program itself. Example:

```
make syscall-tests TARGETS="//test/syscalls:signalfd_test_native"
```

Only **after** a syscall test works under Linux does it make sense to ever run
it under gVisor. A syscall test that succeeds under Linux but fails under gVisor
reflects a problem in gVisor itself. In this case, iterate on the gVisor kernel
code, and keep running the syscall test under gVisor until the syscall test
passes. Example to run `signalfd.cc` in both Linux and gVisor in one shot:

```
make syscall-tests TARGETS="//test/syscalls:signalfd_test_native //test/syscalls:signalfd_test_runsc_systrap_shared"
```
