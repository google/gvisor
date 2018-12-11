# gVisor system call test suite

This is a test suite for Linux system calls. It runs under both gVisor and
Linux, and ensures compatibility between the two.

When adding support for a new syscall (or syscall argument) to gVisor, a
corresponding syscall test should be added. It's usually recommended to write
the test first and make sure that it passes on Linux before making changes to
gVisor.

This document outlines the general guidelines for tests and specific rules that
must be followed for new tests.

## Running the tests

Each test file generates three different test targets that run in different
environments:

* a `native` target that runs directly on the host machine,
* a `runsc_ptrace` target that runs inside runsc using the ptrace platform, and
* a `runsc_kvm` target that runs inside runsc using the KVM platform.

For example, the test in `access_test.cc` generates the following targets:

* `//test/syscalls:access_test_native`
* `//test/syscalls:access_test_runsc_ptrace`
* `//test/syscalls:access_test_runsc_kvm`

Any of these targets can be run directly via `bazel test`.

```bash
$ bazel test //test/syscalls:access_test_native
$ bazel test //test/syscalls:access_test_runsc_ptrace
$ bazel test //test/syscalls:access_test_runsc_kvm
```

To run all the tests on a particular platform, you can filter by the platform
tag:

```bash
# Run all tests in native environment:
$ bazel test --test_tag_filters=native //test/syscalls/...

# Run all tests in runsc with ptrace:
$ bazel test --test_tag_filters=runsc_ptrace //test/syscalls/...

# Run all tests in runsc with kvm:
$ bazel test --test_tag_filters=runsc_kvm //test/syscalls/...
```

You can also run all the tests on every platform. (Warning, this may take a
while to run.)

```bash
# Run all tests on every platform:
$ bazel test //test/syscalls/...
```

## Writing new tests

Whenever we add support for a new syscall, or add support for a new argument or
option for a syscall, we should always add a new test (perhaps many new tests).

In general, it is best to write the test first and make sure it passes on Linux
by running the test on the `native` platform on a Linux machine. This ensures
that the gVisor implementation matches actual Linux behavior. Sometimes man
pages contain errors, so always check the actual Linux behavior.

gVisor uses the [Google Test][googletest] test framework, with a few custom
matchers and guidelines, described below.

### Syscall matchers

When testing an individual system call, use the following syscall matchers,
which will match the value returned by the syscall and the errno.

```cc
SyscallSucceeds()
SyscallSucceedsWithValue(...)
SyscallFails()
SyscallFailsWithErrno(...)
```

### Use test utilities (RAII classes)

The test utilties are written as RAII classes. These utilities should be
preferred over custom test harnesses.

Local class instances should be preferred, wherever possible, over full test
fixtures.

A test utility should be created when there is more than one test that requires
that same functionality, otherwise the class should be test local.


## Save/Restore support in tests
gVisor supports save/restore, and our syscall tests are written in a way to
enable saving/restoring at certain points. Hence, there are calls to
`MaybeSave`, and certain tests that should not trigger saves are named with
`NoSave`.

However, the current open-source test runner does not yet support triggering
save/restore, so these functions and annotations have no effect on the
open-source tests.

We plan on extending our open-source test runner to trigger save/restore. Until
then, these functions and annotations should be ignored.


[googletest]: https://github.com/abseil/googletest
