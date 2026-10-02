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

Each test file generates test targets that run in different
environments:

*   a `native` target that runs directly on the host machine
*   a `runsc_systrap` target that runs inside runsc using the systrap platform
*   a `runsc_ptrace` target that runs inside runsc using the ptrace platform
*   a `runsc_kvm` target that runs inside runsc using the KVM platform.

For example, the test in `access_test.cc` generates the following targets:

*   `//test/syscalls:access_test_native`
*   `//test/syscalls:access_test_runsc_systrap`
*   `//test/syscalls:access_test_runsc_ptrace`
*   `//test/syscalls:access_test_runsc_kvm`

Any of these targets can be run directly via `bazel test`.

```bash
$ bazel test //test/syscalls:access_test_native
$ bazel test //test/syscalls:access_test_runsc_systrap
$ bazel test //test/syscalls:access_test_runsc_ptrace
$ bazel test //test/syscalls:access_test_runsc_kvm
```

To run all the tests on a particular platform, you can filter by the platform
tag:

```bash
# Run all tests in native environment:
$ bazel test --test_tag_filters=native //test/syscalls/...

# Run all tests in runsc with systrap:
$ bazel test --test_tag_filters=runsc_systrap //test/syscalls/...

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

## Linux versions tested in CI

The [public CI pipeline][syscall-jobs] routinely exercises system call tests on
these Linux kernels:

| CI environment                | Kernel                                    | Architectures                      |
| ----------------------------- | ----------------------------------------- | ---------------------------------- |
| Ordinary syscall tests        | Linux 6.8 (`6.8.0-1069-gcp`)              | AMD64 ([1], [2]); ARM64 ([3], [4]) |
| Release-candidate Linux tests | Linux 7.3-rc3 (`7.3.0-070300rc3-generic`) | AMD64 ([5], [6]); ARM64 ([7], [8]) |

This inventory reflects the October 2, 2026 workers in public master builds
[49266](https://buildkite.com/gvisor/pipeline/builds/49266) and
[49276](https://buildkite.com/gvisor/pipeline/builds/49276).

The [ordinary and release-candidate jobs][syscall-jobs] use
[architecture-specific target filters][syscall-filters]: AMD64 selects both
native Linux and gVisor targets; ARM64 selects the gVisor ptrace and systrap
targets, without native Linux targets. The release-candidate version changes
as those worker pools are updated.

The [ARM64 64K-page job][arm64-64k-job] selects systrap targets with
`--define=pagesize=64k`. Its worker kernel release is not established by the
observations above.

[syscall-jobs]: https://github.com/google/gvisor/blob/e1bc74024/.buildkite/pipeline.yaml#L408-L453
[syscall-filters]: https://github.com/google/gvisor/blob/e1bc74024/.bazelrc#L44-L45
[arm64-64k-job]: https://github.com/google/gvisor/blob/e1bc74024/.buildkite/pipeline.yaml#L427-L434
[1]: https://buildkite.com/gvisor/pipeline/builds/49266#01a0fdf6-5027-4e74-b5db-36a03b4db470
[2]: https://buildkite.com/gvisor/pipeline/builds/49276#01a0fe40-cc6e-45a1-bedd-adb100343a73
[3]: https://buildkite.com/gvisor/pipeline/builds/49266#01a0fdf6-5029-4af5-8e2b-d5141aa27c07
[4]: https://buildkite.com/gvisor/pipeline/builds/49276#01a0fe40-cc73-4123-956e-c626b6cf3801
[5]: https://buildkite.com/gvisor/pipeline/builds/49266#01a0fdf6-502c-432b-b0c8-b980431e5bdd
[6]: https://buildkite.com/gvisor/pipeline/builds/49276#01a0fe40-cc76-421b-87d6-2a9b7a822016
[7]: https://buildkite.com/gvisor/pipeline/builds/49266#01a0fdf6-5033-4a4d-b356-82b2e0dc4a9b
[8]: https://buildkite.com/gvisor/pipeline/builds/49276#01a0fe40-cc7f-4ef8-8bcd-7beac4b41f16

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

The test utilities are written as RAII classes. These utilities should be
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
save/restore, so these functions and annotations have no effect on the tests. We
plan on extending the test runner to trigger save/restore. Until then, these
functions and annotations should be ignored.

[googletest]: https://github.com/abseil/googletest
