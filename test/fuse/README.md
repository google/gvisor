# gVisor FUSE Test Suite

This is an integration test suite for fuse(4) filesystem. It runs under both
gVisor and Linux, and ensures compatibility between the two. This test suite is
based on system calls test.

This document describes the framework of fuse integration test and the
guidelines that should be followed when adding new fuse tests.

## Integration Test Framework

Please refer to the figure below. `>` is entering the function, `<` is leaving
the function, and `=` indicates sequentially entering and leaving.

```
 |  Client (Test Main Process)         |  Server (FUSE Daemon)
 |                                     |
 |  >TEST_F()                          |
 |    >SetUp()                         |
 |      =MountFuse()                   |
 |      >SetUpFuseServer()             |
 |        [create communication pipes] |
 |        =fork()                      |        =fork()
 |        >WaitCompleted()             |
 |          [wait for MarkDone()]      |
 |                                     |        =ConsumeFuseInit()
 |                                     |        =MarkDone()
 |        <WaitCompleted()             |
 |      <SetUpFuseServer()             |
 |    <SetUp()                         |
 |    >SetExpected()                   |
 |      [construct expected reaction]  |
 |                                     |        >FuseLoop()
 |                                     |          >ReceiveExpected()
 |                                     |            [wait data from pipe]
 |      [write data to pipe]           |
 |      [wait for MarkDone()]          |
 |                                     |            [save data to memory]
 |                                     |            =MarkDone()
 |    <SetExpected()                   |
 |                                     |          <ReceiveExpected()
 |                                     |          >read()
 |                                     |            [wait for fs operation]
 |    >[Do fs operation]               |
 |      [wait for fs response]         |
 |                                     |          <read()
 |                                     |          =CompareRequest()
 |                                     |          =write() [write fs response]
 |    <[Do fs operation]               |
 |    =[Test fs operation result]      |
 |    =[wait for MarkDone()]           |
 |                                     |          =MarkDone()
 |    >TearDown()                      |
 |      =UnmountFuse()                 |
 |    <TearDown()                      |
 |  <TEST_F()                          |
```

## Running the tests

Based on syscall tests, fuse tests can run in different environments. To enable
fuse testing environment, the test targets should be appended with `_fuse`.

For example, to run fuse test in `stat_test.cc`:

```bash
$ bazel test //test/fuse:stat_test_runsc_ptrace_vfs2_fuse
```

Test all targets tagged with fuse:

```bash
$ bazel test --test_tag_filters=fuse //test/fuse/...
```

## Writing a new FUSE test

1. Add test targets in `BUILD` and `linux/BUILD`.
2. Inherit your test from `FuseTest` base class. It allows you to:
  - Run a fake FUSE server in background during each test setup.
  - Create pipes for communication and provide utility functions.
  - Stop FUSE server after test completes.
3. Customize your comparison function for request assessment in FUSE server.
4. Add the mapping of the size of structs if you are working on new FUSE opcode.
  - Please update `FuseTest::GetPayloadSize()` for each new FUSE opcode.
5. Build the expected request-response pair of your FUSE operation.
6. Call `SetExpected()` function to inject the expected reaction.
7. Check the response and/or errors.
8. Finally call `WaitCompleted()` to ensure the FUSE server acts correctly.

A few customized matchers used in syscalls test are encouraged to test the
outcome of filesystem operations. Such as:

```cc
SyscallSucceeds()
SyscallSucceedsWithValue(...)
SyscallFails()
SyscallFailsWithErrno(...)
```

Please refer to [test/syscalls/README.md](../syscalls/README.md) for further
details.
