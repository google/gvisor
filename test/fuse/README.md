# gVisor FUSE Test Suite

This is an integration test suite for fuse(4) filesystem. It runs under gVisor
sandbox container with VFS2 and FUSE function enabled.

This document describes the framework of FUSE integration test and the
guidelines that should be followed when adding new FUSE tests.

## Integration Test Framework

By inheriting the `FuseTest` class defined in `linux/fuse_base.h`, every test
fixture can runs in an environment with `kMountPoint` mounted by a fake FUSE
server. Below diagram describes how a testing thread communicates with the
FUSE server to achieve integration test.

For the following diagram, `>` is entering the function, `<` is leaving the
function, and `=` indicates sequentially entering and leaving.

```
 |  Client (Test Main Process)         |  Server (FUSE Daemon)
 |                                     |
 |  >TEST_F()                          |
 |    >SetUp()                         |
 |      =MountFuse()                   |
 |      >SetUpFuseServer()             |
 |        [create communication socket]|
 |        =fork()                      |      =fork()
 |        [wait server complete]       |
 |                                     |      =ServerConsumeFuseInit()
 |                                     |      =ServerCompleteWith()
 |      <SetUpFuseServer()             |
 |    <SetUp()                         |
 |    [Testing main]                   |
 |                                     |      >ServerFuseLoop()
 |                                     |        [poll on socket and fd]
 |    >SetServerResponse()             |
 |      [write data to socket]         |
 |      [wait server complete]         |
 |                                     |        [socket event arrive]
 |                                     |        >ServerHandleCommand()
 |                                     |          >ServerReceiveResponse()
 |                                     |            [read data from socket]
 |                                     |            [save data to memory]
 |                                     |          <ServerReceiveResponse()
 |                                     |          =ServerCompleteWith()
 |                                     |        <ServerHandleCommand()
 |    <SetServerResponse()             |
 |    >[Do fs operation]               |
 |      [wait for fs response]         |
 |                                     |        [fd event arrive]
 |                                     |        >ServerProcessFUSERequest()
 |                                     |          =[read fs request]
 |                                     |          =[save fs request to memory]
 |                                     |          =[write fs response]
 |    <[Do fs operation]               |
 |                                     |        <ServerProcessFUSERequest()
 |                                     |
 |    =[Test fs operation result]      |
 |                                     |
 |    >GetServerActualRequest()        |
 |      [write data to socket]         |
 |      [wait server complete]         |
 |                                     |        [socket event arrive]
 |                                     |        >ServerHandleCommand()
 |                                     |          >ServerSendReceivedRequest()
 |                                     |            [write data to socket]
 |                                     |          <ServerSendReceivedRequest()
 |                                     |          =ServerCompleteWith()
 |      [read data from socket]        |
 |                                     |        <ServerHandleCommand()
 |    <GetServerActualRequest()        |
 |                                     |
 |    =[Test actual request]           |
 |                                     |
 |    >TearDown()                      |
 |      >EnsureServerSuccess()         |
 |        [write data to socket]       |
 |        [wait server complete]       |
 |                                     |        [socket event arrive]
 |                                     |        >ServerHandleCommand()
 |                                     |          >ServerSendSuccess()
 |                                     |            [write data to socket]
 |                                     |          <ServerSendSuccess()
 |                                     |          =ServerCompleteWith()
 |        [read data from socket]      |
 |        [test if all succeeded]      |
 |      <EnsureServerSuccess()         |
 |                                     |        <ServerHandleCommand()
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
8. Finally call `WaitServerComplete()` to ensure the FUSE server acts correctly.

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
