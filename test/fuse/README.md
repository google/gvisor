# gVisor FUSE Test Suite

This is an integration test suite for fuse(4) filesystem. It runs under gVisor
sandbox container with FUSE function enabled.

This document describes the framework of FUSE integration test, how to use it,
and the guidelines that should be followed when adding new testing features.

## Integration Test Framework

By inheriting the `FuseTest` class defined in `linux/fuse_base.h`, every test
fixture can run in an environment with `mount_point_` mounted by a fake FUSE
server. It creates a `socketpair(2)` to send and receive control commands and
data between the client and the server. Because the FUSE server runs in the
background thread, gTest cannot catch its assertion failure immediately. Thus,
`TearDown()` function sends command to the FUSE server to check if all gTest
assertion in the server are successful and all requests and preset responses are
consumed.

## Communication Diagram

Diagram below describes how a testing thread communicates with the FUSE server
to achieve integration test.

For the following diagram, `>` means entering the function, `<` is leaving the
function, and `=` indicates sequentially entering and leaving. Not necessarily
follow exactly the below diagram due to the nature of a multi-threaded system,
however, it is still helpful to know when the client waits for the server to
complete a command and when the server awaits the next instruction.

```
|  Client (Testing Thread)            |  Server (FUSE Server Thread)
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
|    [testing main]                   |
|                                     |      >ServerFuseLoop()
|                                     |        [poll on socket and fd]
|    >SetServerResponse()             |
|      [write data to socket]         |
|      [wait server complete]         |
|                                     |        [socket event occurs]
|                                     |        >ServerHandleCommand()
|                                     |          >ServerReceiveResponse()
|                                     |            [read data from socket]
|                                     |            [save data to memory]
|                                     |          <ServerReceiveResponse()
|                                     |          =ServerCompleteWith()
|    <SetServerResponse()             |
|                                     |        <ServerHandleCommand()
|    >[Do fs operation]               |
|      [wait for fs response]         |
|                                     |        [fd event occurs]
|                                     |        >ServerProcessFuseRequest()
|                                     |          =[read fs request]
|                                     |          =[save fs request to memory]
|                                     |          =[write fs response]
|    <[Do fs operation]               |
|                                     |        <ServerProcessFuseRequest()
|                                     |
|    =[Test fs operation result]      |
|                                     |
|    >GetServerActualRequest()        |
|      [write data to socket]         |
|      [wait data from server]        |
|                                     |        [socket event occurs]
|                                     |        >ServerHandleCommand()
|                                     |          >ServerSendReceivedRequest()
|                                     |            [write data to socket]
|      [read data from socket]        |
|      [wait server complete]         |
|                                     |          <ServerSendReceivedRequest()
|                                     |          =ServerCompleteWith()
|    <GetServerActualRequest()        |
|                                     |        <ServerHandleCommand()
|                                     |
|    =[Test actual request]           |
|                                     |
|    >TearDown()                      |
|      ...                            |
|      >GetServerNumUnsentResponses() |
|        [write data to socket]       |
|        [wait server complete]       |
|                                     |        [socket event arrive]
|                                     |        >ServerHandleCommand()
|                                     |          >ServerSendData()
|                                     |            [write data to socket]
|                                     |          <ServerSendData()
|                                     |          =ServerCompleteWith()
|        [read data from socket]      |
|        [test if all succeeded]      |
|      <GetServerNumUnsentResponses() |
|                                     |        <ServerHandleCommand()
|      =UnmountFuse()                 |
|    <TearDown()                      |
|  <TEST_F()                          |
```

## Running the tests

For example, to run fuse test in `stat_test.cc`:

```bash
$ bazel test //test/fuse:stat_test_runsc_ptrace
```

Test all targets tagged with fuse:

```bash
$ bazel test //test/fuse/...
```

## Writing a new FUSE test

1.  Add test targets in `BUILD` and `linux/BUILD`.
2.  Inherit your test from `FuseTest` base class. It allows you to:
    -   Fork a fake FUSE server in background during each test setup.
    -   Create a pair of sockets for communication and provide utility
        functions.
    -   Stop FUSE server and check if error occurs in it after test completes.
3.  Build the expected opcode-response pairs of your FUSE operation.
4.  Call `SetServerResponse()` to preset the next expected opcode and response.
5.  Do real filesystem operations (FUSE is mounted at `mount_point_`).
6.  Check FUSE response and/or errors.
7.  Retrieve FUSE request by `GetServerActualRequest()`.
8.  Check if the request is as expected.

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

## Writing a new FuseTestCmd

A `FuseTestCmd` is a control protocol used in the communication between the
testing thread and the FUSE server. Such commands are sent from the testing
thread to the FUSE server to set up, control, or inspect the behavior of the
FUSE server in response to a sequence of FUSE requests.

The lifecycle of a command contains following steps:

1.  The testing thread sends a `FuseTestCmd` via socket and waits for
    completion.
2.  The FUSE server receives the command and does corresponding action.
3.  (Optional) The testing thread reads data from socket.
4.  The FUSE server sends a success indicator via socket after processing.
5.  The testing thread gets the success signal and continues testing.

The success indicator, i.e. `WaitServerComplete()`, is crucial at the end of
each `FuseTestCmd` sent from the testing thread. Because we don't want to begin
filesystem operation if the requests have not been completely set up. Also, to
test FUSE interactions in a sequential manner, concurrent requests are not
supported now.

To add a new `FuseTestCmd`, one must comply with following format:

1.  Add a new `FuseTestCmd` enum class item defined in `linux/fuse_base.h`
2.  Add a `SetServerXXX()` or `GetServerXXX()` public function in `FuseTest`.
    This is how the testing thread will call to send control message. Define how
    many bytes you want to send along with the command and what you will expect
    to receive. Finally it should block and wait for a success indicator from
    the FUSE server.
3.  Add a handler logic in the switch condition of `ServerHandleCommand()`. Use
    `ServerSendData()` or declare a new private function such as
    `ServerReceiveXXX()` or `ServerSendXXX()`. It is mandatory to set it private
    since only the FUSE server (forked from `FuseTest` base class) can call it.
    This is the server part of the specific `FuseTestCmd` and the format of the
    data should be consistent with what the client expects in the previous step.
