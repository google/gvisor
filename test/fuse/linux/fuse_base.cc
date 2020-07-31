// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "fuse_base.h"

#include <fcntl.h>
#include <linux/fuse.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <iostream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void FuseTest::SetUp() {
  MountFuse();
  SetUpFuseServer();
}

void FuseTest::TearDown() {
  EnsureServerSuccess();
  UnmountFuse();
}

// Sends 3 parts of data to the FUSE server:
//   1. The `kSetResponse` command
//   2. The expected opcode
//   3. The fake FUSE response
// Then waits for the FUSE server notifies its completion.
void FuseTest::SetServerResponse(uint32_t opcode, struct iovec* iov_out,
                                 int iov_out_cnt) {
  FuseTestCmd cmd = kSetResponse;
  EXPECT_THAT(RetryEINTR(write)(sock_[0], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  EXPECT_THAT(RetryEINTR(write)(sock_[0], &opcode, sizeof(opcode)),
              SyscallSucceedsWithValue(sizeof(opcode)));

  EXPECT_THAT(RetryEINTR(writev)(sock_[0], iov_out, iov_out_cnt),
              SyscallSucceedsWithValue(::testing::Gt(0)));

  WaitServerComplete();
}

// Sends the `kGetSuccess` command to the FUSE server, then reads the success
// indicator from server.
void FuseTest::EnsureServerSuccess() {
  FuseTestCmd cmd = kGetSuccess;
  EXPECT_THAT(RetryEINTR(write)(sock_[0], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  char success;
  EXPECT_THAT(read(sock_[0], &success, sizeof(success)),
              SyscallSucceedsWithValue(::testing::Gt(0)));
  ASSERT_EQ(success, 1);

  WaitServerComplete();
}

// Sends the `kGetRequest` command to the FUSE server, then reads the next
// request into iovec struct. The order of calling this function should be
// the same as SetServerResponse().
void FuseTest::GetServerActualRequest(struct iovec* iov_in, int iov_in_cnt) {
  FuseTestCmd cmd = kGetRequest;
  EXPECT_THAT(RetryEINTR(write)(sock_[0], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  EXPECT_THAT(readv(sock_[0], iov_in, iov_in_cnt),
              SyscallSucceedsWithValue(::testing::Gt(0)));

  WaitServerComplete();
}

// Sends the `kGetTotalReceivedBytes` command to the FUSE server, reads from
// the socket, and returns.
uint32_t FuseTest::GetServerTotalReceivedBytes() {
  uint32_t bytes;
  FuseTestCmd cmd = kGetTotalReceivedBytes;
  EXPECT_THAT(RetryEINTR(write)(sock_[0], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  EXPECT_THAT(read(sock_[0], &bytes, sizeof(bytes)),
              SyscallSucceedsWithValue(sizeof(bytes)));

  WaitServerComplete();
  return bytes;
}

void FuseTest::MountFuse() {
  EXPECT_THAT(dev_fd_ = open("/dev/fuse", O_RDWR), SyscallSucceeds());

  std::string mount_opts = absl::StrFormat("fd=%d,%s", dev_fd_, kMountOpts);
  EXPECT_THAT(mount("fuse", kMountPoint, "fuse", MS_NODEV | MS_NOSUID,
                    mount_opts.c_str()),
              SyscallSucceedsWithValue(0));
}

void FuseTest::UnmountFuse() {
  EXPECT_THAT(umount(kMountPoint), SyscallSucceeds());
  // TODO(gvisor.dev/issue/3330): ensure the process is terminated successfully.
}

// SetUpFuseServer creates 1 socketpair and fork the process. The parent thread
// becomes testing thread and the child thread becomes the FUSE server running
// in background. These 2 threads are connected via socketpair. sock_[0] is
// opened in testing thread and sock_[1] is opened in the FUSE server.
void FuseTest::SetUpFuseServer() {
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_),
              SyscallSucceedsWithValue(0));

  switch (fork()) {
    case -1:
      GTEST_FAIL();
      return;
    case 0:
      break;
    default:
      ASSERT_THAT(close(sock_[1]), SyscallSucceedsWithValue(0));
      WaitServerComplete();
      return;
  }

  // Begin child thread, i.e. the FUSE server.
  ASSERT_THAT(close(sock_[0]), SyscallSucceedsWithValue(0));
  ServerCompleteWith(ServerConsumeFuseInit().ok());
  ServerFuseLoop();
  _exit(0);
}

// ServerFuseLoop is the implementation of the fake FUSE server. Monitors 2
// file descriptors: /dev/fuse and sock_[1]. Events from /dev/fuse are FUSE
// requests and events from sock_[1] are FUSE testing commands, leading by
// a FuseTestCmd data to indicate the command.
void FuseTest::ServerFuseLoop() {
  const int nfds = 2;
  struct pollfd fds[nfds] = {
      {
          .fd = dev_fd_,
          .events = POLL_IN | POLLHUP | POLLERR | POLLNVAL,
      },
      {
          .fd = sock_[1],
          .events = POLL_IN | POLLHUP | POLLERR | POLLNVAL,
      },
  };

  while (true) {
    EXPECT_THAT(poll(fds, nfds, -1),
                SyscallSucceedsWithValue(::testing::Gt(0)));

    for (int fd_idx = 0; fd_idx < nfds; ++fd_idx) {
      if (fds[fd_idx].revents == 0) continue;

      EXPECT_EQ(fds[fd_idx].revents, POLL_IN);
      if (fds[fd_idx].fd == sock_[1]) {
        ServerHandleCommand();
      } else if (fds[fd_idx].fd == dev_fd_) {
        ServerProcessFUSERequest();
      }
    }
  }
}

// Writes 1 byte of success indicator through socket.
void FuseTest::ServerCompleteWith(bool success) {
  char data = success ? 1 : 0;
  EXPECT_THAT(RetryEINTR(write)(sock_[1], &data, sizeof(data)),
              SyscallSucceedsWithValue(1));
}

// Waits for the FUSE server to finish its blocking job and check if it
// completes without errors.
void FuseTest::WaitServerComplete() {
  char success;
  EXPECT_THAT(RetryEINTR(read)(sock_[0], &success, sizeof(success)),
              SyscallSucceedsWithValue(1));
  ASSERT_EQ(success, 1);
}

// Consumes the first FUSE request and returns the corresponding PosixError.
PosixError FuseTest::ServerConsumeFuseInit() {
  std::vector<char> buf(FUSE_MIN_READ_BUFFER);
  RETURN_ERROR_IF_SYSCALL_FAIL(
      RetryEINTR(read)(dev_fd_, buf.data(), buf.size()));

  struct iovec iov_out[2];
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_init_out),
      .error = 0,
      .unique = 2,  // The first FUSE request has unique = 2.
  };
  // Returns an empty init out payload since this is just a test.
  struct fuse_init_out out_payload;
  SET_IOVEC_WITH_HEADER_PAYLOAD(iov_out, out_header, out_payload);

  RETURN_ERROR_IF_SYSCALL_FAIL(RetryEINTR(writev)(dev_fd_, iov_out, 2));
  return NoError();
}

// Reads FuseTestCmd sent from testing thread and routes to correct handler.
// Since each command should be a blocking operation, a `ServerCompleteWith()`
// is required after the switch keyword.
void FuseTest::ServerHandleCommand() {
  FuseTestCmd cmd;
  EXPECT_THAT(RetryEINTR(read)(sock_[1], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  switch (cmd) {
    case kSetResponse:
      ServerReceiveResponse();
      break;
    case kGetSuccess:
      ServerSendSuccess();
      break;
    case kGetRequest:
      ServerSendReceivedRequest();
      break;
    case kGetTotalReceivedBytes:
      ServerSendTotalReceivedBytes();
      break;
    default:
      FAIL() << "Unknown FuseTestCmd " << cmd;
      break;
  }

  ServerCompleteWith(!HasFailure());
}

// Reads 1 expected opcode and a fake response from socket and save them into
// the serail buffer of this testing instance.
void FuseTest::ServerReceiveResponse() {
  ssize_t len;
  uint32_t opcode;
  EXPECT_THAT(RetryEINTR(read)(sock_[1], &opcode, sizeof(opcode)),
              SyscallSucceedsWithValue(sizeof(opcode)));

  EXPECT_THAT(len = RetryEINTR(read)(sock_[1], responses_.DataAtTail(),
                                     responses_.AvailBytes()),
              SyscallSucceedsWithValue(::testing::Gt(0)));

  responses_.AddMemBlock(opcode, len);
}

// Sends the received request pointed by current cursor and increase cursor.
void FuseTest::ServerSendReceivedRequest() {
  if (requests_.End()) {
    FAIL() << "No more received request.";
    return;
  }
  auto mem_block = requests_.Next();
  EXPECT_THAT(
      RetryEINTR(write)(sock_[1], requests_.DataAtOffset(mem_block.offset),
                        mem_block.len),
      SyscallSucceedsWithValue(mem_block.len));
}

// Checks if there is any error during test and sends to the socket. 0 is
// failure while 1 is success.
void FuseTest::ServerSendSuccess() {
  char data = HasFailure() ? 0 : 1;
  EXPECT_THAT(RetryEINTR(write)(sock_[1], &data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));
}

void FuseTest::ServerSendTotalReceivedBytes() {
  uint32_t received = static_cast<uint32_t>(requests_.UsedBytes());
  EXPECT_THAT(RetryEINTR(write)(sock_[1], &received, sizeof(received)),
              SyscallSucceedsWithValue(sizeof(received)));
}

// Handles FUSE request. Reads request from /dev/fuse, checks if it has the
// same opcode as expected, and responds with the saved fake FUSE response.
// The FUSE request is copied to the serial buffer and can be retrieved one-
// by-one by calling GetServerActualRequest from testing thread.
void FuseTest::ServerProcessFUSERequest() {
  ssize_t len;

  // Read FUSE request.
  EXPECT_THAT(len = RetryEINTR(read)(dev_fd_, requests_.DataAtTail(),
                                     requests_.AvailBytes()),
              SyscallSucceedsWithValue(::testing::Gt(0)));
  fuse_in_header* in_header =
      reinterpret_cast<fuse_in_header*>(requests_.DataAtTail());
  requests_.AddMemBlock(in_header->opcode, len);

  // Check if there is a corresponding response.
  if (responses_.End()) {
    GTEST_NONFATAL_FAILURE_("No more FUSE response is expected");
    ServerSendErrorResponse(in_header->unique);
    return;
  }
  auto mem_block = responses_.Next();
  if (in_header->opcode != mem_block.opcode) {
    EXPECT_EQ(in_header->opcode, mem_block.opcode);
    ServerSendErrorResponse(in_header->unique);
    return;
  }

  // Write FUSE response.
  fuse_out_header* out_header = reinterpret_cast<fuse_out_header*>(
      responses_.DataAtOffset(mem_block.offset));
  // Patch `unique` in fuse_out_header to avoid EINVAL caused by responding
  // with an unknown `unique`.
  out_header->unique = in_header->unique;
  EXPECT_THAT(RetryEINTR(write)(dev_fd_, out_header, mem_block.len),
              SyscallSucceedsWithValue(mem_block.len));
}

void FuseTest::ServerSendErrorResponse(uint64_t unique) {
  fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header),
      .error = ENOSYS,
      .unique = unique,
  };
  EXPECT_THAT(RetryEINTR(write)(dev_fd_, &out_header, sizeof(out_header)),
              SyscallSucceedsWithValue(sizeof(out_header)));
}

}  // namespace testing
}  // namespace gvisor
