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

#include "test/fuse/linux/fuse_base.h"

#include <fcntl.h>
#include <linux/fuse.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "absl/strings/str_format.h"
#include "gtest/gtest.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void FuseTest::SetUp() {
  MountFuse();
  SetUpFuseServer();
}

void FuseTest::TearDown() { UnmountFuse(); }

// Sends 3 parts of data to the FUSE server:
//   1. The `kSetResponse` command
//   2. The expected opcode
//   3. The fake FUSE response
// Then waits for the FUSE server to notify its completion.
void FuseTest::SetServerResponse(uint32_t opcode,
                                 std::vector<struct iovec>& iovecs) {
  uint32_t cmd = static_cast<uint32_t>(FuseTestCmd::kSetResponse);
  EXPECT_THAT(RetryEINTR(write)(sock_[0], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  EXPECT_THAT(RetryEINTR(write)(sock_[0], &opcode, sizeof(opcode)),
              SyscallSucceedsWithValue(sizeof(opcode)));

  EXPECT_THAT(RetryEINTR(writev)(sock_[0], iovecs.data(), iovecs.size()),
              SyscallSucceeds());

  WaitServerComplete();
}

// Waits for the FUSE server to finish its blocking job and check if it
// completes without errors.
void FuseTest::WaitServerComplete() {
  char success;
  EXPECT_THAT(RetryEINTR(read)(sock_[0], &success, sizeof(success)),
              SyscallSucceedsWithValue(sizeof(success)));
  EXPECT_EQ(success, static_cast<char>(1));
}

// Sends the `kGetRequest` command to the FUSE server, then reads the next
// request into iovec struct. The order of calling this function should be
// the same as the one of SetServerResponse().
void FuseTest::GetServerActualRequest(std::vector<struct iovec>& iovecs) {
  uint32_t cmd = static_cast<uint32_t>(FuseTestCmd::kGetRequest);
  EXPECT_THAT(RetryEINTR(write)(sock_[0], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  EXPECT_THAT(RetryEINTR(readv)(sock_[0], iovecs.data(), iovecs.size()),
              SyscallSucceeds());

  WaitServerComplete();
}

void FuseTest::MountFuse() {
  EXPECT_THAT(dev_fd_ = open("/dev/fuse", O_RDWR), SyscallSucceeds());

  std::string mount_opts = absl::StrFormat("fd=%d,%s", dev_fd_, kMountOpts);
  mount_point_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("fuse", mount_point_.path().c_str(), "fuse",
                    MS_NODEV | MS_NOSUID, mount_opts.c_str()),
              SyscallSucceeds());
}

void FuseTest::UnmountFuse() {
  EXPECT_THAT(umount(mount_point_.path().c_str()), SyscallSucceeds());
  // TODO(gvisor.dev/issue/3330): ensure the process is terminated successfully.
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
      .unique = 2,
  };
  // Returns a fake fuse_init_out with 7.0 version to avoid ECONNREFUSED
  // error in the initialization of FUSE connection.
  struct fuse_init_out out_payload = {
      .major = 7,
  };
  iov_out[0].iov_len = sizeof(out_header);
  iov_out[0].iov_base = &out_header;
  iov_out[1].iov_len = sizeof(out_payload);
  iov_out[1].iov_base = &out_payload;

  RETURN_ERROR_IF_SYSCALL_FAIL(RetryEINTR(writev)(dev_fd_, iov_out, 2));
  return NoError();
}

// Reads 1 expected opcode and a fake response from socket and save them into
// the serial buffer of this testing instance.
void FuseTest::ServerReceiveResponse() {
  ssize_t len;
  uint32_t opcode;
  std::vector<char> buf(FUSE_MIN_READ_BUFFER);
  EXPECT_THAT(RetryEINTR(read)(sock_[1], &opcode, sizeof(opcode)),
              SyscallSucceedsWithValue(sizeof(opcode)));

  EXPECT_THAT(len = RetryEINTR(read)(sock_[1], buf.data(), buf.size()),
              SyscallSucceeds());

  responses_.AddMemBlock(opcode, buf.data(), len);
}

// Writes 1 byte of success indicator through socket.
void FuseTest::ServerCompleteWith(bool success) {
  char data = static_cast<char>(success);
  EXPECT_THAT(RetryEINTR(write)(sock_[1], &data, sizeof(data)),
              SyscallSucceedsWithValue(sizeof(data)));
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
    ASSERT_THAT(poll(fds, nfds, -1), SyscallSucceeds());

    for (int fd_idx = 0; fd_idx < nfds; ++fd_idx) {
      if (fds[fd_idx].revents == 0) continue;

      ASSERT_EQ(fds[fd_idx].revents, POLL_IN);
      if (fds[fd_idx].fd == sock_[1]) {
        ServerHandleCommand();
      } else if (fds[fd_idx].fd == dev_fd_) {
        ServerProcessFuseRequest();
      }
    }
  }
}

// SetUpFuseServer creates 1 socketpair and fork the process. The parent thread
// becomes testing thread and the child thread becomes the FUSE server running
// in background. These 2 threads are connected via socketpair. sock_[0] is
// opened in testing thread and sock_[1] is opened in the FUSE server.
void FuseTest::SetUpFuseServer() {
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_), SyscallSucceeds());

  switch (fork()) {
    case -1:
      GTEST_FAIL();
      return;
    case 0:
      break;
    default:
      ASSERT_THAT(close(sock_[1]), SyscallSucceeds());
      WaitServerComplete();
      return;
  }

  // Begin child thread, i.e. the FUSE server.
  ASSERT_THAT(close(sock_[0]), SyscallSucceeds());
  ServerCompleteWith(ServerConsumeFuseInit().ok());
  ServerFuseLoop();
  _exit(0);
}

// Reads FuseTestCmd sent from testing thread and routes to correct handler.
// Since each command should be a blocking operation, a `ServerCompleteWith()`
// is required after the switch keyword.
void FuseTest::ServerHandleCommand() {
  uint32_t cmd;
  EXPECT_THAT(RetryEINTR(read)(sock_[1], &cmd, sizeof(cmd)),
              SyscallSucceedsWithValue(sizeof(cmd)));

  switch (static_cast<FuseTestCmd>(cmd)) {
    case FuseTestCmd::kSetResponse:
      ServerReceiveResponse();
      break;
    case FuseTestCmd::kGetRequest:
      ServerSendReceivedRequest();
      break;
    default:
      FAIL() << "Unknown FuseTestCmd " << cmd;
      break;
  }

  ServerCompleteWith(!HasFailure());
}

// Sends the received request pointed by current cursor and advances cursor.
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

// Handles FUSE request. Reads request from /dev/fuse, checks if it has the
// same opcode as expected, and responds with the saved fake FUSE response.
// The FUSE request is copied to the serial buffer and can be retrieved one-
// by-one by calling GetServerActualRequest from testing thread.
void FuseTest::ServerProcessFuseRequest() {
  ssize_t len;
  std::vector<char> buf(FUSE_MIN_READ_BUFFER);

  // Read FUSE request.
  EXPECT_THAT(len = RetryEINTR(read)(dev_fd_, buf.data(), buf.size()),
              SyscallSucceeds());
  fuse_in_header* in_header = reinterpret_cast<fuse_in_header*>(buf.data());
  requests_.AddMemBlock(in_header->opcode, buf.data(), len);

  // Check if there is a corresponding response.
  if (responses_.End()) {
    GTEST_NONFATAL_FAILURE_("No more FUSE response is expected");
    ServerRespondFuseError(in_header->unique);
    return;
  }
  auto mem_block = responses_.Next();
  if (in_header->opcode != mem_block.opcode) {
    std::string message = absl::StrFormat("Expect opcode %d but got %d",
                                          mem_block.opcode, in_header->opcode);
    GTEST_NONFATAL_FAILURE_(message.c_str());
    // We won't get correct response if opcode is not expected. Send error
    // response here to avoid wrong parsing by VFS.
    ServerRespondFuseError(in_header->unique);
    return;
  }

  // Write FUSE response.
  ServerRespondFuseSuccess(responses_, mem_block, in_header->unique);
}

void FuseTest::ServerRespondFuseSuccess(FuseMemBuffer& mem_buf,
                                        const FuseMemBlock& block,
                                        uint64_t unique) {
  fuse_out_header* out_header =
      reinterpret_cast<fuse_out_header*>(mem_buf.DataAtOffset(block.offset));

  // Patch `unique` in fuse_out_header to avoid EINVAL caused by responding
  // with an unknown `unique`.
  out_header->unique = unique;
  EXPECT_THAT(RetryEINTR(write)(dev_fd_, out_header, block.len),
              SyscallSucceedsWithValue(block.len));
}

void FuseTest::ServerRespondFuseError(uint64_t unique) {
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
