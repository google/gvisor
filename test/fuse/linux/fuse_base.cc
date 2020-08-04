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
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <iostream>

#include "absl/strings/str_format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void FuseTest::SetUp() {
  MountFuse();
  SetUpFuseServer();
}

void FuseTest::TearDown() { UnmountFuse(); }

// Since CompareRequest is running in background thread, gTest assertions and
// expectations won't directly reflect the test result. However, the FUSE
// background server still connects to the same standard I/O as testing main
// thread. So EXPECT_XX can still be used to show different results. To
// ensure failed testing result is observable, return false and the result
// will be sent to test main thread via pipe.
bool FuseTest::CompareRequest(void* expected_mem, size_t expected_len,
                              void* real_mem, size_t real_len) {
  if (expected_len != real_len) return false;
  return memcmp(expected_mem, real_mem, expected_len) == 0;
}

// SetExpected is called by the testing main thread to set expected request-
// response pair of a single FUSE operation.
void FuseTest::SetExpected(struct iovec* iov_in, int iov_in_cnt,
                           struct iovec* iov_out, int iov_out_cnt) {
  EXPECT_THAT(RetryEINTR(writev)(set_expected_[1], iov_in, iov_in_cnt),
              SyscallSucceedsWithValue(::testing::Gt(0)));
  WaitCompleted();

  EXPECT_THAT(RetryEINTR(writev)(set_expected_[1], iov_out, iov_out_cnt),
              SyscallSucceedsWithValue(::testing::Gt(0)));
  WaitCompleted();
}

// WaitCompleted waits for the FUSE server to finish its job and check if it
// completes without errors.
void FuseTest::WaitCompleted() {
  char success;
  EXPECT_THAT(RetryEINTR(read)(done_[0], &success, sizeof(success)),
              SyscallSucceedsWithValue(1));
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

// ConsumeFuseInit consumes the first FUSE request and returns the
// corresponding PosixError.
PosixError FuseTest::ConsumeFuseInit() {
  RETURN_ERROR_IF_SYSCALL_FAIL(
      RetryEINTR(read)(dev_fd_, buf_.data(), buf_.size()));

  struct iovec iov_out[2];
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_init_out),
      .error = 0,
      .unique = 2,
  };
  // Returns an empty init out payload since this is just a test.
  struct fuse_init_out out_payload;
  iov_out[0].iov_len = sizeof(out_header);
  iov_out[0].iov_base = &out_header;
  iov_out[1].iov_len = sizeof(out_payload);
  iov_out[1].iov_base = &out_payload;

  RETURN_ERROR_IF_SYSCALL_FAIL(RetryEINTR(writev)(dev_fd_, iov_out, 2));
  return NoError();
}

// ReceiveExpected reads 1 pair of expected fuse request-response `iovec`s
// from pipe and save them into member variables of this testing instance.
void FuseTest::ReceiveExpected() {
  // Set expected fuse_in request.
  EXPECT_THAT(len_in_ = RetryEINTR(read)(set_expected_[0], mem_in_.data(),
                                         mem_in_.size()),
              SyscallSucceedsWithValue(::testing::Gt(0)));
  MarkDone(len_in_ > 0);

  // Set expected fuse_out response.
  EXPECT_THAT(len_out_ = RetryEINTR(read)(set_expected_[0], mem_out_.data(),
                                          mem_out_.size()),
              SyscallSucceedsWithValue(::testing::Gt(0)));
  MarkDone(len_out_ > 0);
}

// MarkDone writes 1 byte of success indicator through pipe.
void FuseTest::MarkDone(bool success) {
  char data = success ? 1 : 0;
  EXPECT_THAT(RetryEINTR(write)(done_[1], &data, sizeof(data)),
              SyscallSucceedsWithValue(1));
}

// FuseLoop is the implementation of the fake FUSE server. Read from /dev/fuse,
// compare the request by CompareRequest (use derived function if specified),
// and write the expected response to /dev/fuse.
void FuseTest::FuseLoop() {
  bool success = true;
  ssize_t len = 0;
  while (true) {
    ReceiveExpected();

    EXPECT_THAT(len = RetryEINTR(read)(dev_fd_, buf_.data(), buf_.size()),
                SyscallSucceedsWithValue(len_in_));
    if (len != len_in_) success = false;

    if (!CompareRequest(buf_.data(), len_in_, mem_in_.data(), len_in_)) {
      std::cerr << "the FUSE request is not expected" << std::endl;
      success = false;
    }

    EXPECT_THAT(len = RetryEINTR(write)(dev_fd_, mem_out_.data(), len_out_),
                SyscallSucceedsWithValue(len_out_));
    if (len != len_out_) success = false;
    MarkDone(success);
  }
}

// SetUpFuseServer creates 2 pipes. First is for testing client to send the
// expected request-response pair, and the other acts as a checkpoint for the
// FUSE server to notify the client that it can proceed.
void FuseTest::SetUpFuseServer() {
  ASSERT_THAT(pipe(set_expected_), SyscallSucceedsWithValue(0));
  ASSERT_THAT(pipe(done_), SyscallSucceedsWithValue(0));

  switch (fork()) {
    case -1:
      GTEST_FAIL();
      return;
    case 0:
      break;
    default:
      ASSERT_THAT(close(set_expected_[0]), SyscallSucceedsWithValue(0));
      ASSERT_THAT(close(done_[1]), SyscallSucceedsWithValue(0));
      WaitCompleted();
      return;
  }

  ASSERT_THAT(close(set_expected_[1]), SyscallSucceedsWithValue(0));
  ASSERT_THAT(close(done_[0]), SyscallSucceedsWithValue(0));

  MarkDone(ConsumeFuseInit().ok());

  FuseLoop();
  _exit(0);
}

// GetPayloadSize is a helper function to get the number of bytes of a
// specific FUSE operation struct.
size_t FuseTest::GetPayloadSize(uint32_t opcode, bool in) {
  switch (opcode) {
    case FUSE_INIT:
      return in ? sizeof(struct fuse_init_in) : sizeof(struct fuse_init_out);
    default:
      break;
  }
  return 0;
}

}  // namespace testing
}  // namespace gvisor
