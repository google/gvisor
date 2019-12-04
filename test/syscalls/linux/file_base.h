// Copyright 2018 The gVisor Authors.
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

#ifndef GVISOR_TEST_SYSCALLS_FILE_BASE_H_
#define GVISOR_TEST_SYSCALLS_FILE_BASE_H_

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

class FileTest : public ::testing::Test {
 public:
  void SetUp() override {
    test_pipe_[0] = -1;
    test_pipe_[1] = -1;

    test_file_name_ = NewTempAbsPath();
    test_file_fd_ = ASSERT_NO_ERRNO_AND_VALUE(
        Open(test_file_name_, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR));

    // FIXME(edahlgren): enable when mknod syscall is supported.
    // test_fifo_name_ = NewTempAbsPath();
    // ASSERT_THAT(mknod(test_fifo_name_.c_str()), S_IFIFO|0644, 0,
    //             SyscallSucceeds());
    // ASSERT_THAT(test_fifo_[1] = open(test_fifo_name_.c_str(),
    //                                             O_WRONLY),
    //             SyscallSucceeds());
    // ASSERT_THAT(test_fifo_[0] = open(test_fifo_name_.c_str(),
    //                                             O_RDONLY),
    //             SyscallSucceeds());

    ASSERT_THAT(pipe(test_pipe_), SyscallSucceeds());
    ASSERT_THAT(fcntl(test_pipe_[0], F_SETFL, O_NONBLOCK), SyscallSucceeds());
  }

  // CloseFile will allow the test to manually close the file descriptor.
  void CloseFile() { test_file_fd_.reset(); }

  // UnlinkFile will allow the test to manually unlink the file.
  void UnlinkFile() {
    if (!test_file_name_.empty()) {
      EXPECT_THAT(unlink(test_file_name_.c_str()), SyscallSucceeds());
      test_file_name_.clear();
    }
  }

  // ClosePipes will allow the test to manually close the pipes.
  void ClosePipes() {
    if (test_pipe_[0] > 0) {
      EXPECT_THAT(close(test_pipe_[0]), SyscallSucceeds());
    }

    if (test_pipe_[1] > 0) {
      EXPECT_THAT(close(test_pipe_[1]), SyscallSucceeds());
    }

    test_pipe_[0] = -1;
    test_pipe_[1] = -1;
  }

  void TearDown() override {
    CloseFile();
    UnlinkFile();
    ClosePipes();

    // FIXME(edahlgren): enable when mknod syscall is supported.
    // close(test_fifo_[0]);
    // close(test_fifo_[1]);
    // unlink(test_fifo_name_.c_str());
  }

  std::string test_file_name_;
  std::string test_fifo_name_;
  FileDescriptor test_file_fd_;

  int test_fifo_[2];
  int test_pipe_[2];
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_FILE_BASE_H_
