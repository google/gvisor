// Copyright 2022 The gVisor Authors.
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

#include <asm-generic/errno-base.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#ifndef SYS_close_range
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_close_range 436
#else
#error "Unknown architecture"
#endif
#endif  // SYS_close_range

int close_range(unsigned int first, unsigned int last, unsigned int flags) {
  return syscall(SYS_close_range, first, last, flags);
}

class CloseRangeTest : public ::testing::Test {
 public:
  void CreateFiles(int num_files) {
    file_names_.reserve(num_files);
    for (int i = 0; i < num_files; ++i) {
      file_names_.push_back(NewTempAbsPath());
      int fd;
      ASSERT_THAT(fd = open(file_names_[i].c_str(), O_CREAT, 0644),
                  SyscallSucceeds());
      ASSERT_THAT(close(fd), SyscallSucceeds());
    }
  }

  void OpenFilesRdwr() {
    fds_.clear();
    fds_.reserve(file_names_.size());
    for (std::string &file_name : file_names_) {
      int fd;
      ASSERT_THAT(fd = open(file_name.c_str(), O_RDWR), SyscallSucceeds());
      fds_.push_back(fd);
    }
  }

 private:
  void TearDown() override {
    for (std::string &name : file_names_) {
      unlink(name.c_str());
    }
  }

 protected:
  std::vector<std::string> file_names_;
  std::vector<unsigned int> fds_;
};

// Base test to confirm that all files in contiguous range get closed.
TEST_F(CloseRangeTest, ContiguousRange) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = 0;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }
}

// Test to confirm that a range with files already closed in the range still
// closes the remaining files.
TEST_F(CloseRangeTest, RangeWithHoles) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = 0;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  EXPECT_THAT(close(fds_[2]), SyscallSucceeds());
  EXPECT_THAT(close(fds_[7]), SyscallSucceeds());

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }
}

// Test to confirm that closing a range with fds preceding and following the
// range leaves those other fds open.
TEST_F(CloseRangeTest, RangeInMiddleOfOpenFiles) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = 0;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  size_t slice_start = 4;
  size_t slice_end = 7;
  EXPECT_THAT(close_range(fds_[slice_start], fds_[slice_end], flags),
              SyscallSucceeds());
  for (int fd :
       std::vector(fds_.begin() + slice_start, fds_.begin() + slice_end + 1)) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }
  for (int fd : std::vector(fds_.begin(), fds_.begin() + slice_start)) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }
  for (int fd : std::vector(fds_.begin() + slice_end + 1, fds_.end())) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }
}

// Test to confirm that calling close_range on just one file succeeds.
TEST_F(CloseRangeTest, SingleFile) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 1;
  unsigned int flags = 0; /*  */

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  auto ret = ReadAllFd(fds_[0]);
  EXPECT_THAT(ret, IsPosixErrorOkMatcher());

  EXPECT_THAT(close_range(fds_[0], fds_[0], flags), SyscallSucceeds());

  ret = ReadAllFd(fds_[0]);
  EXPECT_THAT(ret, PosixErrorIs(EBADF));
}

// Test to confirm that calling close_range twice on the same range does not
// cause errors.
TEST_F(CloseRangeTest, CallCloseRangeTwice) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = 0;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
}

// Test that using CLOEXEC flag does not close the file for this process.
TEST_F(CloseRangeTest, CloexecFlagTest) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = CLOSE_RANGE_CLOEXEC;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }
}

// Test that using UNSHARE flag still properly closes the files.
TEST_F(CloseRangeTest, UnshareFlagTest) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = CLOSE_RANGE_UNSHARE;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }
}

// Test that using the UNSHARE flag and closing files at the start of the range
// still leaves the latter files opened.
TEST_F(CloseRangeTest, UnshareFlagAndCloseRangeAtStart) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = CLOSE_RANGE_UNSHARE;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  size_t range_split = 5;
  EXPECT_THAT(close_range(fds_[0], fds_[range_split - 1], flags),
              SyscallSucceeds());
  for (int fd : std::vector(fds_.begin(), fds_.begin() + range_split)) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }
  for (int fd : std::vector(fds_.begin() + range_split, fds_.end())) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }
}

// Test that using the UNSHARE flag and closing files at the end of the range
// still leaves the earlier files opened.
TEST_F(CloseRangeTest, UnshareFlagAndCloseRangeAtEnd) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = CLOSE_RANGE_UNSHARE;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  size_t range_split = 5;
  EXPECT_THAT(
      close_range(fds_[range_split], fds_[num_files_in_range - 1], flags),
      SyscallSucceeds());
  for (int fd : std::vector(fds_.begin(), fds_.begin() + range_split)) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }
  for (int fd : std::vector(fds_.begin() + range_split, fds_.end())) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, PosixErrorIs(EBADF));
  }
}

// Test that using both CLOEXEC and UNSHARE flags does not close files for this
// process.
TEST_F(CloseRangeTest, CloexecAndUnshareFlagTest) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }

  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallSucceeds());
  for (int fd : fds_) {
    auto ret = ReadAllFd(fd);
    EXPECT_THAT(ret, IsPosixErrorOkMatcher());
  }
}

// Test that calling with invalid range does not succeed.
TEST_F(CloseRangeTest, RangeFirstGreaterThanLast) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;
  unsigned int flags = 0;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  EXPECT_THAT(close_range(fds_[num_files_in_range - 1], fds_[0], flags),
              SyscallFailsWithErrno(EINVAL));
}

// Test that calling with invalid flags does not succeed.
TEST_F(CloseRangeTest, InvalidFlags) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  int num_files_in_range = 10;

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  unsigned int flags = CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE | 0xF;
  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallFailsWithErrno(EINVAL));

  flags = 0xF0;
  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallFailsWithErrno(EINVAL));

  flags = CLOSE_RANGE_CLOEXEC | 0xF00;
  EXPECT_THAT(close_range(fds_[0], fds_[num_files_in_range - 1], flags),
              SyscallFailsWithErrno(EINVAL));
}

// Test that calling close_range concurrently while creating new files yields
// expected results.
TEST_F(CloseRangeTest, ConcurrentCalls) {
  SKIP_IF(!IsRunningOnGvisor() && close_range(1, 0, 0) < 0 && errno == ENOSYS);
  const int num_files_in_range = 10;
  const unsigned int flags = CLOSE_RANGE_UNSHARE;
  const int num_threads = 100;
  std::unique_ptr<ScopedThread> threads[num_threads];

  CreateFiles(num_files_in_range);
  OpenFilesRdwr();

  auto cr_call = []() {
    EXPECT_THAT(close_range(num_files_in_range / 2,
                            num_files_in_range + num_threads, flags),
                SyscallSucceeds());
  };
  auto open_file_call = []() {
    auto file = NewTempAbsPath();
    EXPECT_THAT(open(file.c_str(), O_CREAT, 0644), SyscallSucceeds());
  };

  for (int i = 0; i < num_threads; i++) {
    if (i % 2 == 0) {
      threads[i] = std::make_unique<ScopedThread>(cr_call);
    } else {
      threads[i] = std::make_unique<ScopedThread>(open_file_call);
    }
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
