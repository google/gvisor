// Copyright 2026 The gVisor Authors.
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

#include <errno.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<int> ReadProcHexNumber(std::string path) {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents(path));
  EXPECT_EQ(contents[contents.length() - 1], '\n');

  int num;
  if (!absl::SimpleHexAtoi(contents, &num)) {
    return PosixError(EINVAL, "invalid value: " + contents);
  }

  return num;
}

TEST(ProcPidCoredumpFilterTest, BasicRead) {
  auto const coredump_filter = ASSERT_NO_ERRNO_AND_VALUE(
      ReadProcHexNumber("/proc/self/coredump_filter"));
  EXPECT_GE(coredump_filter, 0);
}

TEST(ProcPidCoredumpFilterTest, BasicWrite) {
  constexpr int test_value = 7;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/coredump_filter", O_WRONLY));
  ASSERT_THAT(
      RetryEINTR(write)(fd.get(), std::to_string(test_value).c_str(), 1),
      SyscallSucceeds());

  auto const coredump_filter = ASSERT_NO_ERRNO_AND_VALUE(
      ReadProcHexNumber("/proc/self/coredump_filter"));
  EXPECT_EQ(coredump_filter, test_value);
}

TEST(ProcPidCoredumpFilterTest, WriteNullTerminatedString) {
  constexpr int test_value = 7;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/coredump_filter", O_WRONLY));
  ASSERT_THAT(
      RetryEINTR(write)(fd.get(), std::to_string(test_value).c_str(), 2),
      SyscallSucceeds());

  auto const coredump_filter = ASSERT_NO_ERRNO_AND_VALUE(
      ReadProcHexNumber("/proc/self/coredump_filter"));
  EXPECT_EQ(coredump_filter, test_value);
}

TEST(ProcPidCoredumpFilterTest, PreservedByFork) {
  constexpr int test_value = 4;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/coredump_filter", O_WRONLY));
  ASSERT_THAT(
      RetryEINTR(write)(fd.get(), std::to_string(test_value).c_str(), 1),
      SyscallSucceeds());

  int child;
  ASSERT_THAT(child = fork(), SyscallSucceeds());

  if (child == 0) {
    // In the child, the coredump_filter value should be preserved
    auto const coredump_filter =
        ReadProcHexNumber("/proc/self/coredump_filter").ValueOrDie();
    if (coredump_filter != test_value) {
      _exit(1);
    }

    _exit(0);
  }

  int status;
  EXPECT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(ProcPidCoredumpFilterTest, ParentUnaffected) {
  constexpr int parent_value = 100;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/coredump_filter", O_WRONLY));
  ASSERT_THAT(
      RetryEINTR(write)(fd.get(), std::to_string(parent_value).c_str(), 3),
      SyscallSucceeds());

  int child;
  ASSERT_THAT(child = fork(), SyscallSucceeds());

  if (child == 0) {
    constexpr int child_value = 10;
    int fd;
    TEST_PCHECK((fd = open("/proc/self/coredump_filter", O_WRONLY)) >= 0);
    TEST_PCHECK(RetryEINTR(write)(fd, std::to_string(child_value).c_str(), 2) >
                0);

    _exit(0);
  }

  int status;
  EXPECT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  // In the parent, the coredump filter should not have been affected by the
  // child setting it
  auto const coredump_filter = ASSERT_NO_ERRNO_AND_VALUE(
      ReadProcHexNumber("/proc/self/coredump_filter"));
  EXPECT_EQ(coredump_filter, parent_value);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
