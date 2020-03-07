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

#include <errno.h>

#include <exception>
#include <iostream>
#include <string>

#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<int> ReadProcNumber(std::string path) {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents(path));
  EXPECT_EQ(contents[contents.length() - 1], '\n');

  int num;
  if (!absl::SimpleAtoi(contents, &num)) {
    return PosixError(EINVAL, "invalid value: " + contents);
  }

  return num;
}

TEST(ProcPidOomscoreTest, BasicRead) {
  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));
  EXPECT_LE(oom_score, 1000);
  EXPECT_GE(oom_score, -1000);
}

TEST(ProcPidOomscoreAdjTest, BasicRead) {
  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score_adj"));

  // oom_score_adj defaults to 0.
  EXPECT_EQ(oom_score, 0);
}

TEST(ProcPidOomscoreAdjTest, BasicWrite) {
  constexpr int test_value = 7;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/oom_score_adj", O_WRONLY));
  ASSERT_THAT(
      RetryEINTR(write)(fd.get(), std::to_string(test_value).c_str(), 1),
      SyscallSucceeds());

  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score_adj"));
  EXPECT_EQ(oom_score, test_value);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
