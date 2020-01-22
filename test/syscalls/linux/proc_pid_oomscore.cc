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

#include <iostream>
#include <string>

#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<int> ReadProcNumber(std::string path) {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents(path));
  int oom_score = std::stoi(contents, nullptr);
  return oom_score;
}

TEST(ProcPidOomscoreTest, BasicRead) {
  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));

  // In gVisor oom_score is a stub that always contains 0. If not-gVisor we are
  // satisfied it was a numerical value.
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(oom_score, 0);
  }
}

TEST(ProcPidOomscoreAdjTest, BasicRead) {
  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score_adj"));

  // oom_score_adj defaults to 0.
  EXPECT_EQ(oom_score, 0);
}

TEST(ProcPidOomscoreAdjTest, BasicWrite) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/oom_score_adj", O_WRONLY));
  ASSERT_THAT(RetryEINTR(write)(fd.get(), "7", 1), SyscallSucceeds());

  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score_adj"));
  EXPECT_EQ(oom_score, 7);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
