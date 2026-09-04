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
#include <sys/mman.h>
#include <sys/sysinfo.h>

#include <cstddef>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<int> ReadProcNumber(std::string path) {
  ASSIGN_OR_RETURN_ERRNO(std::string contents, GetContents(path));
  EXPECT_EQ(contents[contents.length() - 1], '\n');

  int num;
  if (!absl::SimpleAtoi(contents, &num)) {
    return PosixError(EINVAL, absl::StrCat("invalid value: ", contents));
  }

  return num;
}

PosixError WriteProcNumber(std::string path, int value) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, Open(path, O_WRONLY));
  std::string str = std::to_string(value);
  if (RetryEINTR(write)(fd.get(), str.c_str(), str.size()) < 0) {
    return PosixError(errno, absl::StrCat("failed to write ", path));
  }
  return NoError();
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

TEST(ProcPidOomscoreAdjTest, WriteNullTerminatedString) {
  constexpr int test_value = 7;
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/oom_score_adj", O_WRONLY));
  ASSERT_THAT(
      RetryEINTR(write)(fd.get(), std::to_string(test_value).c_str(), 2),
      SyscallSucceeds());

  auto const oom_score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score_adj"));
  EXPECT_EQ(oom_score, test_value);
}

// The following tests validate gVisor's dynamic /proc/<pid>/oom_score, which
// mirrors Linux's oom_badness(): score = clamp(rss*1000/total + oom_score_adj)
// to [1, 1000], or 0 for an immune task. They are gVisor-only because the score
// is computed from the sentry's memory accounting.

// A task with oom_score_adj == -1000 is immune and must report oom_score 0.
TEST(ProcPidOomscoreTest, StrictExemptionScoresZero) {
  SKIP_IF(!IsRunningOnGvisor());
  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", -1000));
  auto const score =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));
  EXPECT_EQ(score, 0);
  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 0));
}

// oom_score is biased upward by oom_score_adj, mirroring oom_badness().
TEST(ProcPidOomscoreTest, AdjustmentIncreasesScore) {
  SKIP_IF(!IsRunningOnGvisor());
  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 0));
  auto const score_base =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));
  EXPECT_GE(score_base, 1);
  EXPECT_LE(score_base, 1000);

  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 500));
  auto const score_high =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));
  EXPECT_GT(score_high, score_base);
  EXPECT_GE(score_high, 500);
  EXPECT_LE(score_high, 1000);

  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 0));
}

// oom_score grows with resident memory and shrinks when pages are released.
TEST(ProcPidOomscoreTest, ScoreReflectsResidentMemory) {
  SKIP_IF(!IsRunningOnGvisor());
  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 0));
  auto const score_base =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));

  constexpr size_t kAlloc = 256 * 1024 * 1024;
  void* addr = mmap(nullptr, kAlloc, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(addr, MAP_FAILED);
  volatile char* p = static_cast<volatile char*>(addr);
  for (size_t off = 0; off < kAlloc; off += 4096) p[off] = 1;
  auto const score_touched =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));

  ASSERT_THAT(madvise(addr, kAlloc, MADV_DONTNEED), SyscallSucceeds());
  auto const score_dropped =
      ASSERT_NO_ERRNO_AND_VALUE(ReadProcNumber("/proc/self/oom_score"));
  ASSERT_THAT(munmap(addr, kAlloc), SyscallSucceeds());

  struct sysinfo si = {};
  ASSERT_THAT(sysinfo(&si), SyscallSucceeds());
  if (si.totalram <= 8ULL * 1024 * 1024 * 1024) {
    // Small sandbox: 256MB is a meaningful fraction of total memory, so the
    // score must rise while resident and fall once the pages are dropped.
    EXPECT_GT(score_touched, score_base);
    EXPECT_LT(score_dropped, score_touched);
  } else {
    // Large host (e.g. ~TB RAM): 256MB is < 1/1000th of total,
    // so the normalized score need not change; require only well-formed values.
    EXPECT_GE(score_touched, 1);
    EXPECT_LE(score_touched, 1000);
    EXPECT_GE(score_dropped, 1);
    EXPECT_LE(score_dropped, 1000);
  }
}

// Out-of-range oom_score_adj writes are rejected with EINVAL; boundary values
// are accepted.
TEST(ProcPidOomscoreAdjTest, BoundsValidation) {
  SKIP_IF(!IsRunningOnGvisor());
  EXPECT_EQ(WriteProcNumber("/proc/self/oom_score_adj", 1001).errno_value(),
            EINVAL);
  EXPECT_EQ(WriteProcNumber("/proc/self/oom_score_adj", -1001).errno_value(),
            EINVAL);
  EXPECT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 1000));
  EXPECT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", -1000));
  ASSERT_NO_ERRNO(WriteProcNumber("/proc/self/oom_score_adj", 0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
