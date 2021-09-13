// Copyright 2021 The gVisor Authors.
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

#include <linux/sem.h>
#include <linux/shm.h>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(ProcDefaults, PresenceOfShmMaxMniAll) {
  uint64_t shmmax = 0;
  uint64_t shmall = 0;
  uint64_t shmmni = 0;
  std::string proc_file;
  proc_file = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/sys/kernel/shmmax"));
  ASSERT_FALSE(proc_file.empty());
  ASSERT_TRUE(absl::SimpleAtoi(proc_file, &shmmax));
  proc_file = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/sys/kernel/shmall"));
  ASSERT_FALSE(proc_file.empty());
  ASSERT_TRUE(absl::SimpleAtoi(proc_file, &shmall));
  proc_file = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/sys/kernel/shmmni"));
  ASSERT_FALSE(proc_file.empty());
  ASSERT_TRUE(absl::SimpleAtoi(proc_file, &shmmni));

  ASSERT_EQ(shmmax, SHMMAX);
  ASSERT_EQ(shmall, SHMALL);
  ASSERT_EQ(shmmni, SHMMNI);
  ASSERT_LE(shmall, shmmax);

  // These values should never be higher than this by default, for more
  // information see uapi/linux/shm.h
  ASSERT_LE(shmmax, ULONG_MAX - (1UL << 24));
  ASSERT_LE(shmall, ULONG_MAX - (1UL << 24));
}

TEST(ProcDefaults, PresenceOfSem) {
  uint32_t semmsl = 0;
  uint32_t semmns = 0;
  uint32_t semopm = 0;
  uint32_t semmni = 0;
  std::string proc_file;
  proc_file = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/sys/kernel/sem"));
  ASSERT_FALSE(proc_file.empty());
  std::vector<absl::string_view> sem_limits =
      absl::StrSplit(proc_file, absl::ByAnyChar("\t"), absl::SkipWhitespace());
  ASSERT_EQ(sem_limits.size(), 4);
  ASSERT_TRUE(absl::SimpleAtoi(sem_limits[0], &semmsl));
  ASSERT_TRUE(absl::SimpleAtoi(sem_limits[1], &semmns));
  ASSERT_TRUE(absl::SimpleAtoi(sem_limits[2], &semopm));
  ASSERT_TRUE(absl::SimpleAtoi(sem_limits[3], &semmni));

  ASSERT_EQ(semmsl, SEMMSL);
  ASSERT_EQ(semmns, SEMMNS);
  ASSERT_EQ(semopm, SEMOPM);
  ASSERT_EQ(semmni, SEMMNI);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
