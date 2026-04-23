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

#include <linux/personality.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(PersonalityTest, QueryPersonality) {
  EXPECT_THAT(syscall(__NR_personality, 0xffffffff),
              SyscallSucceedsWithValue(PER_LINUX));
}

TEST(PersonalityTest, SetPersonality) {
  EXPECT_THAT(syscall(__NR_personality, PER_LINUX),
              SyscallSucceedsWithValue(PER_LINUX));
}

TEST(PersonalityTest, InvalidPersonality) {
  SKIP_IF(!IsRunningOnGvisor());
  EXPECT_THAT(syscall(__NR_personality, PER_BSD),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
