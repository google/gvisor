// Copyright 2018 Google LLC
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(TgkillTest, InvalidTID) {
  EXPECT_THAT(tgkill(getpid(), -1, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(tgkill(getpid(), 0, 0), SyscallFailsWithErrno(EINVAL));
}

TEST(TgkillTest, InvalidTGID) {
  EXPECT_THAT(tgkill(-1, gettid(), 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(tgkill(0, gettid(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST(TgkillTest, ValidInput) {
  EXPECT_THAT(tgkill(getpid(), gettid(), 0), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
