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

#include <signal.h>
#include <sys/syscall.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(SigactionTest, GetLessThanOrEqualToZeroFails) {
  struct sigaction act = {};
  ASSERT_THAT(sigaction(-1, nullptr, &act), SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(sigaction(0, nullptr, &act), SyscallFailsWithErrno(EINVAL));
}

TEST(SigactionTest, SetLessThanOrEqualToZeroFails) {
  struct sigaction act = {};
  ASSERT_THAT(sigaction(0, &act, nullptr), SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(sigaction(0, &act, nullptr), SyscallFailsWithErrno(EINVAL));
}

TEST(SigactionTest, GetGreaterThanMaxFails) {
  struct sigaction act = {};
  ASSERT_THAT(sigaction(SIGRTMAX + 1, nullptr, &act),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SigactionTest, SetGreaterThanMaxFails) {
  struct sigaction act = {};
  ASSERT_THAT(sigaction(SIGRTMAX + 1, &act, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SigactionTest, SetSigkillFails) {
  struct sigaction act = {};
  ASSERT_THAT(sigaction(SIGKILL, nullptr, &act), SyscallSucceeds());
  ASSERT_THAT(sigaction(SIGKILL, &act, nullptr), SyscallFailsWithErrno(EINVAL));
}

TEST(SigactionTest, SetSigstopFails) {
  struct sigaction act = {};
  ASSERT_THAT(sigaction(SIGSTOP, nullptr, &act), SyscallSucceeds());
  ASSERT_THAT(sigaction(SIGSTOP, &act, nullptr), SyscallFailsWithErrno(EINVAL));
}

TEST(SigactionTest, BadSigsetFails) {
  constexpr size_t kWrongSigSetSize = 43;

  struct sigaction act = {};

  // The syscall itself (rather than the libc wrapper) takes the sigset_t size.
  ASSERT_THAT(
      syscall(SYS_rt_sigaction, SIGTERM, nullptr, &act, kWrongSigSetSize),
      SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(
      syscall(SYS_rt_sigaction, SIGTERM, &act, nullptr, kWrongSigSetSize),
      SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
