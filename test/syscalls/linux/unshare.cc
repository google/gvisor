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
#include <sched.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(UnshareTest, AllowsZeroFlags) {
  ASSERT_THAT(unshare(0), SyscallSucceeds());
}

TEST(UnshareTest, ThreadFlagFailsIfMultithreaded) {
  absl::Mutex mu;
  bool finished = false;
  ScopedThread t([&] {
    mu.Lock();
    mu.Await(absl::Condition(&finished));
    mu.Unlock();
  });
  ASSERT_THAT(unshare(CLONE_THREAD), SyscallFailsWithErrno(EINVAL));
  mu.Lock();
  finished = true;
  mu.Unlock();
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
