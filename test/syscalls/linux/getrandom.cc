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

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef SYS_getrandom
#if defined(__x86_64__)
#define SYS_getrandom 318
#elif defined(__i386__)
#define SYS_getrandom 355
#else
#error "Unknown architecture"
#endif
#endif  // SYS_getrandom

bool SomeByteIsNonZero(char* random_bytes, int length) {
  for (int i = 0; i < length; i++) {
    if (random_bytes[i] != 0) {
      return true;
    }
  }
  return false;
}

TEST(GetrandomTest, IsRandom) {
  // This test calls get_random and makes sure that the array is filled in with
  // something that is non-zero. Perhaps we get back \x00\x00\x00\x00\x00.... as
  // a random result, but it's so unlikely that we'll just ignore this.
  char random_bytes[64] = {};
  int n = syscall(SYS_getrandom, random_bytes, 64, 0);
  SKIP_IF(!IsRunningOnGvisor() && n < 0 && errno == ENOSYS);
  EXPECT_THAT(n, SyscallSucceeds());
  EXPECT_GT(n, 0);  // Some bytes should be returned.
  EXPECT_TRUE(SomeByteIsNonZero(random_bytes, n));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
