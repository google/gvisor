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

#include <sys/mman.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class MunmapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    m_ = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, m_);
  }

  void* m_ = nullptr;
};

TEST_F(MunmapTest, HappyCase) {
  EXPECT_THAT(munmap(m_, kPageSize), SyscallSucceeds());
}

TEST_F(MunmapTest, ZeroLength) {
  EXPECT_THAT(munmap(m_, 0), SyscallFailsWithErrno(EINVAL));
}

TEST_F(MunmapTest, LastPageRoundUp) {
  // Attempt to unmap up to and including the last page.
  EXPECT_THAT(munmap(m_, static_cast<size_t>(-kPageSize + 1)),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
