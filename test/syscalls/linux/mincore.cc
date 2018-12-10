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
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

size_t CountSetLSBs(std::vector<unsigned char> const& vec) {
  return std::count_if(begin(vec), end(vec),
                       [](unsigned char c) { return (c & 1) != 0; });
}

TEST(MincoreTest, DirtyAnonPagesAreResident) {
  constexpr size_t kTestPageCount = 10;
  auto const kTestMappingBytes = kTestPageCount * kPageSize;
  auto m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kTestMappingBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  memset(m.ptr(), 0, m.len());

  std::vector<unsigned char> vec(kTestPageCount, 0);
  ASSERT_THAT(mincore(m.ptr(), kTestMappingBytes, vec.data()),
              SyscallSucceeds());
  EXPECT_EQ(kTestPageCount, CountSetLSBs(vec));
}

TEST(MincoreTest, UnalignedAddressFails) {
  // Map and touch two pages, then try to mincore the second half of the first
  // page + the first half of the second page. Both pages are mapped, but
  // mincore should return EINVAL due to the misaligned start address.
  constexpr size_t kTestPageCount = 2;
  auto const kTestMappingBytes = kTestPageCount * kPageSize;
  auto m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kTestMappingBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  memset(m.ptr(), 0, m.len());

  std::vector<unsigned char> vec(kTestPageCount, 0);
  EXPECT_THAT(mincore(reinterpret_cast<void*>(m.addr() + kPageSize / 2),
                      kPageSize, vec.data()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MincoreTest, UnalignedLengthSucceedsAndIsRoundedUp) {
  // Map and touch two pages, then try to mincore the first page + the first
  // half of the second page. mincore should silently round up the length to
  // include both pages.
  constexpr size_t kTestPageCount = 2;
  auto const kTestMappingBytes = kTestPageCount * kPageSize;
  auto m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kTestMappingBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  memset(m.ptr(), 0, m.len());

  std::vector<unsigned char> vec(kTestPageCount, 0);
  ASSERT_THAT(mincore(m.ptr(), kPageSize + kPageSize / 2, vec.data()),
              SyscallSucceeds());
  EXPECT_EQ(kTestPageCount, CountSetLSBs(vec));
}

TEST(MincoreTest, ZeroLengthSucceedsAndAllowsAnyVecBelowTaskSize) {
  EXPECT_THAT(mincore(nullptr, 0, nullptr), SyscallSucceeds());
}

TEST(MincoreTest, InvalidLengthFails) {
  EXPECT_THAT(mincore(nullptr, -1, nullptr), SyscallFailsWithErrno(ENOMEM));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
