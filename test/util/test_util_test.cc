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

#include "test/util/test_util.h"

#include <errno.h>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::AnyOf;
using ::testing::Gt;
using ::testing::IsEmpty;
using ::testing::Lt;
using ::testing::Not;
using ::testing::TypedEq;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

namespace gvisor {
namespace testing {

namespace {

TEST(KernelVersionParsing, ValidateParsing) {
  KernelVersion v = ASSERT_NO_ERRNO_AND_VALUE(
      ParseKernelVersion("4.18.10-1foo2-amd64 baz blah"));
  ASSERT_TRUE(v == KernelVersion({4, 18, 10}));

  v = ASSERT_NO_ERRNO_AND_VALUE(ParseKernelVersion("4.18.10-1foo2-amd64"));
  ASSERT_TRUE(v == KernelVersion({4, 18, 10}));

  v = ASSERT_NO_ERRNO_AND_VALUE(ParseKernelVersion("4.18.10-14-amd64"));
  ASSERT_TRUE(v == KernelVersion({4, 18, 10}));

  v = ASSERT_NO_ERRNO_AND_VALUE(ParseKernelVersion("4.18.10-amd64"));
  ASSERT_TRUE(v == KernelVersion({4, 18, 10}));

  v = ASSERT_NO_ERRNO_AND_VALUE(ParseKernelVersion("4.18.10"));
  ASSERT_TRUE(v == KernelVersion({4, 18, 10}));

  v = ASSERT_NO_ERRNO_AND_VALUE(ParseKernelVersion("4.0.10"));
  ASSERT_TRUE(v == KernelVersion({4, 0, 10}));

  v = ASSERT_NO_ERRNO_AND_VALUE(ParseKernelVersion("4.0"));
  ASSERT_TRUE(v == KernelVersion({4, 0, 0}));

  ASSERT_THAT(ParseKernelVersion("4.a"), PosixErrorIs(EINVAL, ::testing::_));
  ASSERT_THAT(ParseKernelVersion("3"), PosixErrorIs(EINVAL, ::testing::_));
  ASSERT_THAT(ParseKernelVersion(""), PosixErrorIs(EINVAL, ::testing::_));
  ASSERT_THAT(ParseKernelVersion("version 3.3.10"),
              PosixErrorIs(EINVAL, ::testing::_));
}

TEST(MatchersTest, SyscallSucceeds) {
  EXPECT_THAT(0, SyscallSucceeds());
  EXPECT_THAT(0L, SyscallSucceeds());

  errno = 0;
  EXPECT_THAT(-1, SyscallSucceeds());
  EXPECT_THAT(-1L, SyscallSucceeds());

  errno = ENOMEM;
  EXPECT_THAT(-1, Not(SyscallSucceeds()));
  EXPECT_THAT(-1L, Not(SyscallSucceeds()));
}

TEST(MatchersTest, SyscallSucceedsWithValue) {
  EXPECT_THAT(0, SyscallSucceedsWithValue(0));
  EXPECT_THAT(1, SyscallSucceedsWithValue(Lt(3)));
  EXPECT_THAT(-1, Not(SyscallSucceedsWithValue(Lt(3))));
  EXPECT_THAT(4, Not(SyscallSucceedsWithValue(Lt(3))));

  // Non-int -1
  EXPECT_THAT(-1L, Not(SyscallSucceedsWithValue(0)));

  // Non-int, truncates to -1 if converted to int, with expected value
  EXPECT_THAT(0xffffffffL, SyscallSucceedsWithValue(0xffffffffL));

  // Non-int, truncates to -1 if converted to int, with monomorphic matcher
  EXPECT_THAT(0xffffffffL,
              SyscallSucceedsWithValue(TypedEq<long>(0xffffffffL)));

  // Non-int, truncates to -1 if converted to int, with polymorphic matcher
  EXPECT_THAT(0xffffffffL, SyscallSucceedsWithValue(Gt(1)));
}

TEST(MatchersTest, SyscallFails) {
  EXPECT_THAT(0, Not(SyscallFails()));
  EXPECT_THAT(0L, Not(SyscallFails()));

  errno = 0;
  EXPECT_THAT(-1, Not(SyscallFails()));
  EXPECT_THAT(-1L, Not(SyscallFails()));

  errno = ENOMEM;
  EXPECT_THAT(-1, SyscallFails());
  EXPECT_THAT(-1L, SyscallFails());
}

TEST(MatchersTest, SyscallFailsWithErrno) {
  EXPECT_THAT(0, Not(SyscallFailsWithErrno(EINVAL)));
  EXPECT_THAT(0L, Not(SyscallFailsWithErrno(EINVAL)));

  errno = ENOMEM;
  EXPECT_THAT(-1, Not(SyscallFailsWithErrno(EINVAL)));
  EXPECT_THAT(-1L, Not(SyscallFailsWithErrno(EINVAL)));

  errno = EINVAL;
  EXPECT_THAT(-1, SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(-1L, SyscallFailsWithErrno(EINVAL));

  EXPECT_THAT(-1, SyscallFailsWithErrno(AnyOf(EINVAL, ENOMEM)));
  EXPECT_THAT(-1L, SyscallFailsWithErrno(AnyOf(EINVAL, ENOMEM)));

  std::vector<int> expected_errnos({EINVAL, ENOMEM});
  errno = ENOMEM;
  EXPECT_THAT(-1, SyscallFailsWithErrno(ElementOf(expected_errnos)));
  EXPECT_THAT(-1L, SyscallFailsWithErrno(ElementOf(expected_errnos)));
}

TEST(AllBitwiseCombinationsTest, NoArguments) {
  EXPECT_THAT(AllBitwiseCombinations(), IsEmpty());
}

TEST(AllBitwiseCombinationsTest, EmptyList) {
  EXPECT_THAT(AllBitwiseCombinations(List<int>{}), IsEmpty());
}

TEST(AllBitwiseCombinationsTest, SingleElementList) {
  EXPECT_THAT(AllBitwiseCombinations(List<int>{5}), UnorderedElementsAre(5));
}

TEST(AllBitwiseCombinationsTest, SingleList) {
  EXPECT_THAT(AllBitwiseCombinations(List<int>{0, 1, 2, 4}),
              UnorderedElementsAre(0, 1, 2, 4));
}

TEST(AllBitwiseCombinationsTest, MultipleLists) {
  EXPECT_THAT(
      AllBitwiseCombinations(List<int>{0, 1, 2, 3}, List<int>{0, 4, 8, 12}),
      UnorderedElementsAreArray(
          {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}));
}

TEST(RandomizeBuffer, Works) {
  const std::vector<char> original(4096);
  std::vector<char> buffer = original;
  RandomizeBuffer(buffer.data(), buffer.size());
  EXPECT_NE(buffer, original);
}

// Enable comparison of vectors of iovec arrays for the following test.
MATCHER_P(IovecsListEq, expected, "") {
  if (arg.size() != expected.size()) {
    *result_listener << "sizes are different (actual: " << arg.size()
                     << ", expected: " << expected.size() << ")";
    return false;
  }

  for (uint64_t i = 0; i < expected.size(); ++i) {
    const std::vector<struct iovec>& actual_iovecs = arg[i];
    const std::vector<struct iovec>& expected_iovecs = expected[i];
    if (actual_iovecs.size() != expected_iovecs.size()) {
      *result_listener << "iovec array size at position " << i
                       << " is different (actual: " << actual_iovecs.size()
                       << ", expected: " << expected_iovecs.size() << ")";
      return false;
    }

    for (uint64_t j = 0; j < expected_iovecs.size(); ++j) {
      const struct iovec& actual_iov = actual_iovecs[j];
      const struct iovec& expected_iov = expected_iovecs[j];
      if (actual_iov.iov_base != expected_iov.iov_base) {
        *result_listener << "iovecs in array " << i << " at position " << j
                         << " are different (expected iov_base: "
                         << expected_iov.iov_base
                         << ", got: " << actual_iov.iov_base << ")";
        return false;
      }
      if (actual_iov.iov_len != expected_iov.iov_len) {
        *result_listener << "iovecs in array " << i << " at position " << j
                         << " are different (expected iov_len: "
                         << expected_iov.iov_len
                         << ", got: " << actual_iov.iov_len << ")";
        return false;
      }
    }
  }

  return true;
}

// Verify empty iovec list generation.
TEST(GenerateIovecs, EmptyList) {
  std::vector<char> buffer = {'a', 'b', 'c'};

  EXPECT_THAT(GenerateIovecs(0, buffer.data(), buffer.size()),
              IovecsListEq(std::vector<std::vector<struct iovec>>()));
}

// Verify generating a single array of only one, partial, iovec.
TEST(GenerateIovecs, OneArray) {
  std::vector<char> buffer = {'a', 'b', 'c'};

  std::vector<std::vector<struct iovec>> expected;
  struct iovec iov = {};
  iov.iov_base = buffer.data();
  iov.iov_len = 2;
  expected.push_back(std::vector<struct iovec>({iov}));
  EXPECT_THAT(GenerateIovecs(2, buffer.data(), buffer.size()),
              IovecsListEq(expected));
}

// Verify that it wraps around after IOV_MAX iovecs.
TEST(GenerateIovecs, WrapsAtIovMax) {
  std::vector<char> buffer = {'a', 'b', 'c'};

  std::vector<std::vector<struct iovec>> expected;
  struct iovec iov = {};
  iov.iov_base = buffer.data();
  iov.iov_len = buffer.size();
  expected.emplace_back();
  for (int i = 0; i < IOV_MAX; ++i) {
    expected[0].push_back(iov);
  }
  iov.iov_len = 1;
  expected.push_back(std::vector<struct iovec>({iov}));

  EXPECT_THAT(
      GenerateIovecs(IOV_MAX * buffer.size() + 1, buffer.data(), buffer.size()),
      IovecsListEq(expected));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
