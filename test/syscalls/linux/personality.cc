// Copyright 2024 The gVisor Authors.
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

#include <sys/personality.h>

#include "gtest/gtest.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr uint64_t kGetPersonality =          0xffffffff;
constexpr uint64_t kUndefinedPersonalityBit = 0x00001000;

TEST(PersonalityTest, DefaultPersonality) {
  EXPECT_THAT(personality(kGetPersonality), SyscallSucceedsWithValue(PER_LINUX));
}

TEST(PersonalityTest, SetLinux) {
  EXPECT_THAT(personality(kGetPersonality), SyscallSucceedsWithValue(PER_LINUX));
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(PER_LINUX) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == PER_LINUX);
  }), IsPosixErrorOkAndHolds(0));
  EXPECT_THAT(personality(kGetPersonality), SyscallSucceedsWithValue(PER_LINUX));
}

TEST(PersonalityTest, SetBSD) {
  EXPECT_THAT(personality(kGetPersonality), SyscallSucceedsWithValue(PER_LINUX));
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(PER_BSD) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == PER_BSD);
  }), IsPosixErrorOkAndHolds(0));
}

TEST(PersonalityTest, PersonalityIsInheritable) {
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(PER_BSD) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == PER_BSD);
	  TEST_CHECK(InForkedProcess([&] {
      TEST_CHECK(personality(kGetPersonality) == PER_BSD);
	    TEST_CHECK(InForkedProcess([&] {
        TEST_CHECK(personality(kGetPersonality) == PER_BSD);
	    }).ok());
      TEST_CHECK(personality(PER_SOLARIS) == PER_BSD);
	    TEST_CHECK(InForkedProcess([&] {
        TEST_CHECK(personality(kGetPersonality) == PER_SOLARIS);
	    }).ok());
      TEST_CHECK(personality(PER_BSD) == PER_SOLARIS);
	    TEST_CHECK(InForkedProcess([&] {
        TEST_CHECK(personality(kGetPersonality) == PER_BSD);
	    }).ok());
      TEST_CHECK(personality(kGetPersonality) == PER_BSD);
	  }).ok());
  }), IsPosixErrorOkAndHolds(0));
}

TEST(PersonalityTest, ChildPersonalityDoesNotAffectParent) {
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(PER_BSD) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == PER_BSD);
	  TEST_CHECK(InForkedProcess([&] {
      TEST_CHECK(personality(PER_SOLARIS) == PER_BSD);
      TEST_CHECK(personality(kGetPersonality) == PER_SOLARIS);
	  }).ok());
    TEST_CHECK(personality(kGetPersonality) == PER_BSD);
  }), IsPosixErrorOkAndHolds(0));
  TEST_CHECK(personality(kGetPersonality) == PER_LINUX);
}

TEST(PersonalityTest, SetShortInode) {
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(SHORT_INODE) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == SHORT_INODE);
  }), IsPosixErrorOkAndHolds(0));
}

TEST(PersonalityTest, SetWholeSeconds) {
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(WHOLE_SECONDS) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == WHOLE_SECONDS);
  }), IsPosixErrorOkAndHolds(0));
}

TEST(PersonalityTest, SetMultiple) {
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(PER_BSD | SHORT_INODE | WHOLE_SECONDS) == PER_LINUX);
    TEST_CHECK(personality(kGetPersonality) == (PER_BSD | SHORT_INODE | WHOLE_SECONDS));
  }), IsPosixErrorOkAndHolds(0));
}

TEST(PersonalityTest, SetThenUnset) {
  EXPECT_THAT(InForkedProcess([&] {
    TEST_CHECK(personality(PER_BSD | SHORT_INODE) == PER_LINUX);
    TEST_CHECK(personality(WHOLE_SECONDS | SHORT_INODE) == (PER_BSD | SHORT_INODE));
    TEST_CHECK(personality(PER_BSD) == (WHOLE_SECONDS | SHORT_INODE));
    TEST_CHECK(personality(kGetPersonality) == PER_BSD);
  }), IsPosixErrorOkAndHolds(0));
}

TEST(PersonalityTest, UnsupportedPersonalityBitsAreRejected) {
  SKIP_IF(!IsRunningOnGvisor());
  EXPECT_THAT(personality(kGetPersonality), SyscallSucceedsWithValue(PER_LINUX));
  EXPECT_THAT(personality(MMAP_PAGE_ZERO), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(ADDR_LIMIT_3GB), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(ADDR_LIMIT_32BIT), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(ADDR_NO_RANDOMIZE), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(ADDR_COMPAT_LAYOUT), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(READ_IMPLIES_EXEC), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(STICKY_TIMEOUTS), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(UNAME26), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(FDPIC_FUNCPTRS), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(PER_LINUX32), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(PER_LINUX32_3GB), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(PER_LINUX_32BIT), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(PER_LINUX_FDPIC), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(PER_RISCOS), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(PER_SOLARIS), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(personality(kGetPersonality), SyscallSucceedsWithValue(PER_LINUX));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
