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
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(GetrusageTest, BasicFork) {
  pid_t pid = fork();
  if (pid == 0) {
    struct rusage rusage_self;
    TEST_PCHECK(getrusage(RUSAGE_SELF, &rusage_self) == 0);
    struct rusage rusage_children;
    TEST_PCHECK(getrusage(RUSAGE_CHILDREN, &rusage_children) == 0);
    // The child has consumed some memory.
    TEST_CHECK(rusage_self.ru_maxrss != 0);
    // The child has no children of its own.
    TEST_CHECK(rusage_children.ru_maxrss == 0);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0), SyscallSucceeds());
  struct rusage rusage_self;
  ASSERT_THAT(getrusage(RUSAGE_SELF, &rusage_self), SyscallSucceeds());
  struct rusage rusage_children;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &rusage_children), SyscallSucceeds());
  // The parent has consumed some memory.
  EXPECT_GT(rusage_self.ru_maxrss, 0);
  // The child has consumed some memory, and because it has exited we can get
  // its max RSS.
  EXPECT_GT(rusage_children.ru_maxrss, 0);
}

// Verifies that a process can get the max resident set size of its grandchild,
// i.e. that maxrss propagates correctly from children to waiting parents.
TEST(GetrusageTest, Grandchild) {
  constexpr int kGrandchildSizeKb = 1024;
  pid_t pid = fork();
  if (pid == 0) {
    pid = fork();
    if (pid == 0) {
      int flags = MAP_ANONYMOUS | MAP_POPULATE | MAP_PRIVATE;
      void *addr =
          mmap(nullptr, kGrandchildSizeKb * 1024, PROT_WRITE, flags, -1, 0);
      TEST_PCHECK(addr != MAP_FAILED);
    } else {
      int status;
      TEST_PCHECK(RetryEINTR(waitpid)(pid, &status, 0) == pid);
    }
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0), SyscallSucceeds());
  struct rusage rusage_self;
  ASSERT_THAT(getrusage(RUSAGE_SELF, &rusage_self), SyscallSucceeds());
  struct rusage rusage_children;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &rusage_children), SyscallSucceeds());
  // The parent has consumed some memory.
  EXPECT_GT(rusage_self.ru_maxrss, 0);
  // The child should consume next to no memory, but the grandchild will
  // consume at least 1MB. Verify that usage bubbles up to the grandparent.
  EXPECT_GT(rusage_children.ru_maxrss, kGrandchildSizeKb);
}

// Verifies that processes ignoring SIGCHLD do not have updated child maxrss
// updated.
TEST(GetrusageTest, IgnoreSIGCHLD) {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGCHLD, sa));
  pid_t pid = fork();
  if (pid == 0) {
    struct rusage rusage_self;
    TEST_PCHECK(getrusage(RUSAGE_SELF, &rusage_self) == 0);
    // The child has consumed some memory.
    TEST_CHECK(rusage_self.ru_maxrss != 0);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallFailsWithErrno(ECHILD));
  struct rusage rusage_self;
  ASSERT_THAT(getrusage(RUSAGE_SELF, &rusage_self), SyscallSucceeds());
  struct rusage rusage_children;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &rusage_children), SyscallSucceeds());
  // The parent has consumed some memory.
  EXPECT_GT(rusage_self.ru_maxrss, 0);
  // The child's maxrss should not have propagated up.
  EXPECT_EQ(rusage_children.ru_maxrss, 0);
}

// Verifies that zombie processes do not update their parent's maxrss. Only
// reaped processes should do this.
TEST(GetrusageTest, IgnoreZombie) {
  pid_t pid = fork();
  if (pid == 0) {
    struct rusage rusage_self;
    TEST_PCHECK(getrusage(RUSAGE_SELF, &rusage_self) == 0);
    struct rusage rusage_children;
    TEST_PCHECK(getrusage(RUSAGE_CHILDREN, &rusage_children) == 0);
    // The child has consumed some memory.
    TEST_CHECK(rusage_self.ru_maxrss != 0);
    // The child has no children of its own.
    TEST_CHECK(rusage_children.ru_maxrss == 0);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  // Give the child time to exit. Because we don't call wait, the child should
  // remain a zombie.
  absl::SleepFor(absl::Seconds(5));
  struct rusage rusage_self;
  ASSERT_THAT(getrusage(RUSAGE_SELF, &rusage_self), SyscallSucceeds());
  struct rusage rusage_children;
  ASSERT_THAT(getrusage(RUSAGE_CHILDREN, &rusage_children), SyscallSucceeds());
  // The parent has consumed some memory.
  EXPECT_GT(rusage_self.ru_maxrss, 0);
  // The child has consumed some memory, but hasn't been reaped.
  EXPECT_EQ(rusage_children.ru_maxrss, 0);
}

TEST(GetrusageTest, Wait4) {
  pid_t pid = fork();
  if (pid == 0) {
    struct rusage rusage_self;
    TEST_PCHECK(getrusage(RUSAGE_SELF, &rusage_self) == 0);
    struct rusage rusage_children;
    TEST_PCHECK(getrusage(RUSAGE_CHILDREN, &rusage_children) == 0);
    // The child has consumed some memory.
    TEST_CHECK(rusage_self.ru_maxrss != 0);
    // The child has no children of its own.
    TEST_CHECK(rusage_children.ru_maxrss == 0);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  struct rusage rusage_children;
  int status;
  ASSERT_THAT(RetryEINTR(wait4)(pid, &status, 0, &rusage_children),
              SyscallSucceeds());
  // The child has consumed some memory, and because it has exited we can get
  // its max RSS.
  EXPECT_GT(rusage_children.ru_maxrss, 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
