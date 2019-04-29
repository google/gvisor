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

// Tests to verify that the behavior of linux and gvisor matches when
// 'sysret' returns to bad (aka non-canonical) %rip or %rsp.
#include <sys/ptrace.h>
#include <sys/user.h>

#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr uint64_t kNonCanonicalRip = 0xCCCC000000000000;
constexpr uint64_t kNonCanonicalRsp = 0xFFFF000000000000;

class SysretTest : public ::testing::Test {
 protected:
  struct user_regs_struct regs_;
  pid_t child_;

  void SetUp() override {
    pid_t pid = fork();

    // Child.
    if (pid == 0) {
      TEST_PCHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0);
      MaybeSave();
      TEST_PCHECK(raise(SIGSTOP) == 0);
      MaybeSave();
      _exit(0);
    }

    // Parent.
    int status;
    ASSERT_THAT(pid, SyscallSucceeds());  // Might still be < 0.
    ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    ASSERT_THAT(ptrace(PTRACE_GETREGS, pid, 0, &regs_), SyscallSucceeds());

    child_ = pid;
  }

  void Detach() {
    ASSERT_THAT(ptrace(PTRACE_DETACH, child_, 0, 0), SyscallSucceeds());
  }

  void SetRip(uint64_t newrip) {
    regs_.rip = newrip;
    ASSERT_THAT(ptrace(PTRACE_SETREGS, child_, 0, &regs_), SyscallSucceeds());
  }

  void SetRsp(uint64_t newrsp) {
    regs_.rsp = newrsp;
    ASSERT_THAT(ptrace(PTRACE_SETREGS, child_, 0, &regs_), SyscallSucceeds());
  }

  // Wait waits for the child pid and returns the exit status.
  int Wait() {
    int status;
    while (true) {
      int rval = wait4(child_, &status, 0, NULL);
      if (rval < 0) {
        return rval;
      }
      if (rval == child_) {
        return status;
      }
    }
  }
};

TEST_F(SysretTest, JustDetach) {
  Detach();
  int status = Wait();
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}

TEST_F(SysretTest, BadRip) {
  SetRip(kNonCanonicalRip);
  Detach();
  int status = Wait();
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
      << "status = " << status;
}

TEST_F(SysretTest, BadRsp) {
  SetRsp(kNonCanonicalRsp);
  Detach();
  int status = Wait();
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS)
      << "status = " << status;
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
