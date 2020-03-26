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

#include <linux/elf.h>
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
  struct iovec iov;
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
    memset(&iov, 0, sizeof(iov));
    ASSERT_THAT(pid, SyscallSucceeds());  // Might still be < 0.
    ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

    iov.iov_base = &regs_;
    iov.iov_len = sizeof(regs_);
    ASSERT_THAT(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov),
                SyscallSucceeds());

    child_ = pid;
  }

  void Detach() {
    ASSERT_THAT(ptrace(PTRACE_DETACH, child_, 0, 0), SyscallSucceeds());
  }

  void SetRip(uint64_t newrip) {
#if defined(__x86_64__)
    regs_.rip = newrip;
#elif defined(__aarch64__)
    regs_.pc = newrip;
#else
#error "Unknown architecture"
#endif
    ASSERT_THAT(ptrace(PTRACE_SETREGSET, child_, NT_PRSTATUS, &iov),
                SyscallSucceeds());
  }

  void SetRsp(uint64_t newrsp) {
#if defined(__x86_64__)
    regs_.rsp = newrsp;
#elif defined(__aarch64__)
    regs_.sp = newrsp;
#else
#error "Unknown architecture"
#endif
    ASSERT_THAT(ptrace(PTRACE_SETREGSET, child_, NT_PRSTATUS, &iov),
                SyscallSucceeds());
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
#if defined(__x86_64__)
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS)
      << "status = " << status;
#elif defined(__aarch64__)
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)
      << "status = " << status;
#else
#error "Unknown architecture"
#endif
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
