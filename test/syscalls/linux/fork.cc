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
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>
#include <cstdlib>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::Ge;

class ForkTest : public ::testing::Test {
 protected:
  // SetUp creates a populated, open file.
  void SetUp() override {
    // Make a shared mapping.
    shared_ = reinterpret_cast<char*>(mmap(0, kPageSize, PROT_READ | PROT_WRITE,
                                           MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ASSERT_NE(reinterpret_cast<void*>(shared_), MAP_FAILED);

    // Make a private mapping.
    private_ =
        reinterpret_cast<char*>(mmap(0, kPageSize, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_NE(reinterpret_cast<void*>(private_), MAP_FAILED);

    // Make a pipe.
    ASSERT_THAT(pipe(pipes_), SyscallSucceeds());
  }

  // TearDown frees associated resources.
  void TearDown() override {
    EXPECT_THAT(munmap(shared_, kPageSize), SyscallSucceeds());
    EXPECT_THAT(munmap(private_, kPageSize), SyscallSucceeds());
    EXPECT_THAT(close(pipes_[0]), SyscallSucceeds());
    EXPECT_THAT(close(pipes_[1]), SyscallSucceeds());
  }

  // Fork executes a clone system call.
  pid_t Fork() {
    pid_t pid = fork();
    MaybeSave();
    TEST_PCHECK_MSG(pid >= 0, "fork failed");
    return pid;
  }

  // Wait waits for the given pid and returns the exit status. If the child was
  // killed by a signal or an error occurs, then 256+signal is returned.
  int Wait(pid_t pid) {
    int status;
    while (true) {
      int rval = wait4(pid, &status, 0, NULL);
      if (rval < 0) {
        return rval;
      }
      if (rval != pid) {
        continue;
      }
      if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
      }
      if (WIFSIGNALED(status)) {
        return 256 + WTERMSIG(status);
      }
    }
  }

  // Exit exits the proccess.
  void Exit(int code) {
    _exit(code);

    // Should never reach here. Since the exit above failed, we really don't
    // have much in the way of options to indicate failure. So we just try to
    // log an assertion failure to the logs. The parent process will likely
    // fail anyways if exit is not working.
    TEST_CHECK_MSG(false, "_exit returned");
  }

  // ReadByte reads a byte from the shared pipe.
  char ReadByte() {
    char val = -1;
    TEST_PCHECK(ReadFd(pipes_[0], &val, 1) == 1);
    MaybeSave();
    return val;
  }

  // WriteByte writes a byte from the shared pipe.
  void WriteByte(char val) {
    TEST_PCHECK(WriteFd(pipes_[1], &val, 1) == 1);
    MaybeSave();
  }

  // Shared pipe.
  int pipes_[2];

  // Shared mapping (one page).
  char* shared_;

  // Private mapping (one page).
  char* private_;
};

TEST_F(ForkTest, Simple) {
  pid_t child = Fork();
  if (child == 0) {
    Exit(0);
  }
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

TEST_F(ForkTest, ExitCode) {
  pid_t child = Fork();
  if (child == 0) {
    Exit(123);
  }
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(123));
  child = Fork();
  if (child == 0) {
    Exit(1);
  }
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(1));
}

TEST_F(ForkTest, Multi) {
  pid_t child1 = Fork();
  if (child1 == 0) {
    Exit(0);
  }
  pid_t child2 = Fork();
  if (child2 == 0) {
    Exit(1);
  }
  EXPECT_THAT(Wait(child1), SyscallSucceedsWithValue(0));
  EXPECT_THAT(Wait(child2), SyscallSucceedsWithValue(1));
}

TEST_F(ForkTest, Pipe) {
  pid_t child = Fork();
  if (child == 0) {
    WriteByte(1);
    Exit(0);
  }
  EXPECT_EQ(ReadByte(), 1);
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

TEST_F(ForkTest, SharedMapping) {
  pid_t child = Fork();
  if (child == 0) {
    // Wait for the parent.
    ReadByte();
    if (shared_[0] == 1) {
      Exit(0);
    }
    // Failed.
    Exit(1);
  }
  // Change the mapping.
  ASSERT_EQ(shared_[0], 0);
  shared_[0] = 1;
  // Unblock the child.
  WriteByte(0);
  // Did it work?
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

TEST_F(ForkTest, PrivateMapping) {
  pid_t child = Fork();
  if (child == 0) {
    // Wait for the parent.
    ReadByte();
    if (private_[0] == 0) {
      Exit(0);
    }
    // Failed.
    Exit(1);
  }
  // Change the mapping.
  ASSERT_EQ(private_[0], 0);
  private_[0] = 1;
  // Unblock the child.
  WriteByte(0);
  // Did it work?
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

// Test that cpuid works after a fork.
TEST_F(ForkTest, Cpuid) {
  pid_t child = Fork();

  // We should be able to determine the CPU vendor.
  ASSERT_NE(GetCPUVendor(), CPUVendor::kUnknownVendor);

  if (child == 0) {
    Exit(0);
  }
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

TEST_F(ForkTest, Mmap) {
  pid_t child = Fork();

  if (child == 0) {
    void* addr =
        mmap(0, kPageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    MaybeSave();
    Exit(addr == MAP_FAILED);
  }

  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

static volatile int alarmed = 0;

void AlarmHandler(int sig, siginfo_t* info, void* context) { alarmed = 1; }

TEST_F(ForkTest, Alarm) {
  // Setup an alarm handler.
  struct sigaction sa;
  sa.sa_sigaction = AlarmHandler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  EXPECT_THAT(sigaction(SIGALRM, &sa, nullptr), SyscallSucceeds());

  pid_t child = Fork();

  if (child == 0) {
    alarm(1);
    sleep(3);
    if (!alarmed) {
      Exit(1);
    }
    Exit(0);
  }

  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
  EXPECT_EQ(0, alarmed);
}

// Child cannot affect parent private memory.
TEST_F(ForkTest, PrivateMemory) {
  std::atomic<uint32_t> local(0);

  pid_t child1 = Fork();
  if (child1 == 0) {
    local++;

    pid_t child2 = Fork();
    if (child2 == 0) {
      local++;

      TEST_CHECK(local.load() == 2);

      Exit(0);
    }

    TEST_PCHECK(Wait(child2) == 0);
    TEST_CHECK(local.load() == 1);
    Exit(0);
  }

  EXPECT_THAT(Wait(child1), SyscallSucceedsWithValue(0));
  EXPECT_EQ(0, local.load());
}

// Kernel-accessed buffers should remain coherent across COW.
TEST_F(ForkTest, COWSegment) {
  constexpr int kBufSize = 1024;
  char* read_buf = private_;
  char* touch = private_ + kPageSize / 2;

  std::string contents(kBufSize, 'a');

  ScopedThread t([&] {
    // Wait to be sure the parent is blocked in read.
    absl::SleepFor(absl::Seconds(3));

    // Fork to mark private pages for COW.
    //
    // Use fork directly rather than the Fork wrapper to skip the multi-threaded
    // check, and limit the child to async-signal-safe functions:
    //
    // "After a fork() in a multithreaded program, the child can safely call
    // only async-signal-safe functions (see signal(7)) until such time as it
    // calls execve(2)."
    //
    // Skip ASSERT in the child, as it isn't async-signal-safe.
    pid_t child = fork();
    if (child == 0) {
      // Wait to be sure parent touched memory.
      sleep(3);
      Exit(0);
    }

    // Check success only in the parent.
    ASSERT_THAT(child, SyscallSucceedsWithValue(Ge(0)));

    // Trigger COW on private page.
    *touch = 42;

    // Write to pipe. Parent should still be able to read this.
    EXPECT_THAT(WriteFd(pipes_[1], contents.c_str(), kBufSize),
                SyscallSucceedsWithValue(kBufSize));

    EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
  });

  EXPECT_THAT(ReadFd(pipes_[0], read_buf, kBufSize),
              SyscallSucceedsWithValue(kBufSize));
  EXPECT_STREQ(contents.c_str(), read_buf);
}

TEST_F(ForkTest, SigAltStack) {
  std::vector<char> stack_mem(SIGSTKSZ);
  stack_t stack = {};
  stack.ss_size = SIGSTKSZ;
  stack.ss_sp = stack_mem.data();
  ASSERT_THAT(sigaltstack(&stack, nullptr), SyscallSucceeds());

  pid_t child = Fork();

  if (child == 0) {
    stack_t oss = {};
    TEST_PCHECK(sigaltstack(nullptr, &oss) == 0);
    MaybeSave();

    TEST_CHECK((oss.ss_flags & SS_DISABLE) == 0);
    TEST_CHECK(oss.ss_size == SIGSTKSZ);
    TEST_CHECK(oss.ss_sp == stack.ss_sp);

    Exit(0);
  }
  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

TEST_F(ForkTest, Affinity) {
  // Make a non-default cpumask.
  cpu_set_t parent_mask;
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, sizeof(cpu_set_t), &parent_mask),
              SyscallSucceeds());
  // Knock out the lowest bit.
  for (unsigned int n = 0; n < CPU_SETSIZE; n++) {
    if (CPU_ISSET(n, &parent_mask)) {
      CPU_CLR(n, &parent_mask);
      break;
    }
  }
  EXPECT_THAT(sched_setaffinity(/*pid=*/0, sizeof(cpu_set_t), &parent_mask),
              SyscallSucceeds());

  pid_t child = Fork();
  if (child == 0) {
    cpu_set_t child_mask;

    int ret = sched_getaffinity(/*pid=*/0, sizeof(cpu_set_t), &child_mask);
    MaybeSave();
    if (ret < 0) {
      Exit(-ret);
    }

    TEST_CHECK(CPU_EQUAL(&child_mask, &parent_mask));

    Exit(0);
  }

  EXPECT_THAT(Wait(child), SyscallSucceedsWithValue(0));
}

TEST(CloneTest, NewUserNamespacePermitsAllOtherNamespaces) {
  // "If CLONE_NEWUSER is specified along with other CLONE_NEW* flags in a
  // single clone(2) or unshare(2) call, the user namespace is guaranteed to be
  // created first, giving the child (clone(2)) or caller (unshare(2))
  // privileges over the remaining namespaces created by the call. Thus, it is
  // possible for an unprivileged caller to specify this combination of flags."
  // - user_namespaces(7)
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  Mapping child_stack = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  int child_pid;
  // We only test with CLONE_NEWIPC, CLONE_NEWNET, and CLONE_NEWUTS since these
  // namespaces were implemented in Linux before user namespaces.
  ASSERT_THAT(
      child_pid = clone(
          +[](void*) { return 0; },
          reinterpret_cast<void*>(child_stack.addr() + kPageSize),
          CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS | SIGCHLD,
          /* arg = */ nullptr),
      SyscallSucceeds());

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}

#ifdef __x86_64__
// Clone with CLONE_SETTLS and a non-canonical TLS address is rejected.
TEST(CloneTest, NonCanonicalTLS) {
  constexpr uintptr_t kNonCanonical = 1ull << 48;

  // We need a valid address for the stack pointer. We'll never actually execute
  // on this.
  char stack;

  EXPECT_THAT(syscall(__NR_clone, SIGCHLD | CLONE_SETTLS, &stack, nullptr,
                      nullptr, kNonCanonical),
              SyscallFailsWithErrno(EPERM));
}
#endif

}  // namespace
}  // namespace testing
}  // namespace gvisor
