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

#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

ABSL_FLAG(int32_t, scratch_uid, 65534, "scratch UID");
ABSL_FLAG(int32_t, scratch_gid, 65534, "scratch GID");

using ::testing::Ge;

namespace gvisor {
namespace testing {

namespace {

TEST(KillTest, CanKillValidPid) {
  // If pid is positive, then signal sig is sent to the process with the ID
  // specified by pid.
  EXPECT_THAT(kill(getpid(), 0), SyscallSucceeds());
  // If pid equals 0, then sig is sent to every process in the process group of
  // the calling process.
  EXPECT_THAT(kill(0, 0), SyscallSucceeds());

  ScopedThread([] { EXPECT_THAT(kill(gettid(), 0), SyscallSucceeds()); });
}

void SigHandler(int sig, siginfo_t* info, void* context) { _exit(0); }

// If pid equals -1, then sig is sent to every process for which the calling
// process has permission to send signals, except for process 1 (init).
TEST(KillTest, CanKillAllPIDs) {
  int pipe_fds[2];
  ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
  FileDescriptor read_fd(pipe_fds[0]);
  FileDescriptor write_fd(pipe_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    read_fd.reset();

    struct sigaction sa;
    sa.sa_sigaction = SigHandler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    TEST_PCHECK(sigaction(SIGWINCH, &sa, nullptr) == 0);
    MaybeSave();

    // Indicate to the parent that we're ready.
    write_fd.reset();

    // Wait until we get the signal from the parent.
    while (true) {
      pause();
    }
  }

  ASSERT_THAT(pid, SyscallSucceeds());

  write_fd.reset();

  // Wait for the child to indicate that it's unmasked the signal by closing
  // the write end.
  char buf;
  ASSERT_THAT(ReadFd(read_fd.get(), &buf, 1), SyscallSucceedsWithValue(0));

  // Signal the child and wait for it to die with status 0, indicating that
  // it got the expected signal.
  EXPECT_THAT(kill(-1, SIGWINCH), SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

class KillSpecificReaperTest
    : public ::testing::TestWithParam<int (*)(void *)> {
};

constexpr pid_t kReaperPid = 1;

// Reaper process of pid namespace will ignore blockable
// signal with SIG_DFL action, such as SIGTERM.
static int KillCannotTermReaper(void *args) {
  if (getpid() != kReaperPid) {
    exit(1);
  }
  if (kill(kReaperPid, SIGTERM) != 0) {
    exit(1);
  }
  // Make sure the reaper process still alive.
  if (kill(kReaperPid, 0) != 0) {
    exit(1);
  }
  exit(0);
}

// Nonreaper process of pid namespace can recieve blockable
// signal with SIG_DFL action, such as SIGTERM.
static int KillCanTermNonReaper(void *args) {
  int status;
  if (getpid() != kReaperPid) {
    exit(1);
  }
  pid_t pid = fork();
  if (pid < 0) {
    exit(1);
  }
  if (pid == 0) {
    while (true) {
      pause();
    }
  }
  if (kill(pid, SIGTERM) != 0) {
    exit(1);
  }
  if (RetryEINTR(waitpid)(pid, &status, 0) != pid) {
      exit(1);
  }
  // NonReaper process killed by SIGTERM.
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM) {
      exit(0);
  }
  exit(1);
}

static bool ReaperActed = false;

static void ReaperSigHandler(int sig, siginfo_t* info, void* context) { ReaperActed = true; }

PosixErrorOr<Cleanup> KillReaperSetup(){
  struct sigaction sa;
  sa.sa_sigaction = ReaperSigHandler;
  return ScopedSigaction(SIGTERM, sa);
}

// Reaper process of pid namespace can recieve blockable
// signal with not SIG_DFL action, such as SIGTERM.
static int KillCanTermReaperAction(void *args) {
  if (getpid() != kReaperPid) {
    exit(1);
  }
  const auto cleanup_sigact = KillReaperSetup();
  if (kill(kReaperPid, SIGTERM) != 0) {
    exit(1);
  }
  if (kill(kReaperPid, 0) != 0) {
    exit(1);
  }
  // Reaper Process have process SIGTERM.
  if (!ReaperActed) {
    exit(1);
  }
  exit(0);
}

TEST_P(KillSpecificReaperTest, KillSigterm) {
  int stack_size = kPageSize*4;
  char * stack = reinterpret_cast<char*>(malloc(stack_size));
  int child_pid;
  // Run real case under new pid namespace.
  ASSERT_THAT(
      child_pid = clone(
          GetParam(),
          reinterpret_cast<void*>(stack + stack_size),
          CLONE_NEWPID | SIGCHLD,
          /* arg = */ nullptr),
      SyscallSucceeds());

  int status;
  ASSERT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}

INSTANTIATE_TEST_SUITE_P(
    KillReapers, KillSpecificReaperTest,
    ::testing::Values(KillCannotTermReaper, KillCanTermNonReaper, KillCanTermReaperAction));

TEST(KillTest, CannotKillInvalidPID) {
  // We need an unused pid to verify that kill fails when given one.
  //
  // There is no way to guarantee that a PID is unused, but the PID of a
  // recently exited process likely won't be reused soon.
  pid_t fake_pid = fork();
  if (fake_pid == 0) {
    _exit(0);
  }

  ASSERT_THAT(fake_pid, SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(fake_pid, &status, 0),
              SyscallSucceedsWithValue(fake_pid));
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));

  EXPECT_THAT(kill(fake_pid, 0), SyscallFailsWithErrno(ESRCH));
}

TEST(KillTest, CannotUseInvalidSignal) {
  EXPECT_THAT(kill(getpid(), 200), SyscallFailsWithErrno(EINVAL));
}

TEST(KillTest, CanKillRemoteProcess) {
  pid_t pid = fork();
  if (pid == 0) {
    while (true) {
      pause();
    }
  }

  ASSERT_THAT(pid, SyscallSucceeds());

  EXPECT_THAT(kill(pid, SIGKILL), SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGKILL, WTERMSIG(status));
}

TEST(KillTest, CanKillOwnProcess) {
  EXPECT_THAT(kill(getpid(), 0), SyscallSucceeds());
}

// Verify that you can kill a process even using a tid from a thread other than
// the group leader.
TEST(KillTest, CannotKillTid) {
  pid_t tid;
  bool tid_available = false;
  bool finished = false;
  absl::Mutex mu;
  ScopedThread t([&] {
    mu.Lock();
    tid = gettid();
    tid_available = true;
    mu.Await(absl::Condition(&finished));
    mu.Unlock();
  });
  mu.LockWhen(absl::Condition(&tid_available));
  EXPECT_THAT(kill(tid, 0), SyscallSucceeds());
  finished = true;
  mu.Unlock();
}

TEST(KillTest, SetPgid) {
  for (int i = 0; i < 10; i++) {
    // The following in the normal pattern for creating a new process group.
    // Both the parent and child process will call setpgid in order to avoid any
    // race conditions. We do this ten times to catch races.
    pid_t pid = fork();
    if (pid == 0) {
      setpgid(0, 0);
      while (true) {
        pause();
      }
    }

    ASSERT_THAT(pid, SyscallSucceeds());

    // Set the child's group and exit.
    ASSERT_THAT(setpgid(pid, pid), SyscallSucceeds());
    EXPECT_THAT(kill(pid, SIGKILL), SyscallSucceeds());

    int status;
    EXPECT_THAT(RetryEINTR(waitpid)(-pid, &status, 0),
                SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(SIGKILL, WTERMSIG(status));
  }
}

TEST(KillTest, ProcessGroups) {
  // Fork a new child.
  //
  // other_child is used as a placeholder process. We use this PID as our "does
  // not exist" process group to ensure some amount of safety. (It is still
  // possible to violate this assumption, but extremely unlikely.)
  pid_t child = fork();
  if (child == 0) {
    while (true) {
      pause();
    }
  }
  ASSERT_THAT(child, SyscallSucceeds());

  pid_t other_child = fork();
  if (other_child == 0) {
    while (true) {
      pause();
    }
  }
  ASSERT_THAT(other_child, SyscallSucceeds());

  // Ensure the kill does not succeed without the new group.
  EXPECT_THAT(kill(-child, SIGKILL), SyscallFailsWithErrno(ESRCH));

  // Put the child in its own process group.
  ASSERT_THAT(setpgid(child, child), SyscallSucceeds());

  // This should be not allowed: you can only create a new group with the same
  // id or join an existing one. The other_child group should not exist.
  ASSERT_THAT(setpgid(child, other_child), SyscallFailsWithErrno(EPERM));

  // Done with other_child; kill it.
  EXPECT_THAT(kill(other_child, SIGKILL), SyscallSucceeds());
  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(other_child, &status, 0), SyscallSucceeds());

  // Linux returns success for the no-op call.
  ASSERT_THAT(setpgid(child, child), SyscallSucceeds());

  // Kill the child's process group.
  ASSERT_THAT(kill(-child, SIGKILL), SyscallSucceeds());

  // Wait on the process group; ensure that the signal was as expected.
  EXPECT_THAT(RetryEINTR(waitpid)(-child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGKILL, WTERMSIG(status));

  // Try to kill the process group again; ensure that the wait fails.
  EXPECT_THAT(kill(-child, SIGKILL), SyscallFailsWithErrno(ESRCH));
  EXPECT_THAT(RetryEINTR(waitpid)(-child, &status, 0),
              SyscallFailsWithErrno(ECHILD));
}

TEST(KillTest, ChildDropsPrivsCannotKill) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const int uid = absl::GetFlag(FLAGS_scratch_uid);
  const int gid = absl::GetFlag(FLAGS_scratch_gid);

  // Create the child that drops privileges and tries to kill the parent.
  pid_t pid = fork();
  if (pid == 0) {
    TEST_PCHECK(setresgid(gid, gid, gid) == 0);
    MaybeSave();

    TEST_PCHECK(setresuid(uid, uid, uid) == 0);
    MaybeSave();

    // setresuid should have dropped CAP_KILL. Make sure.
    TEST_CHECK(!HaveCapability(CAP_KILL).ValueOrDie());

    // Try to kill parent with every signal-sending syscall possible.
    pid_t parent = getppid();

    TEST_CHECK(kill(parent, SIGKILL) < 0);
    TEST_PCHECK_MSG(errno == EPERM, "kill failed with wrong errno");
    MaybeSave();

    TEST_CHECK(tgkill(parent, parent, SIGKILL) < 0);
    TEST_PCHECK_MSG(errno == EPERM, "tgkill failed with wrong errno");
    MaybeSave();

    TEST_CHECK(syscall(SYS_tkill, parent, SIGKILL) < 0);
    TEST_PCHECK_MSG(errno == EPERM, "tkill failed with wrong errno");
    MaybeSave();

    siginfo_t uinfo;
    uinfo.si_code = -1;  // SI_QUEUE (allowed).

    TEST_CHECK(syscall(SYS_rt_sigqueueinfo, parent, SIGKILL, &uinfo) < 0);
    TEST_PCHECK_MSG(errno == EPERM, "rt_sigqueueinfo failed with wrong errno");
    MaybeSave();

    TEST_CHECK(syscall(SYS_rt_tgsigqueueinfo, parent, parent, SIGKILL, &uinfo) <
               0);
    TEST_PCHECK_MSG(errno == EPERM, "rt_sigqueueinfo failed with wrong errno");
    MaybeSave();

    _exit(0);
  }

  ASSERT_THAT(pid, SyscallSucceeds());

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status = " << status;
}

TEST(KillTest, CanSIGCONTSameSession) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  pid_t stopped_child = fork();
  if (stopped_child == 0) {
    raise(SIGSTOP);
    _exit(0);
  }

  ASSERT_THAT(stopped_child, SyscallSucceeds());

  // Put the child in its own process group. The child and parent process
  // groups also share a session.
  ASSERT_THAT(setpgid(stopped_child, stopped_child), SyscallSucceeds());

  // Make sure child stopped.
  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(stopped_child, &status, WUNTRACED),
              SyscallSucceedsWithValue(stopped_child));
  EXPECT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << "status " << status;

  const int uid = absl::GetFlag(FLAGS_scratch_uid);
  const int gid = absl::GetFlag(FLAGS_scratch_gid);

  // Drop privileges only in child process, or else this parent process won't be
  // able to open some log files after the test ends.
  pid_t other_child = fork();
  if (other_child == 0) {
    // Drop privileges.
    TEST_PCHECK(setresgid(gid, gid, gid) == 0);
    MaybeSave();

    TEST_PCHECK(setresuid(uid, uid, uid) == 0);
    MaybeSave();

    // setresuid should have dropped CAP_KILL.
    TEST_CHECK(!HaveCapability(CAP_KILL).ValueOrDie());

    // Child 2 and child should now not share a thread group and any UIDs.
    // Child 2 should have no privileges. That means any signal other than
    // SIGCONT should fail.
    TEST_CHECK(kill(stopped_child, SIGKILL) < 0);
    TEST_PCHECK_MSG(errno == EPERM, "kill failed with wrong errno");
    MaybeSave();

    TEST_PCHECK(kill(stopped_child, SIGCONT) == 0);
    MaybeSave();

    _exit(0);
  }

  ASSERT_THAT(stopped_child, SyscallSucceeds());

  // Make sure child exited normally.
  EXPECT_THAT(RetryEINTR(waitpid)(stopped_child, &status, 0),
              SyscallSucceedsWithValue(stopped_child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;

  // Make sure other_child exited normally.
  EXPECT_THAT(RetryEINTR(waitpid)(other_child, &status, 0),
              SyscallSucceedsWithValue(other_child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << "status " << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
