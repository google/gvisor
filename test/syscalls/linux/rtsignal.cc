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

#include <cerrno>
#include <csignal>

#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// saved_info is set by the handler.
siginfo_t saved_info;

// has_saved_info is set to true by the handler.
volatile bool has_saved_info;

void SigHandler(int sig, siginfo_t* info, void* context) {
  // Copy to the given info.
  saved_info = *info;
  has_saved_info = true;
}

void ClearSavedInfo() {
  // Clear the cached info.
  memset(&saved_info, 0, sizeof(saved_info));
  has_saved_info = false;
}

PosixErrorOr<Cleanup> SetupSignalHandler(int sig) {
  struct sigaction sa;
  sa.sa_sigaction = SigHandler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  return ScopedSigaction(sig, sa);
}

class RtSignalTest : public ::testing::Test {
 protected:
  void SetUp() override {
    action_cleanup_ = ASSERT_NO_ERRNO_AND_VALUE(SetupSignalHandler(SIGUSR1));
    mask_cleanup_ =
        ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGUSR1));
  }

  void TearDown() override { ClearSavedInfo(); }

 private:
  Cleanup action_cleanup_;
  Cleanup mask_cleanup_;
};

static int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t* uinfo) {
  int ret;
  do {
    // NOTE(b/25434735): rt_sigqueueinfo(2) could return EAGAIN for RT signals.
    ret = syscall(SYS_rt_sigqueueinfo, tgid, sig, uinfo);
  } while (ret == -1 && errno == EAGAIN);
  return ret;
}

TEST_F(RtSignalTest, InvalidTID) {
  siginfo_t uinfo;
  // Depending on the kernel version, these calls may fail with
  // ESRCH (goobunutu machines) or EPERM (production machines). Thus,
  // the test simply ensures that they do fail.
  EXPECT_THAT(rt_sigqueueinfo(-1, SIGUSR1, &uinfo), SyscallFails());
  EXPECT_FALSE(has_saved_info);
  EXPECT_THAT(rt_sigqueueinfo(0, SIGUSR1, &uinfo), SyscallFails());
  EXPECT_FALSE(has_saved_info);
}

TEST_F(RtSignalTest, InvalidCodes) {
  siginfo_t uinfo;

  // We need a child for the code checks to apply. If the process is delivering
  // to itself, then it can use whatever codes it wants and they will go
  // through.
  pid_t child = fork();
  if (child == 0) {
    _exit(1);
  }
  ASSERT_THAT(child, SyscallSucceeds());

  // These are not allowed for child processes.
  uinfo.si_code = 0;  // SI_USER.
  EXPECT_THAT(rt_sigqueueinfo(child, SIGUSR1, &uinfo),
              SyscallFailsWithErrno(EPERM));
  uinfo.si_code = 0x80;  // SI_KERNEL.
  EXPECT_THAT(rt_sigqueueinfo(child, SIGUSR1, &uinfo),
              SyscallFailsWithErrno(EPERM));
  uinfo.si_code = -6;  // SI_TKILL.
  EXPECT_THAT(rt_sigqueueinfo(child, SIGUSR1, &uinfo),
              SyscallFailsWithErrno(EPERM));
  uinfo.si_code = -1;  // SI_QUEUE (allowed).
  EXPECT_THAT(rt_sigqueueinfo(child, SIGUSR1, &uinfo), SyscallSucceeds());

  // Join the child process.
  EXPECT_THAT(waitpid(child, nullptr, 0), SyscallSucceeds());
}

TEST_F(RtSignalTest, ValueDelivered) {
  siginfo_t uinfo;
  uinfo.si_code = -1;  // SI_QUEUE (allowed).
  uinfo.si_errno = 0x1234;

  EXPECT_EQ(saved_info.si_errno, 0x0);
  EXPECT_THAT(rt_sigqueueinfo(getpid(), SIGUSR1, &uinfo), SyscallSucceeds());
  EXPECT_TRUE(has_saved_info);
  EXPECT_EQ(saved_info.si_errno, 0x1234);
}

TEST_F(RtSignalTest, SignoMatch) {
  auto action2_cleanup = ASSERT_NO_ERRNO_AND_VALUE(SetupSignalHandler(SIGUSR2));
  auto mask2_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGUSR2));

  siginfo_t uinfo;
  uinfo.si_code = -1;  // SI_QUEUE (allowed).

  EXPECT_THAT(rt_sigqueueinfo(getpid(), SIGUSR1, &uinfo), SyscallSucceeds());
  EXPECT_TRUE(has_saved_info);
  EXPECT_EQ(saved_info.si_signo, SIGUSR1);

  ClearSavedInfo();

  EXPECT_THAT(rt_sigqueueinfo(getpid(), SIGUSR2, &uinfo), SyscallSucceeds());
  EXPECT_TRUE(has_saved_info);
  EXPECT_EQ(saved_info.si_signo, SIGUSR2);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // These tests depend on delivering SIGUSR1/2 to the main thread (so they can
  // synchronously check has_saved_info). Block these so that any other threads
  // created by TestInit will also have them blocked.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);

  return RUN_ALL_TESTS();
}
