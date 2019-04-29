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
#include "test/util/logging.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

static int tkill(pid_t tid, int sig) {
  int ret;
  do {
    // NOTE(b/25434735): tkill(2) could return EAGAIN for RT signals.
    ret = syscall(SYS_tkill, tid, sig);
  } while (ret == -1 && errno == EAGAIN);
  return ret;
}

TEST(TkillTest, InvalidTID) {
  EXPECT_THAT(tkill(-1, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(tkill(0, 0), SyscallFailsWithErrno(EINVAL));
}

TEST(TkillTest, ValidTID) {
  EXPECT_THAT(tkill(gettid(), 0), SyscallSucceeds());
}

void SigHandler(int sig, siginfo_t* info, void* context) {
  TEST_CHECK(sig == SIGRTMAX);
  TEST_CHECK(info->si_pid == getpid());
  TEST_CHECK(info->si_uid == getuid());
  TEST_CHECK(info->si_code == SI_TKILL);
}

// Test with a real signal.
TEST(TkillTest, ValidTIDAndRealSignal) {
  struct sigaction sa;
  sa.sa_sigaction = SigHandler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  ASSERT_THAT(sigaction(SIGRTMAX, &sa, nullptr), SyscallSucceeds());
  // InitGoogle blocks all RT signals, so we need undo it.
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGRTMAX);
  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &unblock, nullptr), SyscallSucceeds());
  EXPECT_THAT(tkill(gettid(), SIGRTMAX), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
