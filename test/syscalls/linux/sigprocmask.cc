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
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Signals numbers used for testing.
static constexpr int kTestSignal1 = SIGUSR1;
static constexpr int kTestSignal2 = SIGUSR2;

static int raw_sigprocmask(int how, const sigset_t* set, sigset_t* oldset) {
  return syscall(SYS_rt_sigprocmask, how, set, oldset, _NSIG / 8);
}

// count of the number of signals received
int signal_count[kMaxSignal + 1];

// signal handler increments the signal counter
void SigHandler(int sig, siginfo_t* info, void* context) {
  TEST_CHECK(sig > 0 && sig <= kMaxSignal);
  signal_count[sig] += 1;
}

// The test fixture saves and restores the signal mask and
// sets up handlers for kTestSignal1 and kTestSignal2.
class SigProcMaskTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Save the current signal mask.
    EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &mask_),
                SyscallSucceeds());

    // Setup signal handlers for kTestSignal1 and kTestSignal2.
    struct sigaction sa;
    sa.sa_sigaction = SigHandler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    EXPECT_THAT(sigaction(kTestSignal1, &sa, &sa_test_sig_1_),
                SyscallSucceeds());
    EXPECT_THAT(sigaction(kTestSignal2, &sa, &sa_test_sig_2_),
                SyscallSucceeds());

    // Clear the signal counters.
    memset(signal_count, 0, sizeof(signal_count));
  }

  void TearDown() override {
    // Restore the signal mask.
    EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, &mask_, nullptr),
                SyscallSucceeds());

    // Restore the signal handlers for kTestSignal1 and kTestSignal2.
    EXPECT_THAT(sigaction(kTestSignal1, &sa_test_sig_1_, nullptr),
                SyscallSucceeds());
    EXPECT_THAT(sigaction(kTestSignal2, &sa_test_sig_2_, nullptr),
                SyscallSucceeds());
  }

 private:
  sigset_t mask_;
  struct sigaction sa_test_sig_1_;
  struct sigaction sa_test_sig_2_;
};

// Both sigsets nullptr should succeed and do nothing.
TEST_F(SigProcMaskTest, NullAddress) {
  EXPECT_THAT(raw_sigprocmask(SIG_BLOCK, nullptr, NULL), SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_UNBLOCK, nullptr, NULL), SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, NULL), SyscallSucceeds());
}

// Bad address for either sigset should fail with EFAULT.
TEST_F(SigProcMaskTest, BadAddress) {
  sigset_t* bad_addr = reinterpret_cast<sigset_t*>(-1);

  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, bad_addr, nullptr),
              SyscallFailsWithErrno(EFAULT));

  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, bad_addr),
              SyscallFailsWithErrno(EFAULT));
}

// Bad value of the "how" parameter should fail with EINVAL.
TEST_F(SigProcMaskTest, BadParameter) {
  int bad_param_1 = -1;
  int bad_param_2 = 42;

  sigset_t set1;
  sigemptyset(&set1);

  EXPECT_THAT(raw_sigprocmask(bad_param_1, &set1, nullptr),
              SyscallFailsWithErrno(EINVAL));

  EXPECT_THAT(raw_sigprocmask(bad_param_2, &set1, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

// Check that we can get the current signal mask.
TEST_F(SigProcMaskTest, GetMask) {
  sigset_t set1;
  sigset_t set2;

  sigemptyset(&set1);
  sigfillset(&set2);
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &set1), SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &set2), SyscallSucceeds());
  EXPECT_THAT(set1, EqualsSigset(set2));
}

// Check that we can set the signal mask.
TEST_F(SigProcMaskTest, SetMask) {
  sigset_t actual;
  sigset_t expected;

  // Try to mask all signals
  sigfillset(&expected);
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, &expected, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &actual),
              SyscallSucceeds());
  // sigprocmask() should have silently ignored SIGKILL and SIGSTOP.
  sigdelset(&expected, SIGSTOP);
  sigdelset(&expected, SIGKILL);
  EXPECT_THAT(actual, EqualsSigset(expected));

  // Try to clear the signal mask
  sigemptyset(&expected);
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, &expected, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &actual),
              SyscallSucceeds());
  EXPECT_THAT(actual, EqualsSigset(expected));

  // Try to set a mask with one signal.
  sigemptyset(&expected);
  sigaddset(&expected, kTestSignal1);
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, &expected, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &actual),
              SyscallSucceeds());
  EXPECT_THAT(actual, EqualsSigset(expected));
}

// Check that we can add and remove signals.
TEST_F(SigProcMaskTest, BlockUnblock) {
  sigset_t actual;
  sigset_t expected;

  // Try to set a mask with one signal.
  sigemptyset(&expected);
  sigaddset(&expected, kTestSignal1);
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, &expected, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &actual),
              SyscallSucceeds());
  EXPECT_THAT(actual, EqualsSigset(expected));

  // Try to add another signal.
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, kTestSignal2);
  EXPECT_THAT(raw_sigprocmask(SIG_BLOCK, &block, nullptr), SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &actual),
              SyscallSucceeds());
  sigaddset(&expected, kTestSignal2);
  EXPECT_THAT(actual, EqualsSigset(expected));

  // Try to remove a signal.
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, kTestSignal1);
  EXPECT_THAT(raw_sigprocmask(SIG_UNBLOCK, &unblock, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, nullptr, &actual),
              SyscallSucceeds());
  sigdelset(&expected, kTestSignal1);
  EXPECT_THAT(actual, EqualsSigset(expected));
}

// Test that the signal mask actually blocks signals.
TEST_F(SigProcMaskTest, SignalHandler) {
  sigset_t mask;

  // clear the signal mask
  sigemptyset(&mask);
  EXPECT_THAT(raw_sigprocmask(SIG_SETMASK, &mask, nullptr), SyscallSucceeds());

  // Check the initial signal counts.
  EXPECT_EQ(0, signal_count[kTestSignal1]);
  EXPECT_EQ(0, signal_count[kTestSignal2]);

  // Check that both kTestSignal1 and kTestSignal2 are not blocked.
  raise(kTestSignal1);
  raise(kTestSignal2);
  EXPECT_EQ(1, signal_count[kTestSignal1]);
  EXPECT_EQ(1, signal_count[kTestSignal2]);

  // Block kTestSignal1.
  sigaddset(&mask, kTestSignal1);
  EXPECT_THAT(raw_sigprocmask(SIG_BLOCK, &mask, nullptr), SyscallSucceeds());

  // Check that kTestSignal1 is blocked.
  raise(kTestSignal1);
  raise(kTestSignal2);
  EXPECT_EQ(1, signal_count[kTestSignal1]);
  EXPECT_EQ(2, signal_count[kTestSignal2]);

  // Unblock kTestSignal1.
  sigaddset(&mask, kTestSignal1);
  EXPECT_THAT(raw_sigprocmask(SIG_UNBLOCK, &mask, nullptr), SyscallSucceeds());

  // Check that the unblocked kTestSignal1 has been delivered.
  EXPECT_EQ(2, signal_count[kTestSignal1]);
  EXPECT_EQ(2, signal_count[kTestSignal2]);
}

// Check that sigprocmask correctly handles aliasing of the set and oldset
// pointers.
TEST_F(SigProcMaskTest, AliasedSets) {
  sigset_t mask;

  // Set a mask in which only kTestSignal1 is blocked.
  sigset_t mask1;
  sigemptyset(&mask1);
  sigaddset(&mask1, kTestSignal1);
  mask = mask1;
  ASSERT_THAT(raw_sigprocmask(SIG_SETMASK, &mask, nullptr), SyscallSucceeds());

  // Exchange it with a mask in which only kTestSignal2 is blocked.
  sigset_t mask2;
  sigemptyset(&mask2);
  sigaddset(&mask2, kTestSignal2);
  mask = mask2;
  ASSERT_THAT(raw_sigprocmask(SIG_SETMASK, &mask, &mask), SyscallSucceeds());

  // Check that the exchange succeeeded:
  // mask should now contain the previously-set mask blocking only kTestSignal1.
  EXPECT_THAT(mask, EqualsSigset(mask1));
  // The current mask should block only kTestSignal2.
  ASSERT_THAT(raw_sigprocmask(0, nullptr, &mask), SyscallSucceeds());
  EXPECT_THAT(mask, EqualsSigset(mask2));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
