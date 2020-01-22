// Copyright 2019 The gVisor Authors.
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
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/rseq/test.h"
#include "test/syscalls/linux/rseq/uapi.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Syscall test for rseq (restartable sequences).
//
// We must be very careful about how these tests are written. Each thread may
// only have one struct rseq registration, which may be done automatically at
// thread start (as of 2019-11-13, glibc does *not* support rseq and thus does
// not do so).
//
// Testing of rseq is thus done primarily in a child process with no
// registration. This means exec'ing a nostdlib binary, as rseq registration can
// only be cleared by execve (or knowing the old rseq address), and glibc (based
// on the current unmerged patches) register rseq before calling main()).

int RSeq(struct rseq* rseq, uint32_t rseq_len, int flags, uint32_t sig) {
  return syscall(kRseqSyscall, rseq, rseq_len, flags, sig);
}

// Returns true if this kernel supports the rseq syscall.
PosixErrorOr<bool> RSeqSupported() {
  // We have to be careful here, there are three possible cases:
  //
  // 1. rseq is not supported -> ENOSYS
  // 2. rseq is supported and not registered -> success, but we should
  //    unregister.
  // 3. rseq is supported and registered -> EINVAL (most likely).

  // The only validation done on new registrations is that rseq is aligned and
  // writable.
  rseq rseq = {};
  int ret = RSeq(&rseq, sizeof(rseq), 0, 0);
  if (ret == 0) {
    // Successfully registered, rseq is supported. Unregister.
    ret = RSeq(&rseq, sizeof(rseq), kRseqFlagUnregister, 0);
    if (ret != 0) {
      return PosixError(errno);
    }
    return true;
  }

  switch (errno) {
    case ENOSYS:
      // Not supported.
      return false;
    case EINVAL:
      // Supported, but already registered. EINVAL returned because we provided
      // a different address.
      return true;
    default:
      // Unknown error.
      return PosixError(errno);
  }
}

constexpr char kRseqBinary[] = "test/syscalls/linux/rseq/rseq";

void RunChildTest(std::string test_case, int want_status) {
  std::string path = RunfilePath(kRseqBinary);

  pid_t child_pid = -1;
  int execve_errno = 0;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(path, {path, test_case}, {}, &child_pid, &execve_errno));

  ASSERT_GT(child_pid, 0);
  ASSERT_EQ(execve_errno, 0);

  int status = 0;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  ASSERT_EQ(status, want_status);
}

// Test that rseq must be aligned.
TEST(RseqTest, Unaligned) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestUnaligned, 0);
}

// Sanity test that registration works.
TEST(RseqTest, Register) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestRegister, 0);
}

// Registration can't be done twice.
TEST(RseqTest, DoubleRegister) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestDoubleRegister, 0);
}

// Registration can be done again after unregister.
TEST(RseqTest, RegisterUnregister) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestRegisterUnregister, 0);
}

// The pointer to rseq must match on register/unregister.
TEST(RseqTest, UnregisterDifferentPtr) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestUnregisterDifferentPtr, 0);
}

// The signature must match on register/unregister.
TEST(RseqTest, UnregisterDifferentSignature) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestUnregisterDifferentSignature, 0);
}

// The CPU ID is initialized.
TEST(RseqTest, CPU) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestCPU, 0);
}

// Critical section is eventually aborted.
TEST(RseqTest, Abort) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestAbort, 0);
}

// Abort may be before the critical section.
TEST(RseqTest, AbortBefore) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestAbortBefore, 0);
}

// Signature must match.
TEST(RseqTest, AbortSignature) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestAbortSignature, SIGSEGV);
}

// Abort must not be in the critical section.
TEST(RseqTest, AbortPreCommit) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestAbortPreCommit, SIGSEGV);
}

// rseq.rseq_cs is cleared on abort.
TEST(RseqTest, AbortClearsCS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestAbortClearsCS, 0);
}

// rseq.rseq_cs is cleared on abort outside of critical section.
TEST(RseqTest, InvalidAbortClearsCS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(RSeqSupported()));

  RunChildTest(kRseqTestInvalidAbortClearsCS, 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
