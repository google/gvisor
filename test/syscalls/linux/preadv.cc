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
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <string>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

// Stress copy-on-write. Attempts to reproduce b/38430174.
TEST(PreadvTest, MMConcurrencyStress) {
  // Fill a one-page file with zeroes (the contents don't really matter).
  const auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      /* parent = */ GetAbsoluteTestTmpdir(),
      /* content = */ std::string(kPageSize, 0), TempPath::kDefaultFileMode));
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDONLY));

  // Get a one-page private mapping to read to.
  const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));

  // Repeatedly fork in a separate thread to force the mapping to become
  // copy-on-write.
  std::atomic<bool> done(false);
  std::atomic<uint64_t> reads(0);
  const ScopedThread t([&] {
    while (!done.load()) {
      const uint64_t reads_prev = reads.load(std::memory_order_acquire);
      const pid_t pid = fork();
      TEST_CHECK(pid >= 0);
      if (pid == 0) {
        // In child. The parent was obviously multithreaded, so it's neither
        // safe nor necessary to do much more than exit.
        syscall(SYS_exit_group, 0);
      }
      int status;
      ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
                  SyscallSucceedsWithValue(pid));
      EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
          << "status = " << status;
      // When reads are slow (e.g. the file is FUSE-backed), we can trigger
      // save/restore cycles (via SyscallSucceedsWithValue above) faster than a
      // single preadv() can be completed, causing the test to run
      // indefinitely. Checking for EINTR doesn't solve this, since preadv()
      // returns -ERESTARTSYS after being interrupted, causing it to
      // automatically be restarted after save/restore. Avoid this by ensuring
      // that at least one read is completed between each iteration of this
      // loop.
      while (reads.load(std::memory_order_relaxed) == reads_prev) {
        if (done.load()) {
          break;
        }
      }
    }
  });

  // Repeatedly read to the mapping.
  struct iovec iov[2];
  iov[0].iov_base = m.ptr();
  iov[0].iov_len = kPageSize / 2;
  iov[1].iov_base = reinterpret_cast<void*>(m.addr() + kPageSize / 2);
  iov[1].iov_len = kPageSize / 2;
  constexpr absl::Duration kTestDuration = absl::Seconds(5);
  const absl::Time end = absl::Now() + kTestDuration;
  while (absl::Now() < end) {
    // Among other causes, save/restore cycles may cause interruptions
    // resulting in partial reads, so we don't expect any particular return
    // value. We don't use RetryEINTR here because we want to check for
    // absl::Now() < end between preadv() attempts.
    int ret = preadv(fd.get(), iov, 2, 0);
    int errnum = errno;
    reads.fetch_add(1, std::memory_order_release);
    if (ret < 0) {
      EXPECT_EQ(errnum, EINTR);
    }
  }

  // Stop the other thread.
  done.store(true);

  // The test passes if it neither deadlocks nor crashes the OS.
}

// This test calls preadv with an O_PATH fd.
TEST(PreadvTest, PreadvWithOpath) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  struct iovec iov;
  iov.iov_base = nullptr;
  iov.iov_len = 0;

  EXPECT_THAT(preadv(fd.get(), &iov, 1, 0), SyscallFailsWithErrno(EBADF));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
