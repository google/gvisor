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

#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <atomic>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// For this set of tests to run, they must be run with coverage enabled. On
// native Linux, this involves compiling the kernel with kcov enabled. For
// gVisor, we need to enable the Go coverage tool, e.g. bazel test --
// collect_coverage_data --instrumentation_filter=//pkg/... <test>.

constexpr char kcovPath[] = "/sys/kernel/debug/kcov";
constexpr int kSize = 4096;
constexpr int KCOV_INIT_TRACE = 0x80086301;
constexpr int KCOV_ENABLE = 0x6364;
constexpr int KCOV_DISABLE = 0x6365;

uint64_t* KcovMmap(int fd) {
  return (uint64_t*)mmap(nullptr, kSize * sizeof(uint64_t),
                         PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
}

TEST(KcovTest, Kcov) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  int fd;
  ASSERT_THAT(fd = open(kcovPath, O_RDWR),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ENOENT)));
  // Kcov not available.
  SKIP_IF(errno == ENOENT);
  auto fd_closer = Cleanup([fd]() { close(fd); });

  ASSERT_THAT(ioctl(fd, KCOV_INIT_TRACE, kSize), SyscallSucceeds());
  uint64_t* area = KcovMmap(fd);
  ASSERT_TRUE(area != MAP_FAILED);
  ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallSucceeds());

  for (int i = 0; i < 10; i++) {
    // Make some syscalls to generate coverage data.
    ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallFailsWithErrno(EINVAL));
  }

  uint64_t num_pcs = *(uint64_t*)(area);
  EXPECT_GT(num_pcs, 0);
  for (uint64_t i = 1; i <= num_pcs; i++) {
    // Verify that PCs are in the standard kernel range.
    EXPECT_GT(area[i], 0xffffffff7fffffffL);
  }

  ASSERT_THAT(ioctl(fd, KCOV_DISABLE, 0), SyscallSucceeds());
}

TEST(KcovTest, PrematureMmap) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  int fd;
  ASSERT_THAT(fd = open(kcovPath, O_RDWR),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ENOENT)));
  // Kcov not available.
  SKIP_IF(errno == ENOENT);
  auto fd_closer = Cleanup([fd]() { close(fd); });

  // Cannot mmap before KCOV_INIT_TRACE.
  uint64_t* area = KcovMmap(fd);
  ASSERT_TRUE(area == MAP_FAILED);
}

// Tests that multiple kcov fds can be used simultaneously.
TEST(KcovTest, MultipleFds) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  int fd1;
  ASSERT_THAT(fd1 = open(kcovPath, O_RDWR),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ENOENT)));
  // Kcov not available.
  SKIP_IF(errno == ENOENT);

  int fd2;
  ASSERT_THAT(fd2 = open(kcovPath, O_RDWR), SyscallSucceeds());
  auto fd_closer = Cleanup([fd1, fd2]() {
    close(fd1);
    close(fd2);
  });

  auto t1 = ScopedThread([&] {
    ASSERT_THAT(ioctl(fd1, KCOV_INIT_TRACE, kSize), SyscallSucceeds());
    uint64_t* area = KcovMmap(fd1);
    ASSERT_TRUE(area != MAP_FAILED);
    ASSERT_THAT(ioctl(fd1, KCOV_ENABLE, 0), SyscallSucceeds());
  });

  ASSERT_THAT(ioctl(fd2, KCOV_INIT_TRACE, kSize), SyscallSucceeds());
  uint64_t* area = KcovMmap(fd2);
  ASSERT_TRUE(area != MAP_FAILED);
  ASSERT_THAT(ioctl(fd2, KCOV_ENABLE, 0), SyscallSucceeds());
}

// Tests behavior for two threads trying to use the same kcov fd.
TEST(KcovTest, MultipleThreads) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  int fd;
  ASSERT_THAT(fd = open(kcovPath, O_RDWR),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ENOENT)));
  // Kcov not available.
  SKIP_IF(errno == ENOENT);
  auto fd_closer = Cleanup([fd]() { close(fd); });

  // Test the behavior of multiple threads trying to use the same kcov fd
  // simultaneously.
  std::atomic<bool> t1_enabled(false), t1_disabled(false), t2_failed(false),
      t2_exited(false);
  auto t1 = ScopedThread([&] {
    ASSERT_THAT(ioctl(fd, KCOV_INIT_TRACE, kSize), SyscallSucceeds());
    uint64_t* area = KcovMmap(fd);
    ASSERT_TRUE(area != MAP_FAILED);
    ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallSucceeds());
    t1_enabled = true;

    // After t2 has made sure that enabling kcov again fails, disable it.
    while (!t2_failed) {
      sched_yield();
    }
    ASSERT_THAT(ioctl(fd, KCOV_DISABLE, 0), SyscallSucceeds());
    t1_disabled = true;

    // Wait for t2 to enable kcov and then exit, after which we should be able
    // to enable kcov again, without needing to set up a new memory mapping.
    while (!t2_exited) {
      sched_yield();
    }
    ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallSucceeds());
  });

  auto t2 = ScopedThread([&] {
    // Wait for t1 to enable kcov, and make sure that enabling kcov again fails.
    while (!t1_enabled) {
      sched_yield();
    }
    ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallFailsWithErrno(EINVAL));
    t2_failed = true;

    // Wait for t1 to disable kcov, after which using fd should now succeed.
    while (!t1_disabled) {
      sched_yield();
    }
    uint64_t* area = KcovMmap(fd);
    ASSERT_TRUE(area != MAP_FAILED);
    ASSERT_THAT(ioctl(fd, KCOV_ENABLE, 0), SyscallSucceeds());
  });

  t2.Join();
  t2_exited = true;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
