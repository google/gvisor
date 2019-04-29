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

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#include "gmock/gmock.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/rlimit_util.h"
#include "test/util/test_util.h"

using ::testing::_;

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<bool> CanMlock() {
  struct rlimit rlim;
  if (getrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
    return PosixError(errno, "getrlimit(RLIMIT_MEMLOCK)");
  }
  if (rlim.rlim_cur != 0) {
    return true;
  }
  return HaveCapability(CAP_IPC_LOCK);
}

// Returns true if the page containing addr is mlocked.
bool IsPageMlocked(uintptr_t addr) {
  // This relies on msync(MS_INVALIDATE) interacting correctly with mlocked
  // pages, which is tested for by the MsyncInvalidate case below.
  int const rv = msync(reinterpret_cast<void*>(addr & ~(kPageSize - 1)),
                       kPageSize, MS_ASYNC | MS_INVALIDATE);
  if (rv == 0) {
    return false;
  }
  // This uses TEST_PCHECK_MSG since it's used in subprocesses.
  TEST_PCHECK_MSG(errno == EBUSY, "msync failed with unexpected errno");
  return true;
}


TEST(MlockTest, Basic) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
}

TEST(MlockTest, ProtNone) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()),
              SyscallFailsWithErrno(ENOMEM));
  // ENOMEM is returned because mlock can't populate the page, but it's still
  // considered locked.
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
}

TEST(MlockTest, MadviseDontneed) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_THAT(madvise(mapping.ptr(), mapping.len(), MADV_DONTNEED),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MlockTest, MsyncInvalidate) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_THAT(msync(mapping.ptr(), mapping.len(), MS_ASYNC | MS_INVALIDATE),
              SyscallFailsWithErrno(EBUSY));
  EXPECT_THAT(msync(mapping.ptr(), mapping.len(), MS_SYNC | MS_INVALIDATE),
              SyscallFailsWithErrno(EBUSY));
}

TEST(MlockTest, Fork) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
  EXPECT_THAT(
      InForkedProcess([&] { TEST_CHECK(!IsPageMlocked(mapping.addr())); }),
      IsPosixErrorOkAndHolds(0));
}

TEST(MlockTest, RlimitMemlockZero) {
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_IPC_LOCK))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_IPC_LOCK, false));
  }
  Cleanup reset_rlimit =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSetSoftRlimit(RLIMIT_MEMLOCK, 0));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()),
              SyscallFailsWithErrno(EPERM));
}

TEST(MlockTest, RlimitMemlockInsufficient) {
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_IPC_LOCK))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_IPC_LOCK, false));
  }
  Cleanup reset_rlimit =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSetSoftRlimit(RLIMIT_MEMLOCK, kPageSize));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()),
              SyscallFailsWithErrno(ENOMEM));
}

TEST(MunlockTest, Basic) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(munlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
}

TEST(MunlockTest, NotLocked) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  EXPECT_THAT(munlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
}

// There is currently no test for mlockall(MCL_CURRENT) because the default
// RLIMIT_MEMLOCK of 64 KB is insufficient to actually invoke
// mlockall(MCL_CURRENT).

TEST(MlockallTest, Future) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));

  // Run this test in a separate (single-threaded) subprocess to ensure that a
  // background thread doesn't try to mmap a large amount of memory, fail due
  // to hitting RLIMIT_MEMLOCK, and explode the process violently.
  EXPECT_THAT(InForkedProcess([] {
                auto const mapping =
                    MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE)
                        .ValueOrDie();
                TEST_CHECK(!IsPageMlocked(mapping.addr()));
                TEST_PCHECK(mlockall(MCL_FUTURE) == 0);
                // Ensure that mlockall(MCL_FUTURE) is turned off before the end
                // of the test, as otherwise mmaps may fail unexpectedly.
                Cleanup do_munlockall([] { TEST_PCHECK(munlockall() == 0); });
                auto const mapping2 = ASSERT_NO_ERRNO_AND_VALUE(
                    MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
                TEST_CHECK(IsPageMlocked(mapping2.addr()));
                // Fire munlockall() and check that it disables
                // mlockall(MCL_FUTURE).
                do_munlockall.Release()();
                auto const mapping3 = ASSERT_NO_ERRNO_AND_VALUE(
                    MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
                TEST_CHECK(!IsPageMlocked(mapping2.addr()));
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST(MunlockallTest, Basic) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED));
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(munlockall(), SyscallSucceeds());
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
}

#ifndef SYS_mlock2
#ifdef __x86_64__
#define SYS_mlock2 325
#endif
#endif

#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 0x01  // Linux: include/uapi/asm-generic/mman-common.h
#endif

#ifdef SYS_mlock2

int mlock2(void const* addr, size_t len, int flags) {
  return syscall(SYS_mlock2, addr, len, flags);
}

TEST(Mlock2Test, NoFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock2(mapping.ptr(), mapping.len(), 0), SyscallSucceeds());
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
}

TEST(Mlock2Test, MlockOnfault) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
  ASSERT_THAT(mlock2(mapping.ptr(), mapping.len(), MLOCK_ONFAULT),
              SyscallSucceeds());
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
}

TEST(Mlock2Test, UnknownFlags) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  EXPECT_THAT(mlock2(mapping.ptr(), mapping.len(), ~0),
              SyscallFailsWithErrno(EINVAL));
}

#endif  // defined(SYS_mlock2)

TEST(MapLockedTest, Basic) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED));
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));
  EXPECT_THAT(munlock(mapping.ptr(), mapping.len()), SyscallSucceeds());
  EXPECT_FALSE(IsPageMlocked(mapping.addr()));
}

TEST(MapLockedTest, RlimitMemlockZero) {
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_IPC_LOCK))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_IPC_LOCK, false));
  }
  Cleanup reset_rlimit =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSetSoftRlimit(RLIMIT_MEMLOCK, 0));
  EXPECT_THAT(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED),
      PosixErrorIs(EPERM, _));
}

TEST(MapLockedTest, RlimitMemlockInsufficient) {
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_IPC_LOCK))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_IPC_LOCK, false));
  }
  Cleanup reset_rlimit =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSetSoftRlimit(RLIMIT_MEMLOCK, kPageSize));
  EXPECT_THAT(
      MmapAnon(2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED),
      PosixErrorIs(EAGAIN, _));
}

TEST(MremapLockedTest, Basic) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED));
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));

  void* addr = mremap(mapping.ptr(), mapping.len(), 2 * mapping.len(),
                      MREMAP_MAYMOVE, nullptr);
  if (addr == MAP_FAILED) {
    FAIL() << "mremap failed: " << errno << " (" << strerror(errno) << ")";
  }
  mapping.release();
  mapping.reset(addr, 2 * mapping.len());
  EXPECT_TRUE(IsPageMlocked(reinterpret_cast<uintptr_t>(addr)));
}

TEST(MremapLockedTest, RlimitMemlockZero) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED));
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));

  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_IPC_LOCK))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_IPC_LOCK, false));
  }
  Cleanup reset_rlimit =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSetSoftRlimit(RLIMIT_MEMLOCK, 0));
  void* addr = mremap(mapping.ptr(), mapping.len(), 2 * mapping.len(),
                      MREMAP_MAYMOVE, nullptr);
  EXPECT_TRUE(addr == MAP_FAILED && errno == EAGAIN)
      << "addr = " << addr << ", errno = " << errno;
}

TEST(MremapLockedTest, RlimitMemlockInsufficient) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanMlock()));
  auto mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_LOCKED));
  EXPECT_TRUE(IsPageMlocked(mapping.addr()));

  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_IPC_LOCK))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_IPC_LOCK, false));
  }
  Cleanup reset_rlimit = ASSERT_NO_ERRNO_AND_VALUE(
      ScopedSetSoftRlimit(RLIMIT_MEMLOCK, mapping.len()));
  void* addr = mremap(mapping.ptr(), mapping.len(), 2 * mapping.len(),
                      MREMAP_MAYMOVE, nullptr);
  EXPECT_TRUE(addr == MAP_FAILED && errno == EAGAIN)
      << "addr = " << addr << ", errno = " << errno;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
