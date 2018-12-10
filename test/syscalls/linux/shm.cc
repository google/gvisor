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

#include <stdio.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "absl/time/clock.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::testing::_;

const uint64_t kAllocSize = kPageSize * 128ULL;

PosixErrorOr<int> Shmget(key_t key, size_t size, int shmflg) {
  int id = shmget(key, size, shmflg);
  if (id == -1) {
    return PosixError(errno, "shmget() failed");
  }
  return id;
}

PosixErrorOr<char*> Shmat(int shmid, const void* shmaddr, int shmflg) {
  const intptr_t addr =
      reinterpret_cast<intptr_t>(shmat(shmid, shmaddr, shmflg));
  if (addr == -1) {
    return PosixError(errno, "shmat() failed");
  }
  return reinterpret_cast<char*>(addr);
}

PosixError Shmdt(const char* shmaddr) {
  const int ret = shmdt(shmaddr);
  if (ret == -1) {
    return PosixError(errno, "shmdt() failed");
  }
  return NoError();
}

template <typename T>
PosixErrorOr<int> Shmctl(int shmid, int cmd, T* buf) {
  int ret = shmctl(shmid, cmd, reinterpret_cast<struct shmid_ds*>(buf));
  if (ret == -1) {
    return PosixError(errno, "shmctl() failed");
  }
  return ret;
}

TEST(ShmTest, AttachDetach) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  struct shmid_ds attr;
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  EXPECT_EQ(attr.shm_segsz, kAllocSize);
  EXPECT_EQ(attr.shm_nattch, 0);

  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  EXPECT_EQ(attr.shm_nattch, 1);

  const char* addr2 = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  EXPECT_EQ(attr.shm_nattch, 2);

  ASSERT_NO_ERRNO(Shmdt(addr));
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  EXPECT_EQ(attr.shm_nattch, 1);

  ASSERT_NO_ERRNO(Shmdt(addr2));
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  EXPECT_EQ(attr.shm_nattch, 0);
}

TEST(ShmTest, LookupByKey) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  const int id =
      ASSERT_NO_ERRNO_AND_VALUE(Shmget(key, kAllocSize, IPC_CREAT | 0777));
  const int id2 = ASSERT_NO_ERRNO_AND_VALUE(Shmget(key, kAllocSize, 0777));
  EXPECT_EQ(id, id2);
}

TEST(ShmTest, DetachedSegmentsPersist) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  addr[0] = 'x';
  ASSERT_NO_ERRNO(Shmdt(addr));

  // We should be able to re-attach to the same segment and get our data back.
  addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  EXPECT_EQ(addr[0], 'x');
  ASSERT_NO_ERRNO(Shmdt(addr));
}

TEST(ShmTest, MultipleDetachFails) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmdt(addr));
  EXPECT_THAT(Shmdt(addr), PosixErrorIs(EINVAL, _));
}

TEST(ShmTest, IpcStat) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);

  const time_t start = time(nullptr);

  const int id =
      ASSERT_NO_ERRNO_AND_VALUE(Shmget(key, kAllocSize, IPC_CREAT | 0777));

  const uid_t uid = getuid();
  const gid_t gid = getgid();
  const pid_t pid = getpid();

  struct shmid_ds attr;
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));

  EXPECT_EQ(attr.shm_perm.__key, key);
  EXPECT_EQ(attr.shm_perm.uid, uid);
  EXPECT_EQ(attr.shm_perm.gid, gid);
  EXPECT_EQ(attr.shm_perm.cuid, uid);
  EXPECT_EQ(attr.shm_perm.cgid, gid);
  EXPECT_EQ(attr.shm_perm.mode, 0777);

  EXPECT_EQ(attr.shm_segsz, kAllocSize);

  EXPECT_EQ(attr.shm_atime, 0);
  EXPECT_EQ(attr.shm_dtime, 0);

  // Change time is set on creation.
  EXPECT_GE(attr.shm_ctime, start);

  EXPECT_EQ(attr.shm_cpid, pid);
  EXPECT_EQ(attr.shm_lpid, 0);

  EXPECT_EQ(attr.shm_nattch, 0);

  // The timestamps only have a resolution of seconds; slow down so we actually
  // see the timestamps change.
  absl::SleepFor(absl::Seconds(1));
  const time_t pre_attach = time(nullptr);

  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));

  EXPECT_GE(attr.shm_atime, pre_attach);
  EXPECT_EQ(attr.shm_dtime, 0);
  EXPECT_LT(attr.shm_ctime, pre_attach);
  EXPECT_EQ(attr.shm_lpid, pid);
  EXPECT_EQ(attr.shm_nattch, 1);

  absl::SleepFor(absl::Seconds(1));
  const time_t pre_detach = time(nullptr);

  ASSERT_NO_ERRNO(Shmdt(addr));
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));

  EXPECT_LT(attr.shm_atime, pre_detach);
  EXPECT_GE(attr.shm_dtime, pre_detach);
  EXPECT_LT(attr.shm_ctime, pre_detach);
  EXPECT_EQ(attr.shm_lpid, pid);
  EXPECT_EQ(attr.shm_nattch, 0);
}

TEST(ShmTest, ShmStat) {
  // This test relies on the segment we create to be the first one on the
  // system, causing it to occupy slot 1. We can't reasonably expect this on a
  // general Linux host.
  SKIP_IF(!IsRunningOnGvisor());

  ASSERT_NO_ERRNO(Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  struct shmid_ds attr;
  ASSERT_NO_ERRNO(Shmctl(1, SHM_STAT, &attr));
  // This does the same thing as IPC_STAT, so only test that the syscall
  // succeeds here.
}

TEST(ShmTest, IpcInfo) {
  struct shminfo info;
  ASSERT_NO_ERRNO(Shmctl(0, IPC_INFO, &info));

  EXPECT_EQ(info.shmmin, 1);  // This is always 1, according to the man page.
  EXPECT_GT(info.shmmax, info.shmmin);
  EXPECT_GT(info.shmmni, 0);
  EXPECT_GT(info.shmseg, 0);
  EXPECT_GT(info.shmall, 0);
}

TEST(ShmTest, ShmInfo) {
  struct shm_info info;

  // We generally can't know what other processes on a linux machine
  // does with shared memory segments, so we can't test specific
  // numbers on Linux. When running under gvisor, we're guaranteed to
  // be the only ones using shm, so we can easily verify machine-wide
  // numbers.
  if (IsRunningOnGvisor()) {
    ASSERT_NO_ERRNO(Shmctl(0, SHM_INFO, &info));
    EXPECT_EQ(info.used_ids, 0);
    EXPECT_EQ(info.shm_tot, 0);
    EXPECT_EQ(info.shm_rss, 0);
    EXPECT_EQ(info.shm_swp, 0);
  }

  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));

  ASSERT_NO_ERRNO(Shmctl(1, SHM_INFO, &info));

  if (IsRunningOnGvisor()) {
    ASSERT_NO_ERRNO(Shmctl(id, SHM_INFO, &info));
    EXPECT_EQ(info.used_ids, 1);
    EXPECT_EQ(info.shm_tot, kAllocSize / kPageSize);
    EXPECT_EQ(info.shm_rss, kAllocSize / kPageSize);
    EXPECT_EQ(info.shm_swp, 0);  // Gvisor currently never swaps.
  }

  ASSERT_NO_ERRNO(Shmdt(addr));
}

TEST(ShmTest, ShmCtlSet) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));

  struct shmid_ds attr;
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  ASSERT_EQ(attr.shm_perm.mode, 0777);

  attr.shm_perm.mode = 0766;
  ASSERT_NO_ERRNO(Shmctl(id, IPC_SET, &attr));

  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  ASSERT_EQ(attr.shm_perm.mode, 0766);

  ASSERT_NO_ERRNO(Shmdt(addr));
}

TEST(ShmTest, RemovedSegmentsAreMarkedDeleted) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmctl<void>(id, IPC_RMID, nullptr));
  struct shmid_ds attr;
  ASSERT_NO_ERRNO(Shmctl(id, IPC_STAT, &attr));
  EXPECT_NE(attr.shm_perm.mode & SHM_DEST, 0);
  ASSERT_NO_ERRNO(Shmdt(addr));
}

TEST(ShmTest, RemovedSegmentsAreDestroyed) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));

  const uint64_t alloc_pages = kAllocSize / kPageSize;

  struct shm_info info;
  ASSERT_NO_ERRNO(Shmctl(1, SHM_INFO, &info));
  const uint64_t before = info.shm_tot;

  ASSERT_NO_ERRNO(Shmctl<void>(id, IPC_RMID, nullptr));
  ASSERT_NO_ERRNO(Shmdt(addr));

  ASSERT_NO_ERRNO(Shmctl(1, SHM_INFO, &info));
  const uint64_t after = info.shm_tot;
  EXPECT_EQ(after, before - alloc_pages);
}

TEST(ShmTest, AllowsAttachToRemovedSegmentWithRefs) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  const char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmctl<void>(id, IPC_RMID, nullptr));
  const char* addr2 = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  ASSERT_NO_ERRNO(Shmdt(addr));
  ASSERT_NO_ERRNO(Shmdt(addr2));
}

TEST(ShmTest, RemovedSegmentsAreNotDiscoverable) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  const int id =
      ASSERT_NO_ERRNO_AND_VALUE(Shmget(key, kAllocSize, IPC_CREAT | 0777));
  ASSERT_NO_ERRNO(Shmctl<void>(id, IPC_RMID, nullptr));
  EXPECT_THAT(Shmget(key, kAllocSize, 0777), PosixErrorIs(ENOENT, _));
}

TEST(ShmDeathTest, ReadonlySegment) {
  SetupGvisorDeathTest();
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, SHM_RDONLY));
  // Reading succeeds.
  static_cast<void>(addr[0]);
  // Writing fails.
  EXPECT_EXIT(addr[0] = 'x', ::testing::KilledBySignal(SIGSEGV), "");
}

TEST(ShmDeathTest, SegmentNotAccessibleAfterDetach) {
  // This test is susceptible to races with concurrent mmaps running in parallel
  // gtest threads since the test relies on the address freed during a shm
  // segment destruction to remain unused. We run the test body in a forked
  // child to guarantee a single-threaded context to avoid this.

  SetupGvisorDeathTest();

  const auto rest = [&] {
    const int id = ASSERT_NO_ERRNO_AND_VALUE(
        Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
    char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
    addr[0] = 'x';
    ASSERT_NO_ERRNO(Shmdt(addr));

    // This access should cause a SIGSEGV.
    addr[0] = 'x';
  };

  EXPECT_THAT(InForkedProcess(rest),
              IsPosixErrorOkAndHolds(W_EXITCODE(0, SIGSEGV)));
}

TEST(ShmTest, RequestingSegmentSmallerThanSHMMINFails) {
  struct shminfo info;
  ASSERT_NO_ERRNO(Shmctl(0, IPC_INFO, &info));
  const uint64_t size = info.shmmin - 1;
  EXPECT_THAT(Shmget(IPC_PRIVATE, size, IPC_CREAT | 0777),
              PosixErrorIs(EINVAL, _));
}

TEST(ShmTest, RequestingSegmentLargerThanSHMMAXFails) {
  struct shminfo info;
  ASSERT_NO_ERRNO(Shmctl(0, IPC_INFO, &info));
  const uint64_t size = info.shmmax + kPageSize;
  EXPECT_THAT(Shmget(IPC_PRIVATE, size, IPC_CREAT | 0777),
              PosixErrorIs(EINVAL, _));
}

TEST(ShmTest, RequestingUnalignedSizeSucceeds) {
  EXPECT_NO_ERRNO(Shmget(IPC_PRIVATE, 4097, IPC_CREAT | 0777));
}

TEST(ShmTest, RequestingDuplicateCreationFails) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(key, kAllocSize, IPC_CREAT | IPC_EXCL | 0777));
  EXPECT_THAT(Shmget(key, kAllocSize, IPC_CREAT | IPC_EXCL | 0777),
              PosixErrorIs(EEXIST, _));
}

TEST(ShmTest, SegmentsSizeFixedOnCreation) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);

  // Base segment.
  const int id =
      ASSERT_NO_ERRNO_AND_VALUE(Shmget(key, kAllocSize, IPC_CREAT | 0777));

  // Ask for the same segment at half size. This succeeds.
  const int id2 = ASSERT_NO_ERRNO_AND_VALUE(Shmget(key, kAllocSize / 2, 0777));

  // Ask for the same segment at double size.
  EXPECT_THAT(Shmget(key, kAllocSize * 2, 0777), PosixErrorIs(EINVAL, _));

  char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  char* addr2 = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id2, nullptr, 0));

  // We have 2 different maps...
  EXPECT_NE(addr, addr2);

  // ... And both maps are kAllocSize bytes; despite asking for a half-sized
  // segment for the second map.
  addr[kAllocSize - 1] = 'x';
  addr2[kAllocSize - 1] = 'x';

  ASSERT_NO_ERRNO(Shmdt(addr));
  ASSERT_NO_ERRNO(Shmdt(addr2));
}

TEST(ShmTest, PartialUnmap) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  EXPECT_THAT(munmap(addr + (kAllocSize / 4), kAllocSize / 2),
              SyscallSucceeds());
  ASSERT_NO_ERRNO(Shmdt(addr));
}

// Check that sentry does not panic when asked for a zero-length private shm
// segment.
TEST(ShmTest, GracefullyFailOnZeroLenSegmentCreation) {
  EXPECT_THAT(Shmget(IPC_PRIVATE, 0, 0), PosixErrorIs(EINVAL, _));
}

TEST(ShmTest, NoDestructionOfAttachedSegmentWithMultipleRmid) {
  const int id = ASSERT_NO_ERRNO_AND_VALUE(
      Shmget(IPC_PRIVATE, kAllocSize, IPC_CREAT | 0777));
  char* addr = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));
  char* addr2 = ASSERT_NO_ERRNO_AND_VALUE(Shmat(id, nullptr, 0));

  // There should be 2 refs to the segment from the 2 attachments, and a single
  // self-reference. Mark the segment as destroyed more than 3 times through
  // shmctl(RMID). If there's a bug with the ref counting, this should cause the
  // count to drop to zero.
  for (int i = 0; i < 6; ++i) {
    ASSERT_NO_ERRNO(Shmctl<void>(id, IPC_RMID, nullptr));
  }

  // Segment should remain accessible.
  addr[0] = 'x';
  ASSERT_NO_ERRNO(Shmdt(addr));

  // Segment should remain accessible even after one of the two attachments are
  // detached.
  addr2[0] = 'x';
  ASSERT_NO_ERRNO(Shmdt(addr2));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
