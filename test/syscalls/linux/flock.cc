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
#include <sys/file.h>
#include <string>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

namespace {

class FlockTest : public FileTest {};

TEST_F(FlockTest, BadFD) {
  // EBADF: fd is not an open file descriptor.
  ASSERT_THAT(flock(-1, 0), SyscallFailsWithErrno(EBADF));
}

TEST_F(FlockTest, InvalidOpCombinations) {
  // The operation cannot be both exclusive and shared.
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_SH | LOCK_NB),
              SyscallFailsWithErrno(EINVAL));

  // Locking and Unlocking doesn't make sense.
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_UN | LOCK_NB),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_UN | LOCK_NB),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(FlockTest, NoOperationSpecified) {
  // Not specifying an operation is invalid.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FlockTestNoFixture, FlockSupportsPipes) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());

  EXPECT_THAT(flock(fds[0], LOCK_EX | LOCK_NB), SyscallSucceeds());
  EXPECT_THAT(close(fds[0]), SyscallSucceeds());
  EXPECT_THAT(close(fds[1]), SyscallSucceeds());
}

TEST_F(FlockTest, TestSimpleExLock) {
  // Test that we can obtain an exclusive lock (no other holders)
  // and that we can unlock it.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestSimpleShLock) {
  // Test that we can obtain a shared lock (no other holders)
  // and that we can unlock it.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestLockableAnyMode) {
  // flock(2): A shared or exclusive lock can be placed on a file
  // regardless of the mode in which the file was opened.
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(test_file_name_, O_RDONLY));  // open read only to test

  // Mode shouldn't prevent us from taking an exclusive lock.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB), SyscallSucceedsWithValue(0));

  // Unlock
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestUnlockWithNoHolders) {
  // Test that unlocking when no one holds a lock succeeeds.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestRepeatedExLockingBySameHolder) {
  // Test that repeated locking by the same holder for the
  // same type of lock works correctly.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_EX),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_EX),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestRepeatedExLockingSingleUnlock) {
  // Test that repeated locking by the same holder for the
  // same type of lock works correctly and that a single unlock is required.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_EX),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_EX),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));

  // Should be unlocked at this point
  ASSERT_THAT(flock(fd.get(), LOCK_NB | LOCK_EX), SyscallSucceedsWithValue(0));

  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestRepeatedShLockingBySameHolder) {
  // Test that repeated locking by the same holder for the
  // same type of lock works correctly.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_SH),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_SH),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestSingleHolderUpgrade) {
  // Test that a shared lock is upgradable when no one else holds a lock.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_SH),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_NB | LOCK_EX),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestSingleHolderDowngrade) {
  // Test single holder lock downgrade case.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestMultipleShared) {
  // This is a simple test to verify that multiple independent shared
  // locks will be granted.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // A shared lock should be granted as there only exists other shared locks.
  ASSERT_THAT(flock(fd.get(), LOCK_SH | LOCK_NB), SyscallSucceedsWithValue(0));

  // Unlock both.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

/*
 * flock(2): If a process uses open(2) (or similar) to obtain more than one
 * descriptor for the same file, these descriptors are treated
 * independently by flock(). An attempt to lock the file using one of
 * these file descriptors may be denied by a lock that the calling process
 * has already placed via another descriptor.
 */
TEST_F(FlockTest, TestMultipleHolderSharedExclusive) {
  // This test will verify that an exclusive lock will not be granted
  // while a shared is held.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Verify We're unable to get an exlcusive lock via the second FD.
  // because someone is holding a shared lock.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Unlock
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestSharedLockFailExclusiveHolder) {
  // This test will verify that a shared lock is denied while
  // someone holds an exclusive lock.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Verify we're unable to get an shared lock via the second FD.
  // because someone is holding an exclusive lock.
  ASSERT_THAT(flock(fd.get(), LOCK_SH | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Unlock
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestExclusiveLockFailExclusiveHolder) {
  // This test will verify that an exclusive lock is denied while
  // someone already holds an exclsuive lock.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Verify we're unable to get an exclusive lock via the second FD
  // because someone is already holding an exclusive lock.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Unlock
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestMultipleHolderSharedExclusiveUpgrade) {
  // This test will verify that we cannot obtain an exclusive lock while
  // a shared lock is held by another descriptor, then verify that an upgrade
  // is possible on a shared lock once all other shared locks have closed.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Verify we're unable to get an exclusive lock via the second FD because
  // a shared lock is held.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Verify that we can get a shared lock via the second descriptor instead
  ASSERT_THAT(flock(fd.get(), LOCK_SH | LOCK_NB), SyscallSucceedsWithValue(0));

  // Unlock the first and there will only be one shared lock remaining.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));

  // Upgrade 2nd fd.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB), SyscallSucceedsWithValue(0));

  // Finally unlock the second
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestMultipleHolderSharedExclusiveDowngrade) {
  // This test will verify that a shared lock is not obtainable while an
  // exclusive lock is held but that once the first is downgraded that
  // the second independent file descriptor can also get a shared lock.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Verify We're unable to get a shared lock via the second FD because
  // an exclusive lock is held.
  ASSERT_THAT(flock(fd.get(), LOCK_SH | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Verify that we can downgrade the first.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));

  // Now verify that we can obtain a shared lock since the first was downgraded.
  ASSERT_THAT(flock(fd.get(), LOCK_SH | LOCK_NB), SyscallSucceedsWithValue(0));

  // Finally unlock both.
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

/*
 * flock(2): Locks created by flock() are associated with an open file table
 * entry. This means that duplicate file descriptors (created by, for example,
 * fork(2) or dup(2)) refer to the same lock, and this lock may be modified or
 * released using any of these descriptors. Furthermore, the lock is released
 * either by an explicit LOCK_UN operation on any of these duplicate descriptors
 * or when all such descriptors have been closed.
 */
TEST_F(FlockTest, TestDupFdUpgrade) {
  // This test will verify that a shared lock is upgradeable via a dupped
  // file descriptor, if the FD wasn't dupped this would fail.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor dup_fd = ASSERT_NO_ERRNO_AND_VALUE(test_file_fd_.Dup());

  // Now we should be able to upgrade via the dupped fd.
  ASSERT_THAT(flock(dup_fd.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  // Validate unlock via dupped fd.
  ASSERT_THAT(flock(dup_fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestDupFdDowngrade) {
  // This test will verify that a exclusive lock is downgradable via a dupped
  // file descriptor, if the FD wasn't dupped this would fail.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor dup_fd = ASSERT_NO_ERRNO_AND_VALUE(test_file_fd_.Dup());

  // Now we should be able to downgrade via the dupped fd.
  ASSERT_THAT(flock(dup_fd.get(), LOCK_SH | LOCK_NB),
              SyscallSucceedsWithValue(0));

  // Validate unlock via dupped fd
  ASSERT_THAT(flock(dup_fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestDupFdCloseRelease) {
  // flock(2): Furthermore, the lock is released either by an explicit LOCK_UN
  // operation on any of these duplicate descriptors, or when all such
  // descriptors have been closed.
  //
  // This test will verify that a dupped fd closing will not release the
  // underlying lock until all such dupped fds have closed.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  FileDescriptor dup_fd = ASSERT_NO_ERRNO_AND_VALUE(test_file_fd_.Dup());

  // At this point we have ONE exclusive locked referenced by two different fds.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Validate that we cannot get a lock on a new unrelated FD.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Closing the dupped fd shouldn't affect the lock until all are closed.
  dup_fd.reset();  // Closed the duped fd.

  // Validate that we still cannot get a lock on a new unrelated FD.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Closing the first fd
  CloseFile();  // Will validate the syscall succeeds.

  // Now we should actually be able to get a lock since all fds related to
  // the first lock are closed.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB), SyscallSucceedsWithValue(0));

  // Unlock.
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestDupFdUnlockRelease) {
  /* flock(2): Furthermore, the lock is released either by an explicit LOCK_UN
   * operation on any of these duplicate descriptors, or when all such
   * descriptors have been closed.
   */
  // This test will verify that an explict unlock on a dupped FD will release
  // the underlying lock unlike the previous case where close on a dup was
  // not enough to release the lock.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX | LOCK_NB),
              SyscallSucceedsWithValue(0));

  const FileDescriptor dup_fd = ASSERT_NO_ERRNO_AND_VALUE(test_file_fd_.Dup());

  // At this point we have ONE exclusive locked referenced by two different fds.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Validate that we cannot get a lock on a new unrelated FD.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Explicitly unlock via the dupped descriptor.
  ASSERT_THAT(flock(dup_fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));

  // Validate that we can now get the lock since we explicitly unlocked.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB), SyscallSucceedsWithValue(0));

  // Unlock
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

TEST_F(FlockTest, TestDupFdFollowedByLock) {
  // This test will verify that taking a lock on a file descriptor that has
  // already been dupped means that the lock is shared between both. This is
  // slightly different than than duping on an already locked FD.
  FileDescriptor dup_fd = ASSERT_NO_ERRNO_AND_VALUE(test_file_fd_.Dup());

  // Take a lock.
  ASSERT_THAT(flock(dup_fd.get(), LOCK_EX | LOCK_NB), SyscallSucceeds());

  // Now dup_fd and test_file_ should both reference the same lock.
  // We shouldn't be able to obtain a lock until both are closed.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  // Closing the first fd
  dup_fd.reset();  // Close the duped fd.

  // Validate that we cannot get a lock yet because the dupped descriptor.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EWOULDBLOCK));

  // Closing the second fd.
  CloseFile();  // CloseFile() will validate the syscall succeeds.

  // Now we should be able to get the lock.
  ASSERT_THAT(flock(fd.get(), LOCK_EX | LOCK_NB), SyscallSucceeds());

  // Unlock.
  ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceedsWithValue(0));
}

// NOTE: These blocking tests are not perfect. Unfortunantely it's very hard to
// determine if a thread was actually blocked in the kernel so we're forced
// to use timing.
TEST_F(FlockTest, BlockingLockNoBlockingForSharedLocks_NoRandomSave) {
  // This test will verify that although LOCK_NB isn't specified
  // two different fds can obtain shared locks without blocking.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH), SyscallSucceeds());

  // kHoldLockTime is the amount of time we will hold the lock before releasing.
  constexpr absl::Duration kHoldLockTime = absl::Seconds(30);

  const DisableSave ds;  // Timing-related.

  // We do this in another thread so we can determine if it was actually
  // blocked by timing the amount of time it took for the syscall to complete.
  ScopedThread t([&] {
    MonotonicTimer timer;
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

    // Only a single shared lock is held, the lock will be granted immediately.
    // This should be granted without any blocking. Don't save here to avoid
    // wild discrepencies on timing.
    timer.Start();
    ASSERT_THAT(flock(fd.get(), LOCK_SH), SyscallSucceeds());

    // We held the lock for 30 seconds but this thread should not have
    // blocked at all so we expect a very small duration on syscall completion.
    ASSERT_LT(timer.Duration(),
              absl::Seconds(1));  // 1000ms is much less than 30s.

    // We can release our second shared lock
    ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceeds());
  });

  // Sleep before unlocking.
  absl::SleepFor(kHoldLockTime);

  // Release the first shared lock. Don't save in this situation to avoid
  // discrepencies in timing.
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceeds());
}

TEST_F(FlockTest, BlockingLockFirstSharedSecondExclusive_NoRandomSave) {
  // This test will verify that if someone holds a shared lock any attempt to
  // obtain an exclusive lock will result in blocking.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_SH), SyscallSucceeds());

  // kHoldLockTime is the amount of time we will hold the lock before releasing.
  constexpr absl::Duration kHoldLockTime = absl::Seconds(2);

  const DisableSave ds;  // Timing-related.

  // We do this in another thread so we can determine if it was actually
  // blocked by timing the amount of time it took for the syscall to complete.
  ScopedThread t([&] {
    MonotonicTimer timer;
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

    // This exclusive lock should block because someone is already holding a
    // shared lock. We don't save here to avoid wild discrepencies on timing.
    timer.Start();
    ASSERT_THAT(RetryEINTR(flock)(fd.get(), LOCK_EX), SyscallSucceeds());

    // We should be blocked, we will expect to be blocked for more than 1.0s.
    ASSERT_GT(timer.Duration(), absl::Seconds(1));

    // We can release our exclusive lock.
    ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceeds());
  });

  // Sleep before unlocking.
  absl::SleepFor(kHoldLockTime);

  // Release the shared lock allowing the thread to proceed.
  // We don't save here to avoid wild discrepencies in timing.
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceeds());
}

TEST_F(FlockTest, BlockingLockFirstExclusiveSecondShared_NoRandomSave) {
  // This test will verify that if someone holds an exclusive lock any attempt
  // to obtain a shared lock will result in blocking.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX), SyscallSucceeds());

  // kHoldLockTime is the amount of time we will hold the lock before releasing.
  constexpr absl::Duration kHoldLockTime = absl::Seconds(2);

  const DisableSave ds;  // Timing-related.

  // We do this in another thread so we can determine if it was actually
  // blocked by timing the amount of time it took for the syscall to complete.
  ScopedThread t([&] {
    MonotonicTimer timer;
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

    // This shared lock should block because someone is already holding an
    // exclusive lock. We don't save here to avoid wild discrepencies on timing.
    timer.Start();
    ASSERT_THAT(RetryEINTR(flock)(fd.get(), LOCK_SH), SyscallSucceeds());

    // We should be blocked, we will expect to be blocked for more than 1.0s.
    ASSERT_GT(timer.Duration(), absl::Seconds(1));

    // We can release our shared lock.
    ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceeds());
  });

  // Sleep before unlocking.
  absl::SleepFor(kHoldLockTime);

  // Release the exclusive lock allowing the blocked thread to proceed.
  // We don't save here to avoid wild discrepencies in timing.
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceeds());
}

TEST_F(FlockTest, BlockingLockFirstExclusiveSecondExclusive_NoRandomSave) {
  // This test will verify that if someone holds an exclusive lock any attempt
  // to obtain another exclusive lock will result in blocking.
  ASSERT_THAT(flock(test_file_fd_.get(), LOCK_EX), SyscallSucceeds());

  // kHoldLockTime is the amount of time we will hold the lock before releasing.
  constexpr absl::Duration kHoldLockTime = absl::Seconds(2);

  const DisableSave ds;  // Timing-related.

  // We do this in another thread so we can determine if it was actually
  // blocked by timing the amount of time it took for the syscall to complete.
  ScopedThread t([&] {
    MonotonicTimer timer;
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

    // This exclusive lock should block because someone is already holding an
    // exclusive lock.
    timer.Start();
    ASSERT_THAT(RetryEINTR(flock)(fd.get(), LOCK_EX), SyscallSucceeds());

    // We should be blocked, we will expect to be blocked for more than 1.0s.
    ASSERT_GT(timer.Duration(), absl::Seconds(1));

    // We can release our exclusive lock.
    ASSERT_THAT(flock(fd.get(), LOCK_UN), SyscallSucceeds());
  });

  // Sleep before unlocking.
  absl::SleepFor(kHoldLockTime);

  // Release the exclusive lock allowing the blocked thread to proceed.
  // We don't save to avoid wild discrepencies in timing.
  EXPECT_THAT(flock(test_file_fd_.get(), LOCK_UN), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
