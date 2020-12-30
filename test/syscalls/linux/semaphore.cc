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
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>

#include <atomic>
#include <cerrno>
#include <ctime>
#include <set>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "test/util/capability_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr int kSemMap = 1024000000;
constexpr int kSemMni = 32000;
constexpr int kSemMns = 1024000000;
constexpr int kSemMnu = 1024000000;
constexpr int kSemMsl = 32000;
constexpr int kSemOpm = 500;
constexpr int kSemUme = 500;
constexpr int kSemUsz = 20;
constexpr int kSemVmx = 32767;
constexpr int kSemAem = 32767;

class AutoSem {
 public:
  explicit AutoSem(int id) : id_(id) {}
  ~AutoSem() {
    if (id_ >= 0) {
      EXPECT_THAT(semctl(id_, 0, IPC_RMID), SyscallSucceeds());
    }
  }

  int release() {
    int old = id_;
    id_ = -1;
    return old;
  }

  int get() { return id_; }

 private:
  int id_ = -1;
};

TEST(SemaphoreTest, SemGet) {
  // Test creation and lookup.
  AutoSem sem(semget(1, 10, IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());
  EXPECT_THAT(semget(1, 10, IPC_CREAT), SyscallSucceedsWithValue(sem.get()));
  EXPECT_THAT(semget(1, 9, IPC_CREAT), SyscallSucceedsWithValue(sem.get()));

  // Creation and lookup failure cases.
  EXPECT_THAT(semget(1, 11, IPC_CREAT), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(semget(1, -1, IPC_CREAT), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(semget(1, 10, IPC_CREAT | IPC_EXCL),
              SyscallFailsWithErrno(EEXIST));
  EXPECT_THAT(semget(2, 1, 0), SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(semget(2, 0, IPC_CREAT), SyscallFailsWithErrno(EINVAL));

  // Private semaphores never conflict.
  AutoSem sem2(semget(IPC_PRIVATE, 1, 0));
  AutoSem sem3(semget(IPC_PRIVATE, 1, 0));
  ASSERT_THAT(sem2.get(), SyscallSucceeds());
  EXPECT_NE(sem.get(), sem2.get());
  ASSERT_THAT(sem3.get(), SyscallSucceeds());
  EXPECT_NE(sem3.get(), sem2.get());
}

// Tests simple operations that shouldn't block in a single-thread.
TEST(SemaphoreTest, SemOpSingleNoBlock) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  struct sembuf buf = {};
  buf.sem_op = 1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());

  buf.sem_op = -1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());

  buf.sem_op = 0;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());

  // Error cases with invalid values.
  ASSERT_THAT(semop(sem.get() + 1, &buf, 1), SyscallFailsWithErrno(EINVAL));

  buf.sem_num = 1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallFailsWithErrno(EFBIG));

  ASSERT_THAT(semop(sem.get(), nullptr, 0), SyscallFailsWithErrno(EINVAL));
}

// Tests multiple operations that shouldn't block in a single-thread.
TEST(SemaphoreTest, SemOpMultiNoBlock) {
  AutoSem sem(semget(IPC_PRIVATE, 4, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  struct sembuf bufs[5] = {};
  bufs[0].sem_num = 0;
  bufs[0].sem_op = 10;
  bufs[0].sem_flg = 0;

  bufs[1].sem_num = 1;
  bufs[1].sem_op = 2;
  bufs[1].sem_flg = 0;

  bufs[2].sem_num = 2;
  bufs[2].sem_op = 3;
  bufs[2].sem_flg = 0;

  bufs[3].sem_num = 0;
  bufs[3].sem_op = -5;
  bufs[3].sem_flg = 0;

  bufs[4].sem_num = 2;
  bufs[4].sem_op = 2;
  bufs[4].sem_flg = 0;

  ASSERT_THAT(semop(sem.get(), bufs, ABSL_ARRAYSIZE(bufs)), SyscallSucceeds());

  ASSERT_THAT(semctl(sem.get(), 0, GETVAL), SyscallSucceedsWithValue(5));
  ASSERT_THAT(semctl(sem.get(), 1, GETVAL), SyscallSucceedsWithValue(2));
  ASSERT_THAT(semctl(sem.get(), 2, GETVAL), SyscallSucceedsWithValue(5));
  ASSERT_THAT(semctl(sem.get(), 3, GETVAL), SyscallSucceedsWithValue(0));

  for (auto& b : bufs) {
    b.sem_op = -b.sem_op;
  }
  // 0 and 3 order must be reversed, otherwise it will block.
  std::swap(bufs[0].sem_op, bufs[3].sem_op);
  ASSERT_THAT(RetryEINTR(semop)(sem.get(), bufs, ABSL_ARRAYSIZE(bufs)),
              SyscallSucceeds());

  // All semaphores should be back to 0 now.
  for (size_t i = 0; i < 4; ++i) {
    ASSERT_THAT(semctl(sem.get(), i, GETVAL), SyscallSucceedsWithValue(0));
  }
}

// Makes a best effort attempt to ensure that operation would block.
TEST(SemaphoreTest, SemOpBlock) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  std::atomic<int> blocked = ATOMIC_VAR_INIT(1);
  ScopedThread th([&sem, &blocked] {
    absl::SleepFor(absl::Milliseconds(100));
    ASSERT_EQ(blocked.load(), 1);

    struct sembuf buf = {};
    buf.sem_op = 1;
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
  });

  struct sembuf buf = {};
  buf.sem_op = -1;
  ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
  blocked.store(0);
}

// Tests that IPC_NOWAIT returns with no wait.
TEST(SemaphoreTest, SemOpNoBlock) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  struct sembuf buf = {};
  buf.sem_flg = IPC_NOWAIT;

  buf.sem_op = -1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallFailsWithErrno(EAGAIN));

  buf.sem_op = 1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());

  buf.sem_op = 0;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallFailsWithErrno(EAGAIN));
}

// Test runs 2 threads, one signals the other waits the same number of times.
TEST(SemaphoreTest, SemOpSimple) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  constexpr size_t kLoops = 100;
  ScopedThread th([&sem] {
    struct sembuf buf = {};
    buf.sem_op = 1;
    for (size_t i = 0; i < kLoops; i++) {
      // Sleep to prevent making all increments in one shot without letting
      // the waiter wait.
      absl::SleepFor(absl::Milliseconds(1));
      ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());
    }
  });

  struct sembuf buf = {};
  buf.sem_op = -1;
  for (size_t i = 0; i < kLoops; i++) {
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
  }
}

// Tests that semaphore can be removed while there are waiters.
// NoRandomSave: Test relies on timing that random save throws off.
TEST(SemaphoreTest, SemOpRemoveWithWaiter_NoRandomSave) {
  AutoSem sem(semget(IPC_PRIVATE, 2, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  ScopedThread th([&sem] {
    absl::SleepFor(absl::Milliseconds(250));
    ASSERT_THAT(semctl(sem.release(), 0, IPC_RMID), SyscallSucceeds());
  });

  // This must happen before IPC_RMID runs above. Otherwise it fails with EINVAL
  // instead because the semaphore has already been removed.
  struct sembuf buf = {};
  buf.sem_op = -1;
  ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1),
              SyscallFailsWithErrno(EIDRM));
}

// Semaphore isn't fair. It will execute any waiter that can satisfy the
// request even if it gets in front of other waiters.
TEST(SemaphoreTest, SemOpBestFitExecution) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  ScopedThread th([&sem] {
    struct sembuf buf = {};
    buf.sem_op = -2;
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallFails());
    // Ensure that wait will only unblock when the semaphore is removed. On
    // EINTR retry it may race with deletion and return EINVAL.
    ASSERT_TRUE(errno == EIDRM || errno == EINVAL) << "errno=" << errno;
  });

  // Ensures that '-1' below will unblock even though '-10' above is waiting
  // for the same semaphore.
  for (size_t i = 0; i < 10; ++i) {
    struct sembuf buf = {};
    buf.sem_op = 1;
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());

    absl::SleepFor(absl::Milliseconds(10));

    buf.sem_op = -1;
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
  }

  ASSERT_THAT(semctl(sem.release(), 0, IPC_RMID), SyscallSucceeds());
}

// Executes random operations in multiple threads and verify correctness.
TEST(SemaphoreTest, SemOpRandom) {
  // Don't do cooperative S/R tests because there are too many syscalls in
  // this test,
  const DisableSave ds;

  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  // Protects the seed below.
  absl::Mutex mutex;
  uint32_t seed = time(nullptr);

  int count = 0;      // Tracks semaphore value.
  bool done = false;  // Tells waiters to stop after signal threads are done.

  // These threads will wait in a loop.
  std::unique_ptr<ScopedThread> decs[5];
  for (auto& dec : decs) {
    dec = absl::make_unique<ScopedThread>([&sem, &mutex, &count, &seed, &done] {
      for (size_t i = 0; i < 500; ++i) {
        int16_t val;
        {
          absl::MutexLock l(&mutex);
          if (done) {
            return;
          }
          val = (rand_r(&seed) % 10 + 1);  // Rand between 1 and 10.
          count -= val;
        }
        struct sembuf buf = {};
        buf.sem_op = -val;
        ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
        absl::SleepFor(absl::Milliseconds(val * 2));
      }
    });
  }

  // These threads will wait for zero in a loop.
  std::unique_ptr<ScopedThread> zeros[5];
  for (auto& zero : zeros) {
    zero = absl::make_unique<ScopedThread>([&sem, &mutex, &done] {
      for (size_t i = 0; i < 500; ++i) {
        {
          absl::MutexLock l(&mutex);
          if (done) {
            return;
          }
        }
        struct sembuf buf = {};
        buf.sem_op = 0;
        ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
        absl::SleepFor(absl::Milliseconds(10));
      }
    });
  }

  // These threads will signal in a loop.
  std::unique_ptr<ScopedThread> incs[5];
  for (auto& inc : incs) {
    inc = absl::make_unique<ScopedThread>([&sem, &mutex, &count, &seed] {
      for (size_t i = 0; i < 500; ++i) {
        int16_t val;
        {
          absl::MutexLock l(&mutex);
          val = (rand_r(&seed) % 10 + 1);  // Rand between 1 and 10.
          count += val;
        }
        struct sembuf buf = {};
        buf.sem_op = val;
        ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());
        absl::SleepFor(absl::Milliseconds(val * 2));
      }
    });
  }

  // First wait for signal threads to be done.
  for (auto& inc : incs) {
    inc->Join();
  }

  // Now there could be waiters blocked (remember operations are random).
  // Notify waiters that we're done and signal semaphore just the right amount.
  {
    absl::MutexLock l(&mutex);
    done = true;
    struct sembuf buf = {};
    buf.sem_op = -count;
    ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());
  }

  // Now all waiters should unblock and exit.
  for (auto& dec : decs) {
    dec->Join();
  }
  for (auto& zero : zeros) {
    zero->Join();
  }
}

TEST(SemaphoreTest, SemOpNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  AutoSem sem(semget(123, 1, 0600 | IPC_CREAT | IPC_EXCL));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  ScopedThread([]() {
    EXPECT_THAT(unshare(CLONE_NEWIPC), SyscallSucceeds());
    AutoSem sem(semget(123, 1, 0600 | IPC_CREAT | IPC_EXCL));
    ASSERT_THAT(sem.get(), SyscallSucceeds());
  });
}

TEST(SemaphoreTest, SemCtlVal) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  // Semaphore must start with 0.
  EXPECT_THAT(semctl(sem.get(), 0, GETVAL), SyscallSucceedsWithValue(0));

  // Increase value and ensure waiters are woken up.
  ScopedThread th([&sem] {
    struct sembuf buf = {};
    buf.sem_op = -10;
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
  });

  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 9), SyscallSucceeds());
  EXPECT_THAT(semctl(sem.get(), 0, GETVAL), SyscallSucceedsWithValue(9));

  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 20), SyscallSucceeds());
  const int value = semctl(sem.get(), 0, GETVAL);
  // 10 or 20 because it could have raced with waiter above.
  EXPECT_TRUE(value == 10 || value == 20) << "value=" << value;
  th.Join();

  // Set it back to 0 and ensure that waiters are woken up.
  ScopedThread thZero([&sem] {
    struct sembuf buf = {};
    buf.sem_op = 0;
    ASSERT_THAT(RetryEINTR(semop)(sem.get(), &buf, 1), SyscallSucceeds());
  });
  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 0), SyscallSucceeds());
  EXPECT_THAT(semctl(sem.get(), 0, GETVAL), SyscallSucceedsWithValue(0));
  thZero.Join();
}

TEST(SemaphoreTest, SemCtlValAll) {
  AutoSem sem(semget(IPC_PRIVATE, 3, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  // Semaphores must start with 0.
  uint16_t get[3] = {10, 10, 10};
  EXPECT_THAT(semctl(sem.get(), 1, GETALL, get), SyscallSucceedsWithValue(0));
  for (auto v : get) {
    EXPECT_EQ(v, 0);
  }

  // SetAll and check that they were set.
  uint16_t vals[3] = {0, 10, 20};
  EXPECT_THAT(semctl(sem.get(), 1, SETALL, vals), SyscallSucceedsWithValue(0));
  EXPECT_THAT(semctl(sem.get(), 1, GETALL, get), SyscallSucceedsWithValue(0));
  for (size_t i = 0; i < ABSL_ARRAYSIZE(vals); ++i) {
    EXPECT_EQ(get[i], vals[i]);
  }

  EXPECT_THAT(semctl(sem.get(), 1, SETALL, nullptr),
              SyscallFailsWithErrno(EFAULT));
}

TEST(SemaphoreTest, SemCtlGetPid) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 1), SyscallSucceeds());
  EXPECT_THAT(semctl(sem.get(), 0, GETPID), SyscallSucceedsWithValue(getpid()));
}

TEST(SemaphoreTest, SemCtlGetPidFork) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  const pid_t child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(semctl(sem.get(), 0, SETVAL, 1) == 0);
    TEST_PCHECK(semctl(sem.get(), 0, GETPID) == getpid());

    _exit(0);
  }
  ASSERT_THAT(child_pid, SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

TEST(SemaphoreTest, SemIpcSet) {
  // Drop CAP_IPC_OWNER which allows us to bypass semaphore permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_IPC_OWNER, false));

  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  struct semid_ds semid = {};
  semid.sem_perm.uid = getuid();
  semid.sem_perm.gid = getgid();

  // Make semaphore readonly and check that signal fails.
  semid.sem_perm.mode = 0400;
  EXPECT_THAT(semctl(sem.get(), 0, IPC_SET, &semid), SyscallSucceeds());
  struct sembuf buf = {};
  buf.sem_op = 1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallFailsWithErrno(EACCES));

  // Make semaphore writeonly and check that wait for zero fails.
  semid.sem_perm.mode = 0200;
  EXPECT_THAT(semctl(sem.get(), 0, IPC_SET, &semid), SyscallSucceeds());
  buf.sem_op = 0;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallFailsWithErrno(EACCES));
}

TEST(SemaphoreTest, SemCtlIpcStat) {
  // Drop CAP_IPC_OWNER which allows us to bypass semaphore permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_IPC_OWNER, false));
  const uid_t kUid = getuid();
  const gid_t kGid = getgid();
  time_t start_time = time(nullptr);

  AutoSem sem(semget(IPC_PRIVATE, 10, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  struct semid_ds ds;
  EXPECT_THAT(semctl(sem.get(), 0, IPC_STAT, &ds), SyscallSucceeds());

  EXPECT_EQ(ds.sem_perm.__key, IPC_PRIVATE);
  EXPECT_EQ(ds.sem_perm.uid, kUid);
  EXPECT_EQ(ds.sem_perm.gid, kGid);
  EXPECT_EQ(ds.sem_perm.cuid, kUid);
  EXPECT_EQ(ds.sem_perm.cgid, kGid);
  EXPECT_EQ(ds.sem_perm.mode, 0600);
  // Last semop time is not set on creation.
  EXPECT_EQ(ds.sem_otime, 0);
  EXPECT_GE(ds.sem_ctime, start_time);
  EXPECT_EQ(ds.sem_nsems, 10);

  // The timestamps only have a resolution of seconds; slow down so we actually
  // see the timestamps change.
  absl::SleepFor(absl::Seconds(1));

  // Set semid_ds structure of the set.
  auto last_ctime = ds.sem_ctime;
  start_time = time(nullptr);
  struct semid_ds semid_to_set = {};
  semid_to_set.sem_perm.uid = kUid;
  semid_to_set.sem_perm.gid = kGid;
  semid_to_set.sem_perm.mode = 0666;
  ASSERT_THAT(semctl(sem.get(), 0, IPC_SET, &semid_to_set), SyscallSucceeds());
  struct sembuf buf = {};
  buf.sem_op = 1;
  ASSERT_THAT(semop(sem.get(), &buf, 1), SyscallSucceeds());

  EXPECT_THAT(semctl(sem.get(), 0, IPC_STAT, &ds), SyscallSucceeds());
  EXPECT_EQ(ds.sem_perm.mode, 0666);
  EXPECT_GE(ds.sem_otime, start_time);
  EXPECT_GT(ds.sem_ctime, last_ctime);

  // An invalid semid fails the syscall with errno EINVAL.
  EXPECT_THAT(semctl(sem.get() + 1, 0, IPC_STAT, &ds),
              SyscallFailsWithErrno(EINVAL));

  // Make semaphore not readable and check the signal fails.
  semid_to_set.sem_perm.mode = 0200;
  ASSERT_THAT(semctl(sem.get(), 0, IPC_SET, &semid_to_set), SyscallSucceeds());
  EXPECT_THAT(semctl(sem.get(), 0, IPC_STAT, &ds),
              SyscallFailsWithErrno(EACCES));
}

// Calls semctl(semid, 0, cmd) until the returned value is >= target, an
// internal timeout expires, or semctl returns an error.
PosixErrorOr<int> WaitSemctl(int semid, int target, int cmd) {
  constexpr absl::Duration timeout = absl::Seconds(10);
  const auto deadline = absl::Now() + timeout;
  int semcnt = 0;
  while (absl::Now() < deadline) {
    semcnt = semctl(semid, 0, cmd);
    if (semcnt < 0) {
      return PosixError(errno, "semctl(GETZCNT) failed");
    }
    if (semcnt >= target) {
      break;
    }
    absl::SleepFor(absl::Milliseconds(10));
  }
  return semcnt;
}

TEST(SemaphoreTest, SemopGetzcnt) {
  // Drop CAP_IPC_OWNER which allows us to bypass semaphore permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_IPC_OWNER, false));
  // Create a write only semaphore set.
  AutoSem sem(semget(IPC_PRIVATE, 1, 0200 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  // No read permission to retrieve semzcnt.
  EXPECT_THAT(semctl(sem.get(), 0, GETZCNT), SyscallFailsWithErrno(EACCES));

  // Remove the calling thread's read permission.
  struct semid_ds ds = {};
  ds.sem_perm.uid = getuid();
  ds.sem_perm.gid = getgid();
  ds.sem_perm.mode = 0600;
  ASSERT_THAT(semctl(sem.get(), 0, IPC_SET, &ds), SyscallSucceeds());

  std::vector<pid_t> children;
  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 1), SyscallSucceeds());

  struct sembuf buf = {};
  buf.sem_num = 0;
  buf.sem_op = 0;
  constexpr size_t kLoops = 10;
  for (size_t i = 0; i < kLoops; i++) {
    auto child_pid = fork();
    if (child_pid == 0) {
      TEST_PCHECK(RetryEINTR(semop)(sem.get(), &buf, 1) == 0);
      _exit(0);
    }
    children.push_back(child_pid);
  }

  EXPECT_THAT(WaitSemctl(sem.get(), kLoops, GETZCNT),
              IsPosixErrorOkAndHolds(kLoops));
  // Set semval to 0, which wakes up children that sleep on the semop.
  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 0), SyscallSucceeds());
  for (const auto& child_pid : children) {
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  EXPECT_EQ(semctl(sem.get(), 0, GETZCNT), 0);
}

TEST(SemaphoreTest, SemopGetzcntOnSetRemoval) {
  auto semid = semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT);
  ASSERT_THAT(semid, SyscallSucceeds());
  ASSERT_THAT(semctl(semid, 0, SETVAL, 1), SyscallSucceeds());
  ASSERT_EQ(semctl(semid, 0, GETZCNT), 0);

  auto child_pid = fork();
  if (child_pid == 0) {
    struct sembuf buf = {};
    buf.sem_num = 0;
    buf.sem_op = 0;

    // Ensure that wait will only unblock when the semaphore is removed. On
    // EINTR retry it may race with deletion and return EINVAL.
    TEST_PCHECK(RetryEINTR(semop)(semid, &buf, 1) < 0 &&
                (errno == EIDRM || errno == EINVAL));
    _exit(0);
  }

  EXPECT_THAT(WaitSemctl(semid, 1, GETZCNT), IsPosixErrorOkAndHolds(1));
  // Remove the semaphore set, which fails the sleep semop.
  ASSERT_THAT(semctl(semid, 0, IPC_RMID), SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  EXPECT_THAT(semctl(semid, 0, GETZCNT), SyscallFailsWithErrno(EINVAL));
}

TEST(SemaphoreTest, SemopGetzcntOnSignal_NoRandomSave) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());
  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 1), SyscallSucceeds());
  ASSERT_EQ(semctl(sem.get(), 0, GETZCNT), 0);

  // Saving will cause semop() to be spuriously interrupted.
  DisableSave ds;

  auto child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(signal(SIGHUP, [](int sig) -> void {}) != SIG_ERR);
    struct sembuf buf = {};
    buf.sem_num = 0;
    buf.sem_op = 0;

    TEST_PCHECK(semop(sem.get(), &buf, 1) < 0 && errno == EINTR);
    _exit(0);
  }

  EXPECT_THAT(WaitSemctl(sem.get(), 1, GETZCNT), IsPosixErrorOkAndHolds(1));
  // Send a signal to the child, which fails the sleep semop.
  ASSERT_EQ(kill(child_pid, SIGHUP), 0);

  ds.reset();

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  EXPECT_EQ(semctl(sem.get(), 0, GETZCNT), 0);
}

TEST(SemaphoreTest, SemopGetncnt) {
  // Drop CAP_IPC_OWNER which allows us to bypass semaphore permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_IPC_OWNER, false));
  // Create a write only semaphore set.
  AutoSem sem(semget(IPC_PRIVATE, 1, 0200 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());

  // No read permission to retrieve semzcnt.
  EXPECT_THAT(semctl(sem.get(), 0, GETNCNT), SyscallFailsWithErrno(EACCES));

  // Remove the calling thread's read permission.
  struct semid_ds ds = {};
  ds.sem_perm.uid = getuid();
  ds.sem_perm.gid = getgid();
  ds.sem_perm.mode = 0600;
  ASSERT_THAT(semctl(sem.get(), 0, IPC_SET, &ds), SyscallSucceeds());

  std::vector<pid_t> children;

  struct sembuf buf = {};
  buf.sem_num = 0;
  buf.sem_op = -1;
  constexpr size_t kLoops = 10;
  for (size_t i = 0; i < kLoops; i++) {
    auto child_pid = fork();
    if (child_pid == 0) {
      TEST_PCHECK(RetryEINTR(semop)(sem.get(), &buf, 1) == 0);
      _exit(0);
    }
    children.push_back(child_pid);
  }
  EXPECT_THAT(WaitSemctl(sem.get(), kLoops, GETNCNT),
              IsPosixErrorOkAndHolds(kLoops));
  // Set semval to 1, which wakes up children that sleep on the semop.
  ASSERT_THAT(semctl(sem.get(), 0, SETVAL, kLoops), SyscallSucceeds());
  for (const auto& child_pid : children) {
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  EXPECT_EQ(semctl(sem.get(), 0, GETNCNT), 0);
}

TEST(SemaphoreTest, SemopGetncntOnSetRemoval) {
  auto semid = semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT);
  ASSERT_THAT(semid, SyscallSucceeds());
  ASSERT_EQ(semctl(semid, 0, GETNCNT), 0);

  auto child_pid = fork();
  if (child_pid == 0) {
    struct sembuf buf = {};
    buf.sem_num = 0;
    buf.sem_op = -1;

    // Ensure that wait will only unblock when the semaphore is removed. On
    // EINTR retry it may race with deletion and return EINVAL
    TEST_PCHECK(RetryEINTR(semop)(semid, &buf, 1) < 0 &&
                (errno == EIDRM || errno == EINVAL));
    _exit(0);
  }

  EXPECT_THAT(WaitSemctl(semid, 1, GETNCNT), IsPosixErrorOkAndHolds(1));
  // Remove the semaphore set, which fails the sleep semop.
  ASSERT_THAT(semctl(semid, 0, IPC_RMID), SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  EXPECT_THAT(semctl(semid, 0, GETNCNT), SyscallFailsWithErrno(EINVAL));
}

TEST(SemaphoreTest, SemopGetncntOnSignal_NoRandomSave) {
  AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
  ASSERT_THAT(sem.get(), SyscallSucceeds());
  ASSERT_EQ(semctl(sem.get(), 0, GETNCNT), 0);

  // Saving will cause semop() to be spuriously interrupted.
  DisableSave ds;

  auto child_pid = fork();
  if (child_pid == 0) {
    TEST_PCHECK(signal(SIGHUP, [](int sig) -> void {}) != SIG_ERR);
    struct sembuf buf = {};
    buf.sem_num = 0;
    buf.sem_op = -1;

    TEST_PCHECK(semop(sem.get(), &buf, 1) < 0 && errno == EINTR);
    _exit(0);
  }
  EXPECT_THAT(WaitSemctl(sem.get(), 1, GETNCNT), IsPosixErrorOkAndHolds(1));
  // Send a signal to the child, which fails the sleep semop.
  ASSERT_EQ(kill(child_pid, SIGHUP), 0);

  ds.reset();

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  EXPECT_EQ(semctl(sem.get(), 0, GETNCNT), 0);
}

TEST(SemaphoreTest, IpcInfo) {
  constexpr int kLoops = 5;
  std::set<int> sem_ids;
  struct seminfo info;
  // Drop CAP_IPC_OWNER which allows us to bypass semaphore permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_IPC_OWNER, false));
  for (int i = 0; i < kLoops; i++) {
    AutoSem sem(semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT));
    ASSERT_THAT(sem.get(), SyscallSucceeds());
    sem_ids.insert(sem.release());
  }
  ASSERT_EQ(sem_ids.size(), kLoops);

  int max_used_index = 0;
  EXPECT_THAT(max_used_index = semctl(0, 0, IPC_INFO, &info),
              SyscallSucceeds());

  std::set<int> sem_ids_before_max_index;
  for (int i = 0; i <= max_used_index; i++) {
    struct semid_ds ds = {};
    int sem_id = semctl(i, 0, SEM_STAT, &ds);
    // Only if index i is used within the registry.
    if (sem_ids.find(sem_id) != sem_ids.end()) {
      struct semid_ds ipc_stat_ds;
      ASSERT_THAT(semctl(sem_id, 0, IPC_STAT, &ipc_stat_ds), SyscallSucceeds());
      EXPECT_EQ(ds.sem_perm.__key, ipc_stat_ds.sem_perm.__key);
      EXPECT_EQ(ds.sem_perm.uid, ipc_stat_ds.sem_perm.uid);
      EXPECT_EQ(ds.sem_perm.gid, ipc_stat_ds.sem_perm.gid);
      EXPECT_EQ(ds.sem_perm.cuid, ipc_stat_ds.sem_perm.cuid);
      EXPECT_EQ(ds.sem_perm.cgid, ipc_stat_ds.sem_perm.cgid);
      EXPECT_EQ(ds.sem_perm.mode, ipc_stat_ds.sem_perm.mode);
      EXPECT_EQ(ds.sem_otime, ipc_stat_ds.sem_otime);
      EXPECT_EQ(ds.sem_ctime, ipc_stat_ds.sem_ctime);
      EXPECT_EQ(ds.sem_nsems, ipc_stat_ds.sem_nsems);

      // Remove the semaphore set's read permission.
      struct semid_ds ipc_set_ds;
      ipc_set_ds.sem_perm.uid = getuid();
      ipc_set_ds.sem_perm.gid = getgid();
      // Keep the semaphore set's write permission so that it could be removed.
      ipc_set_ds.sem_perm.mode = 0200;
      ASSERT_THAT(semctl(sem_id, 0, IPC_SET, &ipc_set_ds), SyscallSucceeds());
      ASSERT_THAT(semctl(i, 0, SEM_STAT, &ds), SyscallFailsWithErrno(EACCES));

      sem_ids_before_max_index.insert(sem_id);
    }
  }
  EXPECT_EQ(sem_ids_before_max_index.size(), kLoops);
  for (const int sem_id : sem_ids) {
    ASSERT_THAT(semctl(sem_id, 0, IPC_RMID), SyscallSucceeds());
  }

  ASSERT_THAT(semctl(0, 0, IPC_INFO, &info), SyscallSucceeds());
  EXPECT_EQ(info.semmap, kSemMap);
  EXPECT_EQ(info.semmni, kSemMni);
  EXPECT_EQ(info.semmns, kSemMns);
  EXPECT_EQ(info.semmnu, kSemMnu);
  EXPECT_EQ(info.semmsl, kSemMsl);
  EXPECT_EQ(info.semopm, kSemOpm);
  EXPECT_EQ(info.semume, kSemUme);
  EXPECT_EQ(info.semusz, kSemUsz);
  EXPECT_EQ(info.semvmx, kSemVmx);
  EXPECT_EQ(info.semaem, kSemAem);
}

TEST(SemaphoreTest, SemInfo) {
  constexpr int kLoops = 5;
  constexpr int kSemSetSize = 3;
  std::set<int> sem_ids;
  struct seminfo info;
  // Drop CAP_IPC_OWNER which allows us to bypass semaphore permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_IPC_OWNER, false));
  for (int i = 0; i < kLoops; i++) {
    AutoSem sem(semget(IPC_PRIVATE, kSemSetSize, 0600 | IPC_CREAT));
    ASSERT_THAT(sem.get(), SyscallSucceeds());
    sem_ids.insert(sem.release());
  }
  ASSERT_EQ(sem_ids.size(), kLoops);
  int max_used_index = 0;
  EXPECT_THAT(max_used_index = semctl(0, 0, SEM_INFO, &info),
              SyscallSucceeds());
  EXPECT_EQ(info.semmap, kSemMap);
  EXPECT_EQ(info.semmni, kSemMni);
  EXPECT_EQ(info.semmns, kSemMns);
  EXPECT_EQ(info.semmnu, kSemMnu);
  EXPECT_EQ(info.semmsl, kSemMsl);
  EXPECT_EQ(info.semopm, kSemOpm);
  EXPECT_EQ(info.semume, kSemUme);
  // There could be semaphores existing in the system during the test, which
  // prevents the test from getting a exact number, but the test could expect at
  // least the number of sempahroes it creates in the begining of the test.
  EXPECT_GE(info.semusz, sem_ids.size());
  EXPECT_EQ(info.semvmx, kSemVmx);
  EXPECT_GE(info.semaem, sem_ids.size() * kSemSetSize);

  std::set<int> sem_ids_before_max_index;
  for (int i = 0; i <= max_used_index; i++) {
    struct semid_ds ds = {};
    int sem_id = semctl(i, 0, SEM_STAT, &ds);
    // Only if index i is used within the registry.
    if (sem_ids.find(sem_id) != sem_ids.end()) {
      struct semid_ds ipc_stat_ds;
      ASSERT_THAT(semctl(sem_id, 0, IPC_STAT, &ipc_stat_ds), SyscallSucceeds());
      EXPECT_EQ(ds.sem_perm.__key, ipc_stat_ds.sem_perm.__key);
      EXPECT_EQ(ds.sem_perm.uid, ipc_stat_ds.sem_perm.uid);
      EXPECT_EQ(ds.sem_perm.gid, ipc_stat_ds.sem_perm.gid);
      EXPECT_EQ(ds.sem_perm.cuid, ipc_stat_ds.sem_perm.cuid);
      EXPECT_EQ(ds.sem_perm.cgid, ipc_stat_ds.sem_perm.cgid);
      EXPECT_EQ(ds.sem_perm.mode, ipc_stat_ds.sem_perm.mode);
      EXPECT_EQ(ds.sem_otime, ipc_stat_ds.sem_otime);
      EXPECT_EQ(ds.sem_ctime, ipc_stat_ds.sem_ctime);
      EXPECT_EQ(ds.sem_nsems, ipc_stat_ds.sem_nsems);

      // Remove the semaphore set's read permission.
      struct semid_ds ipc_set_ds;
      ipc_set_ds.sem_perm.uid = getuid();
      ipc_set_ds.sem_perm.gid = getgid();
      // Keep the semaphore set's write permission so that it could be removed.
      ipc_set_ds.sem_perm.mode = 0200;
      ASSERT_THAT(semctl(sem_id, 0, IPC_SET, &ipc_set_ds), SyscallSucceeds());
      ASSERT_THAT(semctl(i, 0, SEM_STAT, &ds), SyscallFailsWithErrno(EACCES));

      sem_ids_before_max_index.insert(sem_id);
    }
  }
  EXPECT_EQ(sem_ids_before_max_index.size(), kLoops);
  for (const int sem_id : sem_ids) {
    ASSERT_THAT(semctl(sem_id, 0, IPC_RMID), SyscallSucceeds());
  }

  ASSERT_THAT(semctl(0, 0, SEM_INFO, &info), SyscallSucceeds());
  EXPECT_EQ(info.semmap, kSemMap);
  EXPECT_EQ(info.semmni, kSemMni);
  EXPECT_EQ(info.semmns, kSemMns);
  EXPECT_EQ(info.semmnu, kSemMnu);
  EXPECT_EQ(info.semmsl, kSemMsl);
  EXPECT_EQ(info.semopm, kSemOpm);
  EXPECT_EQ(info.semume, kSemUme);
  // Apart from semapahores that are not created by the test, we can't determine
  // the exact number of semaphore sets and semaphores, as a result, semusz and
  // semaem range from 0 to a random number. Since the numbers are always
  // non-negative, the test will not check the reslts of semusz and semaem.
  EXPECT_EQ(info.semvmx, kSemVmx);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
