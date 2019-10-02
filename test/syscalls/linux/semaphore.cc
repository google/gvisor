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

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>

#include <atomic>
#include <cerrno>
#include <ctime>

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
    ASSERT_THAT(semctl(sem.get(), 0, SETVAL, 1), SyscallSucceeds());
    ASSERT_THAT(semctl(sem.get(), 0, GETPID),
                SyscallSucceedsWithValue(getpid()));

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

}  // namespace
}  // namespace testing
}  // namespace gvisor
