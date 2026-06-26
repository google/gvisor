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
#include <linux/sched.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Taken from the v1 version of Linux's struct sched_attr.
//
// In the future, if our tests' libc is updated to include this struct in the
// headers, this definition can be safely removed.
struct sched_attr {
  __u32 size;

  __u32 sched_policy;
  __u64 sched_flags;

  /* SCHED_NORMAL, SCHED_BATCH */
  __s32 sched_nice;

  /* SCHED_FIFO, SCHED_RR */
  __u32 sched_priority;

  /* SCHED_DEADLINE */
  __u64 sched_runtime;
  __u64 sched_deadline;
  __u64 sched_period;

  /* Utilization hints */
  __u32 sched_util_min;
  __u32 sched_util_max;
};

// In linux, pid is limited to 29 bits because how futex is implemented.
constexpr int kImpossiblePID = (1 << 29) + 1;

int sched_setattr(pid_t pid, struct sched_attr* attr, unsigned int flags) {
  return syscall(SYS_sched_setattr, pid, attr, flags);
}

int sched_getattr(pid_t pid, struct sched_attr* attr, unsigned int size,
                  unsigned int flags) {
  return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

PosixErrorOr<Cleanup> schedulerCleanup() {
  struct sched_attr old = {};
  int ret = sched_getattr(0, &old, sizeof(old), 0);
  if (ret < 0) {
    return PosixError(errno, "ioprio_get() failed");
  }

  return Cleanup([old]() mutable { sched_setattr(0, &old, 0); });
}

TEST(SchedGetparamTest, ReturnsZero) {
  struct sched_param param;
  EXPECT_THAT(sched_getparam(getpid(), &param), SyscallSucceeds());
  EXPECT_EQ(param.sched_priority, 0);
  EXPECT_THAT(sched_getparam(/*pid=*/0, &param), SyscallSucceeds());
  EXPECT_EQ(param.sched_priority, 0);
}

TEST(SchedGetparamTest, InvalidPIDReturnsEINVAL) {
  struct sched_param param;
  EXPECT_THAT(sched_getparam(/*pid=*/-1, &param),
              SyscallFailsWithErrno(EINVAL));
}

TEST(SchedGetparamTest, ImpossiblePIDReturnsESRCH) {
  struct sched_param param;
  EXPECT_THAT(sched_getparam(kImpossiblePID, &param),
              SyscallFailsWithErrno(ESRCH));
}

TEST(SchedGetparamTest, NullParamReturnsEINVAL) {
  EXPECT_THAT(sched_getparam(0, nullptr), SyscallFailsWithErrno(EINVAL));
}

TEST(SchedGetschedulerTest, ReturnsSchedOther) {
  EXPECT_THAT(sched_getscheduler(getpid()),
              SyscallSucceedsWithValue(SCHED_OTHER));
  EXPECT_THAT(sched_getscheduler(/*pid=*/0),
              SyscallSucceedsWithValue(SCHED_OTHER));
}

TEST(SchedGetschedulerTest, ReturnsEINVAL) {
  EXPECT_THAT(sched_getscheduler(/*pid=*/-1), SyscallFailsWithErrno(EINVAL));
}

TEST(SchedGetschedulerTest, ReturnsESRCH) {
  EXPECT_THAT(sched_getscheduler(kImpossiblePID), SyscallFailsWithErrno(ESRCH));
}

TEST(SchedSetschedulerTest, BasicSetGet) {
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(schedulerCleanup());

  struct sched_param param = {};
  EXPECT_THAT(sched_setscheduler(0, SCHED_BATCH, &param), SyscallSucceeds());

  int policy = sched_getscheduler(0);
  EXPECT_THAT(policy, SyscallSucceeds());
  EXPECT_EQ(policy, SCHED_BATCH);
}

TEST(SchedAttrTest, InvalidPIDReturnsEINVAL) {
  struct sched_attr attr = {};
  EXPECT_THAT(sched_setattr(-1, &attr, 0), SyscallFailsWithErrno(EINVAL));
}

TEST(SchedAttrTest, ImpossiblePIDReturnsESRCH) {
  struct sched_attr attr = {};
  EXPECT_THAT(sched_setattr(kImpossiblePID, &attr, 0),
              SyscallFailsWithErrno(ESRCH));
}

TEST(SchedAttrTest, BasicSetGet) {
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(schedulerCleanup());

  struct sched_attr attr = {};

  EXPECT_THAT(sched_getattr(0, &attr, sizeof(attr), 0), SyscallSucceeds());
  EXPECT_EQ(attr.sched_policy, SCHED_OTHER);
  EXPECT_EQ(attr.sched_nice, 0);

  attr = {
      .size = sizeof(attr),
      .sched_policy = SCHED_BATCH,
      .sched_nice = 5,
  };

  EXPECT_THAT(sched_setattr(0, &attr, 0), SyscallSucceeds());

  struct sched_attr gotten = {};
  EXPECT_THAT(sched_getattr(0, &gotten, sizeof(gotten), 0), SyscallSucceeds());
  EXPECT_EQ(gotten.sched_policy, SCHED_BATCH);
  EXPECT_EQ(gotten.sched_nice, 5);
}

TEST(SchedAttrTest, ChildPID) {
  pid_t pid = fork();
  ASSERT_THAT(pid, SyscallSucceeds());
  if (pid == 0) {
    while (1) {
      absl::SleepFor(absl::Seconds(60));
    }
  }
  auto cleanup = Cleanup([&pid] {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
  });

  // We are the parent; set the child's scheduling properties
  struct sched_attr attr = {
      .size = sizeof(attr),
      .sched_policy = SCHED_IDLE,
  };
  EXPECT_THAT(sched_setattr(pid, &attr, 0), SyscallSucceeds());

  struct sched_attr gotten = {};
  EXPECT_THAT(sched_getattr(pid, &gotten, sizeof(gotten), 0),
              SyscallSucceeds());
  EXPECT_EQ(gotten.sched_policy, SCHED_IDLE);

  // Check that parent's nice was not affected
  struct sched_attr parent = {};
  EXPECT_THAT(sched_getattr(0, &parent, sizeof(parent), 0), SyscallSucceeds());
  EXPECT_NE(parent.sched_policy, SCHED_IDLE);
}

TEST(SchedAttrTest, InvalidArgs) {
  struct sched_attr attr = {};
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_OTHER;

  attr.sched_nice = 5;

  // Null pointer
  EXPECT_THAT(sched_setattr(0, nullptr, 0), SyscallFailsWithErrno(EINVAL));

  // Invalid struct size (too small, but not 0)
  attr.size = 12;
  EXPECT_THAT(sched_setattr(0, &attr, 0), SyscallFailsWithErrno(E2BIG));
  attr.size = sizeof(attr);

  // Unsupported flag
  EXPECT_THAT(sched_setattr(0, &attr, 0x02), SyscallFailsWithErrno(EINVAL));

  // Unsupported policy
  attr.sched_policy = SCHED_DEADLINE;
  EXPECT_THAT(sched_setattr(0, &attr, 0), SyscallFailsWithErrno(EINVAL));
}

TEST(SchedAttrTest, StructSizeE2BIG) {
  // Get the kernel size of the struct
  struct sched_attr fetch_attr = {
      .size = 1,
  };
  EXPECT_THAT(sched_setattr(0, &fetch_attr, 0), SyscallFailsWithErrno(E2BIG));
  EXPECT_GT(fetch_attr.size, 0);

  // Simulate a "newer" version of the struct.
  // The extra bytes are initialized non-zero
  uint32_t usize = fetch_attr.size + sizeof(struct sched_attr);
  char* buf = new char[usize];
  auto cleanup = Cleanup([&buf] { delete[] buf; });
  memset(buf, 50, usize);
  struct sched_attr* attr = (struct sched_attr*)buf;
  *attr = {
      .size = usize,
  };

  EXPECT_THAT(sched_setattr(0, attr, 0), SyscallFailsWithErrno(E2BIG));
  // The kernel should again specify the real size
  EXPECT_EQ(attr->size, fetch_attr.size);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
