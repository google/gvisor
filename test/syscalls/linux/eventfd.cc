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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/epoll_util.h"
#include "test/util/eventfd_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(EventfdTest, Nonblock) {
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));

  uint64_t l;
  ASSERT_THAT(read(efd.get(), &l, sizeof(l)), SyscallFailsWithErrno(EAGAIN));

  l = 1;
  ASSERT_THAT(write(efd.get(), &l, sizeof(l)), SyscallSucceeds());

  l = 0;
  ASSERT_THAT(read(efd.get(), &l, sizeof(l)), SyscallSucceeds());
  EXPECT_EQ(l, 1);

  ASSERT_THAT(read(efd.get(), &l, sizeof(l)), SyscallFailsWithErrno(EAGAIN));
}

void* read_three_times(void* arg) {
  int efd = *reinterpret_cast<int*>(arg);
  uint64_t l;
  read(efd, &l, sizeof(l));
  read(efd, &l, sizeof(l));
  read(efd, &l, sizeof(l));
  return nullptr;
}

TEST(EventfdTest, BlockingWrite) {
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_SEMAPHORE));
  int efd = fd.get();

  pthread_t p;
  ASSERT_THAT(pthread_create(&p, nullptr, read_three_times,
                             reinterpret_cast<void*>(&efd)),
              SyscallSucceeds());

  uint64_t l = 1;
  ASSERT_THAT(write(efd, &l, sizeof(l)), SyscallSucceeds());
  EXPECT_EQ(l, 1);

  ASSERT_THAT(write(efd, &l, sizeof(l)), SyscallSucceeds());
  EXPECT_EQ(l, 1);

  ASSERT_THAT(write(efd, &l, sizeof(l)), SyscallSucceeds());
  EXPECT_EQ(l, 1);

  ASSERT_THAT(pthread_join(p, nullptr), SyscallSucceeds());
}

TEST(EventfdTest, SmallWrite) {
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));

  uint64_t l = 16;
  ASSERT_THAT(write(efd.get(), &l, 4), SyscallFailsWithErrno(EINVAL));
}

TEST(EventfdTest, SmallRead) {
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));

  uint64_t l = 1;
  ASSERT_THAT(write(efd.get(), &l, sizeof(l)), SyscallSucceeds());

  l = 0;
  ASSERT_THAT(read(efd.get(), &l, 4), SyscallFailsWithErrno(EINVAL));
}

TEST(EventfdTest, BigWrite) {
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));

  uint64_t big[16];
  big[0] = 16;
  ASSERT_THAT(write(efd.get(), big, sizeof(big)), SyscallSucceeds());
}

TEST(EventfdTest, BigRead) {
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));

  uint64_t l = 1;
  ASSERT_THAT(write(efd.get(), &l, sizeof(l)), SyscallSucceeds());

  uint64_t big[16];
  ASSERT_THAT(read(efd.get(), big, sizeof(big)), SyscallSucceeds());
  EXPECT_EQ(big[0], 1);
}

TEST(EventfdTest, BigWriteBigRead) {
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_NONBLOCK | EFD_SEMAPHORE));

  uint64_t l[16];
  l[0] = 16;
  ASSERT_THAT(write(efd.get(), l, sizeof(l)), SyscallSucceeds());
  ASSERT_THAT(read(efd.get(), l, sizeof(l)), SyscallSucceeds());
  EXPECT_EQ(l[0], 1);
}

// NotifyNonZero is inherently racy, so random save is disabled.
TEST(EventfdTest, NotifyNonZero_NoRandomSave) {
  // Waits will time out at 10 seconds.
  constexpr int kEpollTimeoutMs = 10000;
  // Create an eventfd descriptor.
  FileDescriptor efd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(7, EFD_NONBLOCK | EFD_SEMAPHORE));
  // Create an epoll fd to listen to efd.
  FileDescriptor epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  // Add efd to epoll.
  ASSERT_NO_ERRNO(
      RegisterEpollFD(epollfd.get(), efd.get(), EPOLLIN | EPOLLET, efd.get()));

  // Use epoll to get a value from efd.
  struct epoll_event out_ev;
  int wait_out = epoll_wait(epollfd.get(), &out_ev, 1, kEpollTimeoutMs);
  EXPECT_EQ(wait_out, 1);
  EXPECT_EQ(efd.get(), out_ev.data.fd);
  uint64_t val = 0;
  ASSERT_THAT(read(efd.get(), &val, sizeof(val)), SyscallSucceeds());
  EXPECT_EQ(val, 1);

  // Start a thread that, after this thread blocks on epoll_wait, will write to
  // efd. This is racy -- it's possible that this write will happen after
  // epoll_wait times out.
  ScopedThread t([&efd] {
    sleep(5);
    uint64_t val = 1;
    write(efd.get(), &val, sizeof(val));
  });

  // epoll_wait should return once the thread writes.
  wait_out = epoll_wait(epollfd.get(), &out_ev, 1, kEpollTimeoutMs);
  EXPECT_EQ(wait_out, 1);
  EXPECT_EQ(efd.get(), out_ev.data.fd);

  val = 0;
  ASSERT_THAT(read(efd.get(), &val, sizeof(val)), SyscallSucceeds());
  EXPECT_EQ(val, 1);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
