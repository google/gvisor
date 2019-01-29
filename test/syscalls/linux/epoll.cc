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

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/epoll_util.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int kFDsPerEpoll = 3;
constexpr uint64_t kMagicConstant = 0x0102030405060708;

uint64_t ms_elapsed(const struct timespec* begin, const struct timespec* end) {
  return (end->tv_sec - begin->tv_sec) * 1000 +
         (end->tv_nsec - begin->tv_nsec) / 1000000;
}

TEST(EpollTest, AllWritable) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(),
                                    EPOLLIN | EPOLLOUT, kMagicConstant + i));
  }

  struct epoll_event result[kFDsPerEpoll];
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(kFDsPerEpoll));
  // TODO: Why do some tests check epoll_event::data, and others
  // don't? Does Linux actually guarantee that, in any of these test cases,
  // epoll_wait will necessarily write out the epoll_events in the order that
  // they were registered?
  for (int i = 0; i < kFDsPerEpoll; i++) {
    ASSERT_EQ(result[i].events, EPOLLOUT);
  }
}

TEST(EpollTest, LastReadable) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(),
                                    EPOLLIN | EPOLLOUT, kMagicConstant + i));
  }

  uint64_t tmp = 1;
  ASSERT_THAT(WriteFd(eventfds[kFDsPerEpoll - 1].get(), &tmp, sizeof(tmp)),
              SyscallSucceedsWithValue(sizeof(tmp)));

  struct epoll_event result[kFDsPerEpoll];
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(kFDsPerEpoll));

  int i;
  for (i = 0; i < kFDsPerEpoll - 1; i++) {
    EXPECT_EQ(result[i].events, EPOLLOUT);
  }
  EXPECT_EQ(result[i].events, EPOLLOUT | EPOLLIN);
  EXPECT_EQ(result[i].data.u64, kMagicConstant + i);
}

TEST(EpollTest, LastNonWritable) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(),
                                    EPOLLIN | EPOLLOUT, kMagicConstant + i));
  }

  // Write the maximum value to the event fd so that writing to it again would
  // block.
  uint64_t tmp = ULLONG_MAX - 1;
  ASSERT_THAT(WriteFd(eventfds[kFDsPerEpoll - 1].get(), &tmp, sizeof(tmp)),
              SyscallSucceedsWithValue(sizeof(tmp)));

  struct epoll_event result[kFDsPerEpoll];
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(kFDsPerEpoll));

  int i;
  for (i = 0; i < kFDsPerEpoll - 1; i++) {
    EXPECT_EQ(result[i].events, EPOLLOUT);
  }
  EXPECT_EQ(result[i].events, EPOLLIN);
  EXPECT_THAT(ReadFd(eventfds[kFDsPerEpoll - 1].get(), &tmp, sizeof(tmp)),
              sizeof(tmp));
  EXPECT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(kFDsPerEpoll));

  for (i = 0; i < kFDsPerEpoll; i++) {
    EXPECT_EQ(result[i].events, EPOLLOUT);
  }
}

TEST(EpollTest, Timeout_NoRandomSave) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN,
                                    kMagicConstant + i));
  }

  constexpr int kTimeoutMs = 200;
  struct timespec begin;
  struct timespec end;
  struct epoll_event result[kFDsPerEpoll];

  {
    const DisableSave ds;  // Timing-related.
    EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &begin), SyscallSucceeds());

    ASSERT_THAT(
        RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, kTimeoutMs),
        SyscallSucceedsWithValue(0));
    EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &end), SyscallSucceeds());
  }

  // Check the lower bound on the timeout.  Checking for an upper bound is
  // fragile because Linux can overrun the timeout due to scheduling delays.
  EXPECT_GT(ms_elapsed(&begin, &end), kTimeoutMs - 1);
}

void* writer(void* arg) {
  int fd = *reinterpret_cast<int*>(arg);
  uint64_t tmp = 1;

  usleep(200000);
  if (WriteFd(fd, &tmp, sizeof(tmp)) != sizeof(tmp)) {
    fprintf(stderr, "writer failed: errno %s\n", strerror(errno));
  }

  return nullptr;
}

TEST(EpollTest, WaitThenUnblock) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN,
                                    kMagicConstant + i));
  }

  // Fire off a thread that will make at least one of the event fds readable.
  pthread_t thread;
  int make_readable = eventfds[0].get();
  ASSERT_THAT(pthread_create(&thread, nullptr, writer, &make_readable),
              SyscallSucceedsWithValue(0));

  struct epoll_event result[kFDsPerEpoll];
  EXPECT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(1));
  EXPECT_THAT(pthread_detach(thread), SyscallSucceeds());
}

void sighandler(int s) {}

void* signaler(void* arg) {
  pthread_t* t = reinterpret_cast<pthread_t*>(arg);
  // Repeatedly send the real-time signal until we are detached, because it's
  // difficult to know exactly when epoll_wait on another thread (which this
  // is intending to interrupt) has started blocking.
  while (1) {
    usleep(200000);
    pthread_kill(*t, SIGRTMIN);
  }
  return nullptr;
}

TEST(EpollTest, UnblockWithSignal) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN,
                                    kMagicConstant + i));
  }

  signal(SIGRTMIN, sighandler);
  // Unblock the real time signals that InitGoogle blocks :(
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGRTMIN);
  ASSERT_THAT(sigprocmask(SIG_UNBLOCK, &unblock, nullptr), SyscallSucceeds());

  pthread_t thread;
  pthread_t cur = pthread_self();
  ASSERT_THAT(pthread_create(&thread, nullptr, signaler, &cur),
              SyscallSucceedsWithValue(0));

  struct epoll_event result[kFDsPerEpoll];
  EXPECT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallFailsWithErrno(EINTR));
  EXPECT_THAT(pthread_cancel(thread), SyscallSucceeds());
  EXPECT_THAT(pthread_detach(thread), SyscallSucceeds());
}

TEST(EpollTest, TimeoutNoFds) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  struct epoll_event result[kFDsPerEpoll];
  EXPECT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, 100),
              SyscallSucceedsWithValue(0));
}

struct addr_ctx {
  int epollfd;
  int eventfd;
};

void* fd_adder(void* arg) {
  struct addr_ctx* actx = reinterpret_cast<struct addr_ctx*>(arg);
  struct epoll_event event;
  event.events = EPOLLIN | EPOLLOUT;
  event.data.u64 = 0xdeadbeeffacefeed;

  usleep(200000);
  if (epoll_ctl(actx->epollfd, EPOLL_CTL_ADD, actx->eventfd, &event) == -1) {
    fprintf(stderr, "epoll_ctl failed: %s\n", strerror(errno));
  }

  return nullptr;
}

TEST(EpollTest, UnblockWithNewFD) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto eventfd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());

  pthread_t thread;
  struct addr_ctx actx = {epollfd.get(), eventfd.get()};
  ASSERT_THAT(pthread_create(&thread, nullptr, fd_adder, &actx),
              SyscallSucceedsWithValue(0));

  struct epoll_event result[kFDsPerEpoll];
  // Wait while no FDs are ready, but after 200ms fd_adder will add a ready FD
  // to epoll which will wake us up.
  EXPECT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(1));
  EXPECT_THAT(pthread_detach(thread), SyscallSucceeds());
  EXPECT_EQ(result[0].data.u64, 0xdeadbeeffacefeed);
}

TEST(EpollTest, Oneshot) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN,
                                    kMagicConstant + i));
  }

  struct epoll_event event;
  event.events = EPOLLOUT | EPOLLONESHOT;
  event.data.u64 = kMagicConstant;
  ASSERT_THAT(
      epoll_ctl(epollfd.get(), EPOLL_CTL_MOD, eventfds[0].get(), &event),
      SyscallSucceeds());

  struct epoll_event result[kFDsPerEpoll];
  // One-shot entry means that the first epoll_wait should succeed.
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(result[0].data.u64, kMagicConstant);

  // One-shot entry means that the second epoll_wait should timeout.
  EXPECT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, 100),
              SyscallSucceedsWithValue(0));
}

TEST(EpollTest, EdgeTriggered_NoRandomSave) {
  // Test edge-triggered entry: make it edge-triggered, first wait should
  // return it, second one should time out, make it writable again, third wait
  // should return it, fourth wait should timeout.
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto eventfd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());
  ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfd.get(),
                                  EPOLLOUT | EPOLLET, kMagicConstant));

  struct epoll_event result[kFDsPerEpoll];

  {
    const DisableSave ds;  // May trigger spurious event.

    // Edge-triggered entry means that the first epoll_wait should return the
    // event.
    ASSERT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, -1),
                SyscallSucceedsWithValue(1));
    EXPECT_EQ(result[0].data.u64, kMagicConstant);

    // Edge-triggered entry means that the second epoll_wait should time out.
    ASSERT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, 100),
                SyscallSucceedsWithValue(0));
  }

  uint64_t tmp = ULLONG_MAX - 1;

  // Make an fd non-writable.
  ASSERT_THAT(WriteFd(eventfd.get(), &tmp, sizeof(tmp)),
              SyscallSucceedsWithValue(sizeof(tmp)));

  // Make the same fd non-writable to trigger a change, which will trigger an
  // edge-triggered event.
  ASSERT_THAT(ReadFd(eventfd.get(), &tmp, sizeof(tmp)),
              SyscallSucceedsWithValue(sizeof(tmp)));

  {
    const DisableSave ds;  // May trigger spurious event.

    // An edge-triggered event should now be returned.
    ASSERT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, -1),
                SyscallSucceedsWithValue(1));
    EXPECT_EQ(result[0].data.u64, kMagicConstant);

    // The edge-triggered event had been consumed above, we don't expect to
    // get it again.
    ASSERT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, 100),
                SyscallSucceedsWithValue(0));
  }
}

TEST(EpollTest, OneshotAndEdgeTriggered) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto eventfd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());
  ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfd.get(),
                                  EPOLLOUT | EPOLLET | EPOLLONESHOT,
                                  kMagicConstant));

  struct epoll_event result[kFDsPerEpoll];
  // First time one shot edge-triggered entry means that epoll_wait should
  // return the event.
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(result[0].data.u64, kMagicConstant);

  // Edge-triggered entry means that the second epoll_wait should time out.
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, 100),
              SyscallSucceedsWithValue(0));

  uint64_t tmp = ULLONG_MAX - 1;
  // Make an fd non-writable.
  ASSERT_THAT(WriteFd(eventfd.get(), &tmp, sizeof(tmp)),
              SyscallSucceedsWithValue(sizeof(tmp)));
  // Make the same fd non-writable to trigger a change, which will not trigger
  // an edge-triggered event because we've also included EPOLLONESHOT.
  ASSERT_THAT(ReadFd(eventfd.get(), &tmp, sizeof(tmp)),
              SyscallSucceedsWithValue(sizeof(tmp)));
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, 100),
              SyscallSucceedsWithValue(0));
}

TEST(EpollTest, CycleOfOneDisallowed) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());

  struct epoll_event event;
  event.events = EPOLLOUT;
  event.data.u64 = kMagicConstant;

  ASSERT_THAT(epoll_ctl(epollfd.get(), EPOLL_CTL_ADD, epollfd.get(), &event),
              SyscallFailsWithErrno(EINVAL));
}

TEST(EpollTest, CycleOfThreeDisallowed) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto epollfd1 = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto epollfd2 = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());

  ASSERT_NO_ERRNO(
      RegisterEpollFD(epollfd.get(), epollfd1.get(), EPOLLIN, kMagicConstant));
  ASSERT_NO_ERRNO(
      RegisterEpollFD(epollfd1.get(), epollfd2.get(), EPOLLIN, kMagicConstant));

  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.u64 = kMagicConstant;
  EXPECT_THAT(epoll_ctl(epollfd2.get(), EPOLL_CTL_ADD, epollfd.get(), &event),
              SyscallFailsWithErrno(ELOOP));
}

TEST(EpollTest, CloseFile) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto eventfd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());
  ASSERT_NO_ERRNO(
      RegisterEpollFD(epollfd.get(), eventfd.get(), EPOLLOUT, kMagicConstant));

  struct epoll_event result[kFDsPerEpoll];
  ASSERT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(result[0].data.u64, kMagicConstant);

  // Close the event fd early.
  eventfd.reset();

  EXPECT_THAT(RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, 100),
              SyscallSucceedsWithValue(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
