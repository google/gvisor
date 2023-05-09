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
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/synchronization/mutex.h"
#include "test/util/epoll_util.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/socket_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int kFDsPerEpoll = 3;
constexpr uint64_t kMagicConstant = 0x0102030405060708;

#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

int test_epoll_pwait2(int fd, struct epoll_event* events, int maxevents,
                      const struct timespec* timeout, const sigset_t* sigset) {
  return syscall(SYS_epoll_pwait2, fd, events, maxevents, timeout, sigset);
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

TEST(EpollTest, Timeout) {
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
  EXPECT_GT(ms_elapsed(begin, end), kTimeoutMs - 1);
}

TEST(EpollTest, EpollPwait2Timeout) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  // 200 milliseconds.
  constexpr int kTimeoutNs = 200000000;
  struct timespec timeout;
  timeout.tv_sec = 0;
  timeout.tv_nsec = 0;
  struct timespec begin;
  struct timespec end;
  struct epoll_event result[kFDsPerEpoll];

  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN,
                                    kMagicConstant + i));
  }

  // Pass valid arguments so that the syscall won't be blocked indefinitely
  // nor return errno EINVAL.
  //
  // The syscall returns immediately when timeout is zero,
  // even if no events are available.
  SKIP_IF(!IsRunningOnGvisor() &&
          test_epoll_pwait2(epollfd.get(), result, kFDsPerEpoll, &timeout,
                            nullptr) < 0 &&
          errno == ENOSYS);

  {
    const DisableSave ds;  // Timing-related.
    EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &begin), SyscallSucceeds());

    timeout.tv_nsec = kTimeoutNs;
    ASSERT_THAT(RetryEINTR(test_epoll_pwait2)(epollfd.get(), result,
                                              kFDsPerEpoll, &timeout, nullptr),
                SyscallSucceedsWithValue(0));
    EXPECT_THAT(clock_gettime(CLOCK_MONOTONIC, &end), SyscallSucceeds());
  }

  // Check the lower bound on the timeout.  Checking for an upper bound is
  // fragile because Linux can overrun the timeout due to scheduling delays.
  EXPECT_GT(ns_elapsed(begin, end), kTimeoutNs - 1);
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

#ifndef ANDROID  // Android does not support pthread_cancel

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

#endif  // ANDROID

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

// NOTE(b/228468030): This test aims to test epoll functionality when 2 epoll
// instances are used to track the same FD using EPOLLONESHOT.
TEST(EpollTest, DoubleEpollOneShot) {
  int sockets[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());
  auto epollfd1 = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  auto epollfd2 = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());

  ASSERT_NO_ERRNO(RegisterEpollFD(epollfd1.get(), sockets[1],
                                  EPOLLIN | EPOLLONESHOT, kMagicConstant));
  ASSERT_NO_ERRNO(RegisterEpollFD(epollfd2.get(), sockets[1],
                                  EPOLLIN | EPOLLONESHOT, kMagicConstant));

  const DisableSave ds;  // May trigger spurious event.

  constexpr char msg1[] = "hello";
  constexpr char msg2[] = "world";
  // For the purpose of this test, msg1 and msg2 should be equal in size.
  ASSERT_EQ(sizeof(msg1), sizeof(msg2));
  const auto msg_size = sizeof(msg1);

  // Server and client here only communicate with `msg_size` sized messages.
  // When client sees msg2, it will shutdown. All other communication is msg1.
  const uint n = 1 << 14;  // Arbitrary to trigger race.
  ScopedThread server([&sockets, &msg1, &msg2]() {
    char tmp[msg_size];
    for (uint i = 0; i < n; ++i) {
      // Read request.
      ASSERT_THAT(ReadFd(sockets[0], &tmp, sizeof(tmp)),
                  SyscallSucceedsWithValue(sizeof(tmp)));
      EXPECT_EQ(strcmp(tmp, msg1), 0);
      // Respond to request.
      if (i < n - 2) {
        ASSERT_EQ(WriteFd(sockets[0], msg1, sizeof(msg1)), sizeof(msg1));
      } else {
        ASSERT_EQ(WriteFd(sockets[0], msg2, sizeof(msg2)), sizeof(msg2));
      }
    }
  });

  // m is used to synchronize reads on sockets[1].
  absl::Mutex m;

  auto clientFn = [&sockets, &msg1, &msg2, &m](FileDescriptor& epollfd) {
    char tmp[msg_size];
    bool rearm = false;
    while (true) {
      if (rearm) {
        // Rearm with EPOLLONESHOT.
        struct epoll_event event;
        event.events = EPOLLIN | EPOLLONESHOT;
        event.data.u64 = kMagicConstant;
        ASSERT_THAT(epoll_ctl(epollfd.get(), EPOLL_CTL_MOD, sockets[1], &event),
                    SyscallSucceeds());
      }

      // Make request.
      {
        absl::MutexLock lock(&m);
        ASSERT_EQ(WriteFd(sockets[1], msg1, sizeof(msg1)), sizeof(msg1));
      }

      // Wait for response.
      struct epoll_event result[kFDsPerEpoll];
      ASSERT_THAT(
          RetryEINTR(epoll_wait)(epollfd.get(), result, kFDsPerEpoll, -1),
          SyscallSucceedsWithValue(1));
      EXPECT_EQ(result[0].data.u64, kMagicConstant);
      rearm = true;

      // Read response.
      {
        absl::MutexLock lock(&m);
        ASSERT_THAT(ReadFd(sockets[1], &tmp, sizeof(tmp)),
                    SyscallSucceedsWithValue(sizeof(tmp)));
      }
      if (strcmp(tmp, msg2) == 0) {
        break;
      }
      EXPECT_EQ(strcmp(tmp, msg1), 0);
    }
  };

  ScopedThread client1([&epollfd1, &clientFn]() { clientFn(epollfd1); });

  ScopedThread client2([&epollfd2, &clientFn]() { clientFn(epollfd2); });

  server.Join();
  client1.Join();
  client2.Join();
}

TEST(EpollTest, EdgeTriggered) {
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

TEST(EpollTest, PipeReaderHupAfterWriterClosed) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  int pipefds[2];
  ASSERT_THAT(pipe(pipefds), SyscallSucceeds());
  FileDescriptor rfd(pipefds[0]);
  FileDescriptor wfd(pipefds[1]);

  ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), rfd.get(), 0, kMagicConstant));
  struct epoll_event result[kFDsPerEpoll];
  // Initially, rfd should not generate any events of interest.
  ASSERT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, 0),
              SyscallSucceedsWithValue(0));
  // Close the write end of the pipe.
  wfd.reset();
  // rfd should now generate EPOLLHUP, which EPOLL_CTL_ADD unconditionally adds
  // to the set of events of interest.
  ASSERT_THAT(epoll_wait(epollfd.get(), result, kFDsPerEpoll, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(result[0].events, EPOLLHUP);
  EXPECT_EQ(result[0].data.u64, kMagicConstant);
}

TEST(EpollTest, DoubleLayerEpoll) {
  int pipefds[2];
  ASSERT_THAT(pipe2(pipefds, O_NONBLOCK), SyscallSucceeds());
  FileDescriptor rfd(pipefds[0]);
  FileDescriptor wfd(pipefds[1]);

  auto epfd1 = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  ASSERT_NO_ERRNO(
      RegisterEpollFD(epfd1.get(), rfd.get(), EPOLLIN | EPOLLHUP, rfd.get()));

  auto epfd2 = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  ASSERT_NO_ERRNO(RegisterEpollFD(epfd2.get(), epfd1.get(), EPOLLIN | EPOLLHUP,
                                  epfd1.get()));

  // Write to wfd and then check if epoll events were generated correctly.
  // Run this loop a couple of times to check if event in epfd1 is cleaned.
  constexpr char data[] = "data";
  for (int i = 0; i < 2; ++i) {
    ScopedThread thread1([&wfd, &data]() {
      sleep(1);
      ASSERT_EQ(WriteFd(wfd.get(), data, sizeof(data)), sizeof(data));
    });

    struct epoll_event ret_events[2];
    ASSERT_THAT(RetryEINTR(epoll_wait)(epfd2.get(), ret_events, 2, 5000),
                SyscallSucceedsWithValue(1));
    ASSERT_EQ(ret_events[0].data.fd, epfd1.get());
    ASSERT_THAT(RetryEINTR(epoll_wait)(epfd1.get(), ret_events, 2, 5000),
                SyscallSucceedsWithValue(1));
    ASSERT_EQ(ret_events[0].data.fd, rfd.get());
    char readBuf[sizeof(data)];
    ASSERT_EQ(ReadFd(rfd.get(), readBuf, sizeof(data)), sizeof(data));
  }
}

TEST(EpollTest, RegularFiles) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());

  struct epoll_event event;
  event.events = EPOLLIN | EPOLLOUT;
  event.data.u64 = kMagicConstant;

  auto path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDONLY));
  EXPECT_THAT(epoll_ctl(epollfd.get(), EPOLL_CTL_ADD, fd.get(), &event),
              SyscallFailsWithErrno(EPERM));
}

// Regression test for b/222369818.
TEST(EpollTest, ReadyMutexCircularity) {
  constexpr int kSignal = SIGUSR1;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, kSignal);
  auto cleanup_sigmask =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_BLOCK, set));
  int sigfd_raw;
  ASSERT_THAT(sigfd_raw = signalfd(-1 /* fd */, &set, SFD_NONBLOCK),
              SyscallSucceeds());
  FileDescriptor sigfd(sigfd_raw);

  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  ASSERT_NO_ERRNO(RegisterEpollFD(epollfd.get(), sigfd.get(), EPOLLIN, 0));

  // The test passes if this does not deadlock.
  constexpr int kIterations = 25000;
  auto pid = getpid();
  auto tid = gettid();
  DisableSave ds;
  ScopedThread sender_thread([&] {
    for (int i = 0; i < kIterations; i++) {
      ASSERT_THAT(tgkill(pid, tid, kSignal), SyscallSucceeds());
    }
  });
  int num_signals = 0;
  signalfd_siginfo info;
  while (true) {
    struct epoll_event ev;
    int ret = RetryEINTR(epoll_wait)(epollfd.get(), &ev, 1, 1000 /* timeout */);
    ASSERT_THAT(ret, SyscallSucceeds());
    if (ret == 0) {
      break;
    }
    ASSERT_THAT(read(sigfd.get(), &info, sizeof(info)),
                SyscallSucceedsWithValue(sizeof(info)));
    num_signals++;
  }
  EXPECT_GT(num_signals, 0);
  sender_thread.Join();
  // epoll_wait() may have timed out before sender_thread finished executing
  // (possible on slower platforms like ptrace), so read from sigfd (which is
  // non-blocking) one more time to potentially dequeue the signal before
  // unmasking it in cleanup_sigmask's destructor.
  read(sigfd.get(), &info, sizeof(info));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
