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

#include "test/syscalls/linux/socket_unix_non_stream.h"

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cerrno>
#include <cstdint>
#include <functional>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/memory_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

TEST_P(UnixNonStreamSocketPairTest, RecvMsgTooLarge) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int rcvbuf;
  socklen_t length = sizeof(rcvbuf);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVBUF, &rcvbuf, &length),
      SyscallSucceeds());

  // Make the call larger than the receive buffer.
  const int recv_size = 3 * rcvbuf;

  // Write a message that does fit in the receive buffer.
  const int write_size = rcvbuf - kPageSize;

  std::vector<char> write_buf(write_size, 'a');
  const int ret = RetryEINTR(write)(sockets->second_fd(), write_buf.data(),
                                    write_buf.size());
  if (ret < 0 && errno == ENOBUFS) {
    // NOTE(b/116636318): Linux may stall the write for a long time and
    // ultimately return ENOBUFS. Allow this error, since a retry will likely
    // result in the same error.
    return;
  }
  ASSERT_THAT(ret, SyscallSucceeds());

  std::vector<char> recv_buf(recv_size);

  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(sockets->first_fd(), recv_buf.data(),
                                     recv_buf.size(), write_size));

  recv_buf.resize(write_size);
  EXPECT_EQ(recv_buf, write_buf);
}

// Create a region of anonymous memory of size 'size', which is fragmented in
// FileMem.
//
// ptr contains the start address of the region. The returned vector contains
// all of the mappings to be unmapped when done.
PosixErrorOr<std::vector<Mapping>> CreateFragmentedRegion(const int size,
                                                          void** ptr) {
  Mapping region;
  ASSIGN_OR_RETURN_ERRNO(region, Mmap(nullptr, size, PROT_NONE,
                                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

  *ptr = region.ptr();

  // Don't save hundreds of times for all of these mmaps.
  DisableSave ds;

  std::vector<Mapping> pages;

  // Map and commit a single page at a time, mapping and committing an unrelated
  // page between each call to force FileMem fragmentation.
  for (uintptr_t addr = region.addr(); addr < region.endaddr();
       addr += kPageSize) {
    Mapping page;
    ASSIGN_OR_RETURN_ERRNO(
        page,
        Mmap(reinterpret_cast<void*>(addr), kPageSize, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0));
    *reinterpret_cast<volatile char*>(page.ptr()) = 42;

    pages.emplace_back(std::move(page));

    // Unrelated page elsewhere.
    ASSIGN_OR_RETURN_ERRNO(page,
                           Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    *reinterpret_cast<volatile char*>(page.ptr()) = 42;

    pages.emplace_back(std::move(page));
  }

  // The mappings above have taken ownership of the region.
  region.release();

  return std::move(pages);
}

// A contiguous iov that is heavily fragmented in FileMem can still be sent
// successfully. See b/115833655.
TEST_P(UnixNonStreamSocketPairTest, FragmentedSendMsg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  const int buffer_size = UIO_MAXIOV * kPageSize;
  // Extra page for message header overhead.
  const int sndbuf = buffer_size + kPageSize;
  // N.B. setsockopt(SO_SNDBUF) doubles the passed value.
  const int set_sndbuf = sndbuf / 2;

  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &set_sndbuf, sizeof(set_sndbuf)),
              SyscallSucceeds());

  int actual_sndbuf = 0;
  socklen_t length = sizeof(actual_sndbuf);
  ASSERT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &actual_sndbuf, &length),
              SyscallSucceeds());

  if (actual_sndbuf != sndbuf) {
    // Unable to get the sndbuf we want.
    //
    // N.B. At minimum, the socketpair gofer should provide a socket that is
    // already the correct size.
    //
    // TODO(b/35921550): When internal UDS support SO_SNDBUF, we can assert that
    // we always get the right SO_SNDBUF on gVisor.
    GTEST_SKIP() << "SO_SNDBUF = " << actual_sndbuf << ", want " << sndbuf;
  }

  // Create a contiguous region of memory of 2*UIO_MAXIOV*PAGE_SIZE. We'll call
  // sendmsg with a single iov, but the goal is to get the sentry to split this
  // into > UIO_MAXIOV iovs when calling the kernel.
  void* ptr;
  std::vector<Mapping> pages =
      ASSERT_NO_ERRNO_AND_VALUE(CreateFragmentedRegion(buffer_size, &ptr));

  struct iovec iov = {};
  iov.iov_base = ptr;
  iov.iov_len = buffer_size;

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // NOTE(b/116636318,b/115833655): Linux has poor behavior in the presence of
  // physical memory fragmentation. As a result, this may stall for a long time
  // and ultimately return ENOBUFS. Allow this error, since it means that we
  // made it to the host kernel and started the sendmsg.
  EXPECT_THAT(RetryEINTR(sendmsg)(sockets->first_fd(), &msg, 0),
              AnyOf(SyscallSucceedsWithValue(buffer_size),
                    SyscallFailsWithErrno(ENOBUFS)));
}

// A contiguous iov that is heavily fragmented in FileMem can still be received
// into successfully. Regression test for b/115833655.
TEST_P(UnixNonStreamSocketPairTest, FragmentedRecvMsg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  const int buffer_size = UIO_MAXIOV * kPageSize;
  // Extra page for message header overhead.
  const int sndbuf = buffer_size + kPageSize;
  // N.B. setsockopt(SO_SNDBUF) doubles the passed value.
  const int set_sndbuf = sndbuf / 2;

  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &set_sndbuf, sizeof(set_sndbuf)),
              SyscallSucceeds());

  int actual_sndbuf = 0;
  socklen_t length = sizeof(actual_sndbuf);
  ASSERT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &actual_sndbuf, &length),
              SyscallSucceeds());

  if (actual_sndbuf != sndbuf) {
    // Unable to get the sndbuf we want.
    //
    // N.B. At minimum, the socketpair gofer should provide a socket that is
    // already the correct size.
    //
    // TODO(b/35921550): When internal UDS support SO_SNDBUF, we can assert that
    // we always get the right SO_SNDBUF on gVisor.
    GTEST_SKIP() << "SO_SNDBUF = " << actual_sndbuf << ", want " << sndbuf;
  }

  std::vector<char> write_buf(buffer_size, 'a');
  const int ret = RetryEINTR(write)(sockets->first_fd(), write_buf.data(),
                                    write_buf.size());
  if (ret < 0 && errno == ENOBUFS) {
    // NOTE(b/116636318): Linux may stall the write for a long time and
    // ultimately return ENOBUFS. Allow this error, since a retry will likely
    // result in the same error.
    return;
  }
  ASSERT_THAT(ret, SyscallSucceeds());

  // Create a contiguous region of memory of 2*UIO_MAXIOV*PAGE_SIZE. We'll call
  // sendmsg with a single iov, but the goal is to get the sentry to split this
  // into > UIO_MAXIOV iovs when calling the kernel.
  void* ptr;
  std::vector<Mapping> pages =
      ASSERT_NO_ERRNO_AND_VALUE(CreateFragmentedRegion(buffer_size, &ptr));

  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(
      sockets->second_fd(), reinterpret_cast<char*>(ptr), buffer_size));

  EXPECT_EQ(0, memcmp(write_buf.data(), ptr, buffer_size));
}

TEST_P(UnixNonStreamSocketPairTest, SendTimeout) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  const int buf_size = 5 * kPageSize;
  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF, &buf_size,
                         sizeof(buf_size)),
              SyscallSucceeds());
  EXPECT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_RCVBUF, &buf_size,
                         sizeof(buf_size)),
              SyscallSucceeds());

  // The buffer size should be big enough to avoid many iterations in the next
  // loop. Otherwise, this will slow down save tests.
  std::vector<char> buf(kPageSize);
  for (;;) {
    int ret;
    ASSERT_THAT(
        ret = RetryEINTR(send)(sockets->first_fd(), buf.data(), buf.size(), 0),
        ::testing::AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(EAGAIN)));
    if (ret == -1) {
      break;
    }
  }
}

// All MSG_PEEK/MSG_TRUNC combinations, as exercised by the zero-length
// receive tests below.
constexpr int kZeroLengthRecvFlagCombos[] = {0, MSG_PEEK, MSG_TRUNC,
                                             MSG_PEEK | MSG_TRUNC};

// A zero-length receive on a packet socket with a message pending: the
// message's payload is truncated away entirely, so msg_flags reports
// MSG_TRUNC. The message is consumed unless MSG_PEEK is set, and the return
// value is 0 unless MSG_TRUNC requests the full message length.
TEST_P(UnixNonStreamSocketPairTest, ZeroLengthRecvPendingMessage) {
  const struct {
    int flags;
    bool ret_is_msg_size;
    bool consumes;
  } cases[] = {
      {0, /*ret_is_msg_size=*/false, /*consumes=*/true},
      {MSG_PEEK, /*ret_is_msg_size=*/false, /*consumes=*/false},
      {MSG_TRUNC, /*ret_is_msg_size=*/true, /*consumes=*/true},
      {MSG_PEEK | MSG_TRUNC, /*ret_is_msg_size=*/true, /*consumes=*/false},
  };
  char sent_data[3] = {'a', 'b', 'c'};
  for (const auto& c : cases) {
    SCOPED_TRACE(::testing::Message() << "flags=" << c.flags);
    auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
    ASSERT_THAT(
        RetryEINTR(send)(sockets->second_fd(), sent_data, sizeof(sent_data), 0),
        SyscallSucceedsWithValue(sizeof(sent_data)));

    struct msghdr msg = {};
    const ssize_t want_ret = c.ret_is_msg_size ? sizeof(sent_data) : 0;
    ASSERT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg, c.flags),
                SyscallSucceedsWithValue(want_ret));
    EXPECT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);

    char drain[2 * sizeof(sent_data)] = {};
    if (c.consumes) {
      EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), drain, sizeof(drain),
                                   MSG_DONTWAIT),
                  SyscallFailsWithErrno(EAGAIN));
    } else {
      EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), drain, sizeof(drain),
                                   MSG_DONTWAIT),
                  SyscallSucceedsWithValue(sizeof(sent_data)));
      EXPECT_EQ(memcmp(sent_data, drain, sizeof(sent_data)), 0);
    }
  }
}

// A zero-length non-blocking receive on an empty packet socket must fail
// with EAGAIN rather than report an empty message, whatever the combination
// of MSG_PEEK/MSG_TRUNC and control message space. The zero-length
// MSG_PEEK|MSG_DONTWAIT receive with control space is how systemd checks its
// namespace fd storage socket pairs; it treats a 0 return as a malformed
// message.
TEST_P(UnixNonStreamSocketPairTest, ZeroLengthRecvEmptyQueue) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  for (int flags : kZeroLengthRecvFlagCombos) {
    for (bool control_space : {false, true}) {
      SCOPED_TRACE(::testing::Message()
                   << "flags=" << flags << " control_space=" << control_space);
      char control[CMSG_SPACE(sizeof(int))];
      struct msghdr msg = {};
      if (control_space) {
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
      }
      EXPECT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg,
                                      flags | MSG_DONTWAIT | MSG_CMSG_CLOEXEC),
                  SyscallFailsWithErrno(EAGAIN));
    }
  }
}

// A zero-length receive on an empty packet socket whose peer has shut down
// writes: seqpacket sockets are connection-oriented, so the shutdown
// propagates and the receive returns 0 (EOF). Datagram sockets have no
// connection semantics, so they still fail with EAGAIN.
TEST_P(UnixNonStreamSocketPairTest, ZeroLengthRecvPeerShutdown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int type;
  socklen_t length = sizeof(type);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &length),
      SyscallSucceeds());

  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_WR), SyscallSucceeds());

  for (int flags : kZeroLengthRecvFlagCombos) {
    SCOPED_TRACE(::testing::Message() << "flags=" << flags);
    struct msghdr msg = {};
    if (type == SOCK_SEQPACKET) {
      EXPECT_THAT(
          RetryEINTR(recvmsg)(sockets->first_fd(), &msg, flags | MSG_DONTWAIT),
          SyscallSucceedsWithValue(0));
      // EOF, not a truncated message.
      EXPECT_EQ(msg.msg_flags & MSG_TRUNC, 0);
    } else {
      EXPECT_THAT(
          RetryEINTR(recvmsg)(sockets->first_fd(), &msg, flags | MSG_DONTWAIT),
          SyscallFailsWithErrno(EAGAIN));
    }
  }
}

// Shutting down writes fails subsequent sends with EPIPE, and must not
// affect the peer's receive side on datagram sockets: messages sent before
// the shutdown remain readable, and afterwards the peer sees EAGAIN, not
// EOF. On seqpacket sockets, the shutdown propagates: once the queue is
// drained, the peer reads EOF.
TEST_P(UnixNonStreamSocketPairTest, PeerWriteShutdown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int type;
  socklen_t length = sizeof(type);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &length),
      SyscallSucceeds());

  char sent_data[3] = {'a', 'b', 'c'};
  ASSERT_THAT(
      RetryEINTR(send)(sockets->second_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_WR), SyscallSucceeds());

  // Sends after the shutdown fail with EPIPE.
  EXPECT_THAT(RetryEINTR(send)(sockets->second_fd(), sent_data,
                               sizeof(sent_data), MSG_NOSIGNAL),
              SyscallFailsWithErrno(EPIPE));

  // The message sent before the shutdown is still readable.
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                               sizeof(received_data), MSG_DONTWAIT),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  EXPECT_EQ(memcmp(sent_data, received_data, sizeof(sent_data)), 0);

  // With the queue drained, seqpacket sockets see the propagated shutdown
  // (EOF); datagram sockets, which have no connection semantics, do not.
  if (type == SOCK_SEQPACKET) {
    EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                                 sizeof(received_data), MSG_DONTWAIT),
                SyscallSucceedsWithValue(0));
  } else {
    EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), received_data,
                                 sizeof(received_data), MSG_DONTWAIT),
                SyscallFailsWithErrno(EAGAIN));
  }
}

// After both directions are shut down, poll reports POLLHUP. Linux sets
// EPOLLHUP when sk_shutdown == SHUTDOWN_MASK, EPOLLRDHUP|EPOLLIN for the
// read shutdown, and EPOLLOUT since buffer space is available (see
// unix_dgram_poll(), which serves both datagram and seqpacket sockets).
TEST_P(UnixNonStreamSocketPairTest, PollAfterFullShutdown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());

  struct pollfd poll_fd = {sockets->first_fd(), POLLIN | POLLOUT | POLLRDHUP,
                           0};
  ASSERT_THAT(RetryEINTR(poll)(&poll_fd, 1, /*timeout=*/0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(poll_fd.revents, POLLIN | POLLOUT | POLLRDHUP | POLLHUP);
}

constexpr int kBlockedPollTimeoutMs = 3000;

struct BlockedPollResult {
  int ret;
  int16_t revents;
};

// Blocks a poller on fd in a background thread — with an events mask that
// contains no data events, only POLLRDHUP or the implicit POLLHUP/POLLERR
// (events=0) — then runs trigger() and reports how poll returned. A kernel
// that fails to wake hangup-only waiters on shutdown makes poll ride out
// its full timeout and return 0.
BlockedPollResult PollDuringTrigger(int fd, int16_t events,
                                    const std::function<void()>& trigger) {
  BlockedPollResult res = {};
  struct pollfd pfd = {fd, events, 0};
  ScopedThread t([&] {
    res.ret = RetryEINTR(poll)(&pfd, 1, kBlockedPollTimeoutMs);
    res.revents = pfd.revents;
  });
  // Give the poller time to block. If the trigger still wins the race, the
  // test degrades to checking poll's entry-time readiness.
  absl::SleepFor(absl::Milliseconds(300));
  trigger();
  t.Join();
  return res;
}

// A blocked poller interested only in hangup events (events=0; POLLHUP is
// unmaskable) must be woken by a concurrent full shutdown of the socket:
// unix_shutdown() wakes all waiters via sk_state_change(), and the poller
// re-evaluates to POLLHUP.
TEST_P(UnixNonStreamSocketPairTest, ShutdownWakesHangupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int fd = sockets->first_fd();

  BlockedPollResult res = PollDuringTrigger(
      fd, 0, [fd] { ASSERT_THAT(shutdown(fd, SHUT_RDWR), SyscallSucceeds()); });
  EXPECT_EQ(res.ret, 1);
  EXPECT_EQ(res.revents, POLLHUP);
}

// A blocked POLLRDHUP-only poller must likewise be woken by a concurrent
// read shutdown.
TEST_P(UnixNonStreamSocketPairTest, ReadShutdownWakesRdHupOnlyPoller) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  const int fd = sockets->first_fd();

  BlockedPollResult res = PollDuringTrigger(fd, POLLRDHUP, [fd] {
    ASSERT_THAT(shutdown(fd, SHUT_RD), SyscallSucceeds());
  });
  EXPECT_EQ(res.ret, 1);
  EXPECT_EQ(res.revents, POLLRDHUP);
}

// The peer's blocked POLLRDHUP-only poller: a write shutdown propagates to
// the peer's read side on seqpacket sockets, waking the poller; on
// datagram sockets there is no propagation and the poller must ride out
// its timeout undisturbed.
TEST_P(UnixNonStreamSocketPairTest, WriteShutdownPeerRdHupWakeup) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int type;
  socklen_t length = sizeof(type);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &length),
      SyscallSucceeds());

  const int peer = sockets->second_fd();
  BlockedPollResult res = PollDuringTrigger(
      sockets->first_fd(), POLLRDHUP,
      [peer] { ASSERT_THAT(shutdown(peer, SHUT_WR), SyscallSucceeds()); });
  if (type == SOCK_SEQPACKET) {
    EXPECT_EQ(res.ret, 1);
    EXPECT_EQ(res.revents, POLLRDHUP);
  } else {
    EXPECT_EQ(res.ret, 0);
  }
}

}  // namespace testing
}  // namespace gvisor
