// Copyright 2020 The gVisor Authors.
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

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <cstring>

#include "gtest/gtest.h"
#include "absl/synchronization/notification.h"
#include "benchmark/benchmark.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr ssize_t kMessageSize = 1024;

class Message {
 public:
  explicit Message(int byte = 0) : Message(byte, kMessageSize, 0) {}

  explicit Message(int byte, int sz) : Message(byte, sz, 0) {}

  explicit Message(int byte, int sz, int cmsg_sz)
      : buffer_(sz, byte), cmsg_buffer_(cmsg_sz, 0) {
    iov_.iov_base = buffer_.data();
    iov_.iov_len = sz;
    hdr_.msg_iov = &iov_;
    hdr_.msg_iovlen = 1;
    hdr_.msg_control = cmsg_buffer_.data();
    hdr_.msg_controllen = cmsg_sz;
  }

  struct msghdr* header() {
    return &hdr_;
  }

 private:
  std::vector<char> buffer_;
  std::vector<char> cmsg_buffer_;
  struct iovec iov_ = {};
  struct msghdr hdr_ = {};
};

void BM_Recvmsg(benchmark::State& state) {
  int sockets[2];
  TEST_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  FileDescriptor send_socket(sockets[0]), recv_socket(sockets[1]);
  absl::Notification notification;
  Message send_msg('a'), recv_msg;

  ScopedThread t([&send_msg, &send_socket, &notification] {
    while (!notification.HasBeenNotified()) {
      sendmsg(send_socket.get(), send_msg.header(), 0);
    }
  });

  int64_t bytes_received = 0;
  for (auto ignored : state) {
    int n = recvmsg(recv_socket.get(), recv_msg.header(), 0);
    TEST_CHECK(n > 0);
    bytes_received += n;
  }

  notification.Notify();
  recv_socket.reset();

  state.SetBytesProcessed(bytes_received);
}

BENCHMARK(BM_Recvmsg)->UseRealTime();

void BM_Sendmsg(benchmark::State& state) {
  int sockets[2];
  TEST_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  FileDescriptor send_socket(sockets[0]), recv_socket(sockets[1]);
  absl::Notification notification;
  Message send_msg('a'), recv_msg;

  ScopedThread t([&recv_msg, &recv_socket, &notification] {
    while (!notification.HasBeenNotified()) {
      recvmsg(recv_socket.get(), recv_msg.header(), 0);
    }
  });

  int64_t bytes_sent = 0;
  for (auto ignored : state) {
    int n = sendmsg(send_socket.get(), send_msg.header(), 0);
    TEST_CHECK(n > 0);
    bytes_sent += n;
  }

  notification.Notify();
  send_socket.reset();

  state.SetBytesProcessed(bytes_sent);
}

BENCHMARK(BM_Sendmsg)->UseRealTime();

void BM_Recvfrom(benchmark::State& state) {
  int sockets[2];
  TEST_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  FileDescriptor send_socket(sockets[0]), recv_socket(sockets[1]);
  absl::Notification notification;
  char send_buffer[kMessageSize], recv_buffer[kMessageSize];

  ScopedThread t([&send_socket, &send_buffer, &notification] {
    while (!notification.HasBeenNotified()) {
      sendto(send_socket.get(), send_buffer, kMessageSize, 0, nullptr, 0);
    }
  });

  int bytes_received = 0;
  for (auto ignored : state) {
    int n = recvfrom(recv_socket.get(), recv_buffer, kMessageSize, 0, nullptr,
                     nullptr);
    TEST_CHECK(n > 0);
    bytes_received += n;
  }

  notification.Notify();
  recv_socket.reset();

  state.SetBytesProcessed(bytes_received);
}

BENCHMARK(BM_Recvfrom)->UseRealTime();

void BM_Sendto(benchmark::State& state) {
  int sockets[2];
  TEST_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  FileDescriptor send_socket(sockets[0]), recv_socket(sockets[1]);
  absl::Notification notification;
  char send_buffer[kMessageSize], recv_buffer[kMessageSize];

  ScopedThread t([&recv_socket, &recv_buffer, &notification] {
    while (!notification.HasBeenNotified()) {
      recvfrom(recv_socket.get(), recv_buffer, kMessageSize, 0, nullptr,
               nullptr);
    }
  });

  int64_t bytes_sent = 0;
  for (auto ignored : state) {
    int n = sendto(send_socket.get(), send_buffer, kMessageSize, 0, nullptr, 0);
    TEST_CHECK(n > 0);
    bytes_sent += n;
  }

  notification.Notify();
  send_socket.reset();

  state.SetBytesProcessed(bytes_sent);
}

BENCHMARK(BM_Sendto)->UseRealTime();

PosixErrorOr<sockaddr_storage> InetLoopbackAddr(int family) {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  addr.ss_family = family;
  switch (family) {
    case AF_INET:
      reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr.s_addr =
          htonl(INADDR_LOOPBACK);
      break;
    case AF_INET6:
      reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr =
          in6addr_loopback;
      break;
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
  return addr;
}

// BM_RecvmsgWithControlBuf measures the performance of recvmsg when we allocate
// space for control messages. Note that we do not expect to receive any.
void BM_RecvmsgWithControlBuf(benchmark::State& state) {
  auto listen_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr = ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(AF_INET6));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(listen_socket.get(),
                   reinterpret_cast<struct sockaddr*>(&addr), addrlen),
              SyscallSucceeds());

  ASSERT_THAT(listen(listen_socket.get(), SOMAXCONN), SyscallSucceeds());

  // Get the address we're listening on, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(getsockname(listen_socket.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());

  auto send_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(
      RetryEINTR(connect)(send_socket.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());

  // Accept the connection.
  auto recv_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_socket.get(), nullptr, nullptr));

  absl::Notification notification;
  Message send_msg('a');
  // Create a msghdr with a buffer allocated for control messages.
  Message recv_msg(0, kMessageSize, /*cmsg_sz=*/24);

  ScopedThread t([&send_msg, &send_socket, &notification] {
    while (!notification.HasBeenNotified()) {
      sendmsg(send_socket.get(), send_msg.header(), 0);
    }
  });

  int64_t bytes_received = 0;
  for (auto ignored : state) {
    int n = recvmsg(recv_socket.get(), recv_msg.header(), 0);
    TEST_CHECK(n > 0);
    bytes_received += n;
  }

  notification.Notify();
  recv_socket.reset();

  state.SetBytesProcessed(bytes_received);
}

BENCHMARK(BM_RecvmsgWithControlBuf)->UseRealTime();

// BM_SendmsgTCP measures the sendmsg throughput with varying payload sizes.
//
// state.Args[0] indicates whether the underlying socket should be blocking or
// non-blocking w/ 0 indicating non-blocking and 1 to indicate blocking.
// state.Args[1] is the size of the payload to be used per sendmsg call.
void BM_SendmsgTCP(benchmark::State& state) {
  auto listen_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr = ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(AF_INET));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(listen_socket.get(),
                   reinterpret_cast<struct sockaddr*>(&addr), addrlen),
              SyscallSucceeds());

  ASSERT_THAT(listen(listen_socket.get(), SOMAXCONN), SyscallSucceeds());

  // Get the address we're listening on, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(getsockname(listen_socket.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());

  auto send_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(
      RetryEINTR(connect)(send_socket.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());

  // Accept the connection.
  auto recv_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_socket.get(), nullptr, nullptr));

  // Check if we want to run the test w/ a blocking send socket
  // or non-blocking.
  const int blocking = state.range(0);
  if (!blocking) {
    // Set the send FD to O_NONBLOCK.
    int opts;
    ASSERT_THAT(opts = fcntl(send_socket.get(), F_GETFL), SyscallSucceeds());
    opts |= O_NONBLOCK;
    ASSERT_THAT(fcntl(send_socket.get(), F_SETFL, opts), SyscallSucceeds());
  }

  absl::Notification notification;

  // Get the buffer size we should use for this iteration of the test.
  const int buf_size = state.range(1);
  Message send_msg('a', buf_size), recv_msg(0, buf_size);

  ScopedThread t([&recv_msg, &recv_socket, &notification] {
    while (!notification.HasBeenNotified()) {
      TEST_CHECK(recvmsg(recv_socket.get(), recv_msg.header(), 0) >= 0);
    }
  });

  int64_t bytes_sent = 0;
  int ncalls = 0;
  for (auto ignored : state) {
    int sent = 0;
    while (true) {
      struct msghdr hdr = {};
      struct iovec iov = {};
      struct msghdr* snd_header = send_msg.header();
      iov.iov_base = static_cast<char*>(snd_header->msg_iov->iov_base) + sent;
      iov.iov_len = snd_header->msg_iov->iov_len - sent;
      hdr.msg_iov = &iov;
      hdr.msg_iovlen = 1;
      int n = RetryEINTR(sendmsg)(send_socket.get(), &hdr, 0);
      ncalls++;
      if (n > 0) {
        sent += n;
        if (sent == buf_size) {
          break;
        }
        // n can be > 0 but less than requested size. In which case we don't
        // poll.
        continue;
      }
      // Poll the fd for it to become writable.
      struct pollfd poll_fd = {send_socket.get(), POLL_OUT, 0};
      EXPECT_THAT(RetryEINTR(poll)(&poll_fd, 1, 10),
                  SyscallSucceedsWithValue(0));
    }
    bytes_sent += static_cast<int64_t>(sent);
  }

  notification.Notify();
  send_socket.reset();
  state.SetBytesProcessed(bytes_sent);
}

void Args(benchmark::internal::Benchmark* benchmark) {
  for (int blocking = 0; blocking < 2; blocking++) {
    for (int buf_size = 1024; buf_size <= 256 << 20; buf_size *= 2) {
      benchmark->Args({blocking, buf_size});
    }
  }
}

BENCHMARK(BM_SendmsgTCP)->Apply(&Args)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
