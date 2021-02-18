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

#include "test/syscalls/linux/socket_unix_seqpacket.h"

#include <stdio.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(SeqpacketUnixSocketPairTest, WriteOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(SeqpacketUnixSocketPairTest, ReadOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  char data[10] = {};
  ASSERT_THAT(read(sockets->second_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(SeqpacketUnixSocketPairTest, Sendto) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "\0nonexistent";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  constexpr char kStr[] = "abc";
  ASSERT_THAT(sendto(sockets->second_fd(), kStr, 3, 0, (struct sockaddr*)&addr,
                     sizeof(addr)),
              SyscallSucceedsWithValue(3));

  char data[10] = {};
  ASSERT_THAT(read(sockets->first_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(3));
}

TEST_P(SeqpacketUnixSocketPairTest, IncreasedSocketSendBufUnblocksWrites) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int sock = sockets->first_fd();
  int buf_size = 0;
  socklen_t buf_size_len = sizeof(buf_size);
  ASSERT_THAT(getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, &buf_size_len),
              SyscallSucceeds());
  int opts;
  ASSERT_THAT(opts = fcntl(sock, F_GETFL), SyscallSucceeds());
  opts |= O_NONBLOCK;
  ASSERT_THAT(fcntl(sock, F_SETFL, opts), SyscallSucceeds());

  std::vector<char> buf(buf_size / 4);
  // Write till the socket buffer is full.
  while (RetryEINTR(send)(sock, buf.data(), buf.size(), 0) != -1) {
    // Sleep to give linux a chance to move data from the send buffer to the
    // receive buffer.
    absl::SleepFor(absl::Milliseconds(10));  // 10ms.
  }
  // The last error should have been EWOULDBLOCK.
  ASSERT_EQ(errno, EWOULDBLOCK);

  // Now increase the socket send buffer.
  buf_size = buf_size * 2;
  ASSERT_THAT(
      setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)),
      SyscallSucceeds());

  // Skip test if the setsockopt didn't increase the sendbuf. This happens for
  // tests where the socket is a host fd where gVisor does not permit increasing
  // send buffer size.
  int new_buf_size = 0;
  buf_size_len = sizeof(new_buf_size);
  ASSERT_THAT(
      getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &new_buf_size, &buf_size_len),
      SyscallSucceeds());
  if (IsRunningOnGvisor() && (new_buf_size <= buf_size)) {
    GTEST_SKIP() << "Skipping test new send buffer size " << new_buf_size
                 << " is the same as the value before setsockopt, "
                 << " socket is probably a host backed socket." << std ::endl;
  }
  //  send should succeed again.
  ASSERT_THAT(RetryEINTR(send)(sock, buf.data(), buf.size(), 0),
              SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
