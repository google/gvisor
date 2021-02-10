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

#include "test/syscalls/linux/socket_unix_dgram.h"

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

TEST_P(DgramUnixSocketPairTest, WriteOneSideClosed) {
  // FIXME(b/35925052): gVisor datagram sockets return EPIPE instead of
  // ECONNREFUSED.
  SKIP_IF(IsRunningOnGvisor());

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(DgramUnixSocketPairTest, IncreasedSocketSendBufUnblocksWrites) {
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

  // The send should succeed again.
  ASSERT_THAT(RetryEINTR(send)(sock, buf.data(), buf.size(), 0),
              SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
