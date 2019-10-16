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

#include <poll.h>
#include <stdio.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of connected stream unix sockets.
using StreamUnixSocketPairTest = SocketPairTest;

TEST_P(StreamUnixSocketPairTest, WriteOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(StreamUnixSocketPairTest, ReadOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  char data[10] = {};
  ASSERT_THAT(read(sockets->second_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(StreamUnixSocketPairTest, RecvmsgOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Set timeout so that it will not wait for ever.
  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv,
                         sizeof(tv)),
              SyscallSucceeds());

  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  char received_data[10] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  struct msghdr msg = {};
  msg.msg_flags = -1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(recvmsg(sockets->second_fd(), &msg, MSG_WAITALL),
              SyscallSucceedsWithValue(0));
}

TEST_P(StreamUnixSocketPairTest, ReadOneSideClosedWithUnreadData) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char buf[10] = {};
  ASSERT_THAT(RetryEINTR(write)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(sizeof(buf)));

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallSucceedsWithValue(0));

  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  ASSERT_THAT(RetryEINTR(read)(sockets->second_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, StreamUnixSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(UnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(FilesystemBoundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractBoundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                   List<int>{0, SOCK_NONBLOCK}))))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
