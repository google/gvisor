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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of unbound dgram unix sockets.
using UnboundDgramUnixSocketPairTest = SocketPairTest;

TEST_P(UnboundDgramUnixSocketPairTest, BindConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundDgramUnixSocketPairTest, SelfConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->first_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundDgramUnixSocketPairTest, DoubleConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundDgramUnixSocketPairTest, GetRemoteAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addressLength = sockets->first_addr_size();
  struct sockaddr_storage address = {};
  ASSERT_THAT(getpeername(sockets->second_fd(), (struct sockaddr*)(&address),
                          &addressLength),
              SyscallSucceeds());
  EXPECT_EQ(
      0, memcmp(&address, sockets->first_addr(), sockets->first_addr_size()));
}

TEST_P(UnboundDgramUnixSocketPairTest, Sendto) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(sendto(sockets->second_fd(), sent_data, sizeof(sent_data), 0,
                     sockets->first_addr(), sockets->first_addr_size()),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data)];
  ASSERT_THAT(ReadFd(sockets->first_fd(), received_data, sizeof(received_data)),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(received_data)));
}

TEST_P(UnboundDgramUnixSocketPairTest, ZeroWriteAllowed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  char sent_data[3];
  // Send a zero length packet.
  ASSERT_THAT(write(sockets->second_fd(), sent_data, 0),
              SyscallSucceedsWithValue(0));
  // Receive the packet.
  char received_data[sizeof(sent_data)];
  ASSERT_THAT(read(sockets->first_fd(), received_data, sizeof(received_data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(UnboundDgramUnixSocketPairTest, Listen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(listen(sockets->first_fd(), 0), SyscallFailsWithErrno(ENOTSUP));
}

TEST_P(UnboundDgramUnixSocketPairTest, Accept) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(accept(sockets->first_fd(), nullptr, nullptr),
              SyscallFailsWithErrno(ENOTSUP));
}

TEST_P(UnboundDgramUnixSocketPairTest, SendtoWithoutConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  char data = 'a';
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->second_fd(), &data, sizeof(data), 0,
                         sockets->first_addr(), sockets->first_addr_size()),
      SyscallSucceedsWithValue(sizeof(data)));
}

TEST_P(UnboundDgramUnixSocketPairTest, SendtoWithoutConnectPassCreds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  SetSoPassCred(sockets->first_fd());
  char data = 'a';
  ASSERT_THAT(
      RetryEINTR(sendto)(sockets->second_fd(), &data, sizeof(data), 0,
                         sockets->first_addr(), sockets->first_addr_size()),
      SyscallSucceedsWithValue(sizeof(data)));
  ucred creds;
  creds.pid = -1;
  char buf[sizeof(data) + 1];
  ASSERT_NO_FATAL_FAILURE(
      RecvCreds(sockets->first_fd(), &creds, buf, sizeof(buf), sizeof(data)));
  EXPECT_EQ(0, memcmp(&data, buf, sizeof(data)));
  EXPECT_THAT(getpid(), SyscallSucceedsWithValue(creds.pid));
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, UnboundDgramUnixSocketPairTest,
    ::testing::ValuesIn(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(FilesystemUnboundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_DGRAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_DGRAM},
                                   List<int>{0, SOCK_NONBLOCK})))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
