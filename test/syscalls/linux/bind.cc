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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(AllSocketPairTest, Bind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, BindTooLong) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  // first_addr is a sockaddr_storage being used as a sockaddr_un. Use the full
  // length which is longer than expected for a Unix socket.
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sizeof(sockaddr_storage)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, DoubleBindSocket) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  EXPECT_THAT(
      bind(sockets->first_fd(), sockets->first_addr(),
           sockets->first_addr_size()),
      // Linux 4.09 returns EINVAL here, but some time before 4.19 it switched
      // to EADDRINUSE.
      AnyOf(SyscallFailsWithErrno(EADDRINUSE), SyscallFailsWithErrno(EINVAL)));
}

TEST_P(AllSocketPairTest, GetLocalAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  socklen_t addressLength = sockets->first_addr_size();
  struct sockaddr_storage address = {};
  ASSERT_THAT(getsockname(sockets->first_fd(), (struct sockaddr*)(&address),
                          &addressLength),
              SyscallSucceeds());
  EXPECT_EQ(
      0, memcmp(&address, sockets->first_addr(), sockets->first_addr_size()));
}

TEST_P(AllSocketPairTest, GetLocalAddrWithoutBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  socklen_t addressLength = sockets->first_addr_size();
  struct sockaddr_storage received_address = {};
  ASSERT_THAT(
      getsockname(sockets->first_fd(), (struct sockaddr*)(&received_address),
                  &addressLength),
      SyscallSucceeds());
  struct sockaddr_storage want_address = {};
  want_address.ss_family = sockets->first_addr()->sa_family;
  EXPECT_EQ(0, memcmp(&received_address, &want_address, addressLength));
}

TEST_P(AllSocketPairTest, GetRemoteAddressWithoutConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  socklen_t addressLength = sockets->first_addr_size();
  struct sockaddr_storage address = {};
  ASSERT_THAT(getpeername(sockets->second_fd(), (struct sockaddr*)(&address),
                          &addressLength),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(AllSocketPairTest, DoubleBindAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  EXPECT_THAT(bind(sockets->second_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(AllSocketPairTest, Unbind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());

  // Filesystem Unix sockets do not release their address when closed.
  if (sockets->first_addr()->sa_data[0] != 0) {
    ASSERT_THAT(bind(sockets->second_fd(), sockets->first_addr(),
                     sockets->first_addr_size()),
                SyscallFailsWithErrno(EADDRINUSE));
    return;
  }

  ASSERT_THAT(bind(sockets->second_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(close(sockets->release_second_fd()), SyscallSucceeds());
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, AllSocketPairTest,
    ::testing::ValuesIn(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(
            FilesystemUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_DGRAM,
                                             SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_DGRAM,
                                             SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
