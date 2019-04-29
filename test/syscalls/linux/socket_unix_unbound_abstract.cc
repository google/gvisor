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
#include <sys/un.h>
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of unbound abstract unix sockets.
using UnboundAbstractUnixSocketPairTest = SocketPairTest;

TEST_P(UnboundAbstractUnixSocketPairTest, AddressAfterNull) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr =
      *reinterpret_cast<const struct sockaddr_un*>(sockets->first_addr());
  ASSERT_EQ(addr.sun_path[sizeof(addr.sun_path) - 1], 0);
  SKIP_IF(addr.sun_path[sizeof(addr.sun_path) - 2] != 0 ||
          addr.sun_path[sizeof(addr.sun_path) - 3] != 0);

  addr.sun_path[sizeof(addr.sun_path) - 2] = 'a';

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(),
                   reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
              SyscallSucceeds());
}

TEST_P(UnboundAbstractUnixSocketPairTest, ShortAddressNotExtended) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr =
      *reinterpret_cast<const struct sockaddr_un*>(sockets->first_addr());
  ASSERT_EQ(addr.sun_path[sizeof(addr.sun_path) - 1], 0);

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size() - 1),
              SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(UnboundAbstractUnixSocketPairTest, BindNothing) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  ASSERT_THAT(bind(sockets->first_fd(),
                   reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
              SyscallSucceeds());
}

TEST_P(UnboundAbstractUnixSocketPairTest, GetSockNameFullLength) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  sockaddr_storage addr = {};
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, sockets->first_addr_size());
}

TEST_P(UnboundAbstractUnixSocketPairTest, GetSockNamePartialLength) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size() - 1),
              SyscallSucceeds());

  sockaddr_storage addr = {};
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(getsockname(sockets->first_fd(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addr_len),
              SyscallSucceeds());
  EXPECT_EQ(addr_len, sockets->first_addr_size() - 1);
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, UnboundAbstractUnixSocketPairTest,
    ::testing::ValuesIn(ApplyVec<SocketPairKind>(
        AbstractUnboundUnixDomainSocketPair,
        AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_SEQPACKET,
                                         SOCK_DGRAM},
                               List<int>{0, SOCK_NONBLOCK}))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
