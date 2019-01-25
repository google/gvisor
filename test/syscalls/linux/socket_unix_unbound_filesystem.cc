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
#include <sys/un.h>
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of unbound filesystem unix
// sockets.
using UnboundFilesystemUnixSocketPairTest = SocketPairTest;

TEST_P(UnboundFilesystemUnixSocketPairTest, AddressAfterNull) {
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
              SyscallFailsWithErrno(EADDRINUSE));
}

TEST_P(UnboundFilesystemUnixSocketPairTest, GetSockNameLength) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  sockaddr_storage got_addr = {};
  socklen_t got_addr_len = sizeof(got_addr);
  ASSERT_THAT(
      getsockname(sockets->first_fd(),
                  reinterpret_cast<struct sockaddr*>(&got_addr), &got_addr_len),
      SyscallSucceeds());

  sockaddr_un want_addr =
      *reinterpret_cast<const struct sockaddr_un*>(sockets->first_addr());

  EXPECT_EQ(got_addr_len,
            strlen(want_addr.sun_path) + 1 + sizeof(want_addr.sun_family));
}

INSTANTIATE_TEST_CASE_P(
    AllUnixDomainSockets, UnboundFilesystemUnixSocketPairTest,
    ::testing::ValuesIn(ApplyVec<SocketPairKind>(
        FilesystemUnboundUnixDomainSocketPair,
        AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_SEQPACKET,
                                         SOCK_DGRAM},
                               List<int>{0, SOCK_NONBLOCK}))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
