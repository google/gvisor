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

// Test fixture for tests that apply to pairs of unbound seqpacket unix sockets.
using UnboundUnixSeqpacketSocketPairTest = SocketPairTest;

TEST_P(UnboundUnixSeqpacketSocketPairTest, SendtoWithoutConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  char data = 'a';
  ASSERT_THAT(sendto(sockets->second_fd(), &data, sizeof(data), 0,
                     sockets->first_addr(), sockets->first_addr_size()),
              SyscallFailsWithErrno(ENOTCONN));
}

TEST_P(UnboundUnixSeqpacketSocketPairTest, SendtoWithoutConnectIgnoresAddr) {
  // FIXME: gVisor tries to find /foo/bar and thus returns ENOENT.
  if (IsRunningOnGvisor()) {
    return;
  }

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  // Even a bogus address is completely ignored.
  constexpr char kPath[] = "/foo/bar";

  // Sanity check that kPath doesn't exist.
  struct stat s;
  ASSERT_THAT(stat(kPath, &s), SyscallFailsWithErrno(ENOENT));

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  char data = 'a';
  ASSERT_THAT(
      sendto(sockets->second_fd(), &data, sizeof(data), 0,
             reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(ENOTCONN));
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, UnboundUnixSeqpacketSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(
            FilesystemUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK}))))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
