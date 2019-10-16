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
#include <algorithm>
#include <vector>
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(AllSocketPairTest, BoundSenderAddrCoalesced) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor closer(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  int ri[2] = {0, 0};
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(
      RetryEINTR(recvfrom)(accepted, ri, sizeof(ri), 0,
                           reinterpret_cast<sockaddr*>(&addr), &addr_len),
      SyscallSucceedsWithValue(sizeof(ri)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());

  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, AllSocketPairTest,
    ::testing::ValuesIn(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(FilesystemUnboundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                   List<int>{0, SOCK_NONBLOCK})))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
