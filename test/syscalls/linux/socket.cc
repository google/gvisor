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

#include <sys/socket.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST(SocketTest, UnixSocketPairProtocol) {
  int socks[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, PF_UNIX, socks),
              SyscallSucceeds());
  close(socks[0]);
  close(socks[1]);
}

TEST(SocketTest, ProtocolUnix) {
  struct {
    int domain, type, protocol;
  } tests[] = {
      {AF_UNIX, SOCK_STREAM, PF_UNIX},
      {AF_UNIX, SOCK_SEQPACKET, PF_UNIX},
      {AF_UNIX, SOCK_DGRAM, PF_UNIX},
  };
  for (int i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    ASSERT_NO_ERRNO_AND_VALUE(
        Socket(tests[i].domain, tests[i].type, tests[i].protocol));
  }
}

TEST(SocketTest, ProtocolInet) {
  struct {
    int domain, type, protocol;
  } tests[] = {
      {AF_INET, SOCK_DGRAM, IPPROTO_UDP},
      {AF_INET, SOCK_STREAM, IPPROTO_TCP},
  };
  for (int i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    ASSERT_NO_ERRNO_AND_VALUE(
        Socket(tests[i].domain, tests[i].type, tests[i].protocol));
  }
}

using SocketOpenTest = ::testing::TestWithParam<int>;

// UDS cannot be opened.
TEST_P(SocketOpenTest, Unix) {
  // FIXME(b/142001530): Open incorrectly succeeds on gVisor.
  SKIP_IF(IsRunningOnGvisor());

  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));

  struct sockaddr_un addr =
      ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(/*abstract=*/false, AF_UNIX));

  ASSERT_THAT(bind(bound.get(), reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceeds());

  EXPECT_THAT(open(addr.sun_path, GetParam()), SyscallFailsWithErrno(ENXIO));
}

INSTANTIATE_TEST_SUITE_P(OpenModes, SocketOpenTest,
                         ::testing::Values(O_RDONLY, O_RDWR));

}  // namespace testing
}  // namespace gvisor
