// Copyright 2019 The gVisor Authors.
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

#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/capability_util.h"

namespace gvisor {
namespace testing {

namespace {

// Fixture for SO_PRIORITY tests.
class SoPriorityTest : public ::testing::TestWithParam<SocketKind> {
 protected:
  void SetUp() override {
    socket_ = ASSERT_NO_ERRNO_AND_VALUE(GetParam().Create());
  }

  int socket_fd() const { return socket_->get(); }

 private:
  std::unique_ptr<FileDescriptor> socket_;
};

TEST_P(SoPriorityTest, SoPriorityDefault) {
  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_PRIORITY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, 0);
}

TEST_P(SoPriorityTest, SetSoPriority) {
  // Skip this test in non-root environment where core.sysctl_allow_so_priority
  // can be false, causing setting SO_PRIORITY to fail.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int v = 3;
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_PRIORITY, &v, sizeof(v)),
              SyscallSucceeds());

  int get = -1;
  socklen_t get_len = sizeof(get);
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_PRIORITY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, v);

  v = 0;
  ASSERT_THAT(setsockopt(socket_fd(), SOL_SOCKET, SO_PRIORITY, &v, sizeof(v)),
              SyscallSucceeds());
  EXPECT_THAT(getsockopt(socket_fd(), SOL_SOCKET, SO_PRIORITY, &get, &get_len),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(get_len, sizeof(get));
  EXPECT_EQ(get, v);
}

INSTANTIATE_TEST_SUITE_P(SoPriorityTest, SoPriorityTest,
                         ::testing::Values(IPv4UDPUnboundSocket(0),
                                           IPv6UDPUnboundSocket(0),
                                           IPv4TCPUnboundSocket(0),
                                           IPv6TCPUnboundSocket(0)));

}  // namespace

}  // namespace testing
}  // namespace gvisor
