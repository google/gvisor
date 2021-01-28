// Copyright 2020 The gVisor Authors.
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

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// Test ICMP port exhaustion returns EAGAIN.
//
// We disable both random/cooperative S/R for this test as it makes way too many
// syscalls.
TEST(PingSocket, ICMPPortExhaustion_NoRandomSave) {
  DisableSave ds;

  {
    auto s = Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (!s.ok()) {
      ASSERT_EQ(s.error().errno_value(), EACCES);
      GTEST_SKIP();
    }
  }

  const struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_addr =
          {
              .s_addr = htonl(INADDR_LOOPBACK),
          },
  };

  std::vector<FileDescriptor> sockets;
  constexpr int kSockets = 65536;
  for (int i = 0; i < kSockets; i++) {
    auto s =
        ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
    int ret = connect(s.get(), reinterpret_cast<const struct sockaddr*>(&addr),
                      sizeof(addr));
    if (ret == 0) {
      sockets.push_back(std::move(s));
      continue;
    }
    ASSERT_THAT(ret, SyscallFailsWithErrno(EAGAIN));
    break;
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
