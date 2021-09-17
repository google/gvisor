// Copyright 2021 The gVisor Authors.
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

#include <net/if.h>
#include <netinet/if_ether.h>

#include <limits>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::Combine;
using ::testing::Values;

class PacketSocketTest : public ::testing::TestWithParam<std::tuple<int, int>> {
 protected:
  void SetUp() override {
    if (!ASSERT_NO_ERRNO_AND_VALUE(HavePacketSocketCapability())) {
      const auto [type, protocol] = GetParam();
      ASSERT_THAT(socket(AF_PACKET, type, htons(protocol)),
                  SyscallFailsWithErrno(EPERM));
      GTEST_SKIP() << "Missing packet socket capability";
    }
  }
};

TEST_P(PacketSocketTest, Create) {
  const auto [type, protocol] = GetParam();
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, type, htons(protocol)));
  EXPECT_GE(fd.get(), 0);
}

INSTANTIATE_TEST_SUITE_P(AllPacketSocketTests, PacketSocketTest,
                         Combine(Values(SOCK_DGRAM, SOCK_RAW),
                                 Values(0, 1, 255, ETH_P_IP, ETH_P_IPV6,
                                        std::numeric_limits<uint16_t>::max())));

}  // namespace

}  // namespace testing
}  // namespace gvisor
