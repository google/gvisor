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

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(ProcNetIfInet6, Format) {
  auto ifinet6 = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/net/if_inet6"));
  EXPECT_THAT(ifinet6,
              ::testing::MatchesRegex(
                  // Ex: "00000000000000000000000000000001 01 80 10 80 lo\n"
                  "^([a-f\\d]{32}( [a-f\\d]{2}){4} +[a-z][a-z\\d]*\\n)+$"));
}

TEST(ProcSysNetIpv4Sack, Exists) {
  EXPECT_THAT(open("/proc/sys/net/ipv4/tcp_sack", O_RDONLY), SyscallSucceeds());
}

TEST(ProcSysNetIpv4Sack, CanReadAndWrite) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_DAC_OVERRIDE))));

  auto const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/sys/net/ipv4/tcp_sack", O_RDWR));

  char buf;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));

  EXPECT_TRUE(buf == '0' || buf == '1') << "unexpected tcp_sack: " << buf;

  char to_write = (buf == '1') ? '0' : '1';
  EXPECT_THAT(PwriteFd(fd.get(), &to_write, sizeof(to_write), 0),
              SyscallSucceedsWithValue(sizeof(to_write)));

  buf = 0;
  EXPECT_THAT(PreadFd(fd.get(), &buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
  EXPECT_EQ(buf, to_write);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
