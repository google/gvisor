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

#include "test/util/mount_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(ParseMounts, Mounts) {
  auto entries = ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountsEntriesFrom(
      R"proc(sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
 /mnt tmpfs rw,noexec 0 0
)proc"));
  EXPECT_EQ(entries.size(), 3);
}

TEST(ParseMounts, MountInfo) {
  auto entries = ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntriesFrom(
      R"proc(22 28 0:20 / /sys rw,relatime shared:7 - sysfs sysfs rw
23 28 0:21 / /proc rw,relatime shared:14 - proc proc rw
2007 8844 0:278 / /mnt rw,noexec - tmpfs  rw,mode=123,uid=268601820,gid=5000
)proc"));
  EXPECT_EQ(entries.size(), 3);

  entries = ASSERT_NO_ERRNO_AND_VALUE(ProcSelfMountInfoEntriesFrom(
      R"proc(22 28 0:20 / /sys rw,relatime shared:7 master:20 - sysfs sysfs rw
23 28 0:21 / /proc rw,relatime shared:14 master:20 propagate_from:1 - proc proc rw
2007 8844 0:278 / /mnt rw,noexec - tmpfs  rw,mode=123,uid=268601820,gid=5000
)proc"));
  EXPECT_EQ(entries.size(), 3);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
