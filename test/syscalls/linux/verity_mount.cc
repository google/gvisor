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

#include <sys/mount.h>

#include <iomanip>
#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Mount verity file system on an existing gofer mount.
TEST(MountTest, MountExisting) {
  // Verity is implemented in VFS2.
  SKIP_IF(IsRunningWithVFS1());

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Mount a new tmpfs file system.
  auto const tmpfs_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", tmpfs_dir.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());

  // Mount a verity file system on the existing gofer mount.
  auto const verity_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string opts = "lower_path=" + tmpfs_dir.path();
  EXPECT_THAT(mount("", verity_dir.path().c_str(), "verity", 0, opts.c_str()),
              SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
