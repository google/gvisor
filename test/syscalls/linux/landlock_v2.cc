// Copyright 2026 The gVisor Authors.
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

// Landlock syscall tests (ABI v2).

#include <errno.h>

#include <cstdio>
#include <string>

#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV2Test, ReferRenameOutOfAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 2);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath src =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string from;
  static std::string to;
  from = src.path();
  to = JoinPath(root.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REFER, allowed, LANDLOCK_ACCESS_FS_REFER);
    int rc = rename(from.c_str(), to.c_str());
    _exit(rc == 0 ? kAllowed : (errno == EXDEV ? kDenied : kOther));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV2Test, ReferRenameWithinAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 2);

  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  TempPath src =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(src_dir.path()));
  const std::string allowed = parent.path();
  static std::string from;
  static std::string to;
  from = src.release();
  to = JoinPath(dst_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REFER, allowed, LANDLOCK_ACCESS_FS_REFER);
    _exit(ClassifyFs(rename(from.c_str(), to.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
