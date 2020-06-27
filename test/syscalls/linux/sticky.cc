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

#include <fcntl.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

ABSL_FLAG(int32_t, scratch_uid, 65534, "first scratch UID");
ABSL_FLAG(int32_t, scratch_gid, 65534, "first scratch GID");

namespace gvisor {
namespace testing {

namespace {

TEST(StickyTest, StickyBitPermDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(chmod(parent.path().c_str(), 0777 | S_ISVTX), SyscallSucceeds());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(parent.path(), "some content", 0755));
  const TempPath dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirWith(parent.path(), 0755));
  const TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(parent.path(), file.path()));

  // Drop privileges and change IDs only in child thread, or else this parent
  // thread won't be able to open some log files after the test ends.
  ScopedThread([&] {
    // Drop privileges.
    if (HaveCapability(CAP_FOWNER).ValueOrDie()) {
      EXPECT_NO_ERRNO(SetCapability(CAP_FOWNER, false));
    }

    // Change EUID and EGID.
    EXPECT_THAT(
        syscall(SYS_setresgid, -1, absl::GetFlag(FLAGS_scratch_gid), -1),
        SyscallSucceeds());
    EXPECT_THAT(
        syscall(SYS_setresuid, -1, absl::GetFlag(FLAGS_scratch_uid), -1),
        SyscallSucceeds());

    std::string new_path = NewTempAbsPath();
    EXPECT_THAT(rename(file.path().c_str(), new_path.c_str()),
                SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(unlink(file.path().c_str()), SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(rmdir(dir.path().c_str()), SyscallFailsWithErrno(EPERM));
    EXPECT_THAT(unlink(link.path().c_str()), SyscallFailsWithErrno(EPERM));
  });
}

TEST(StickyTest, StickyBitSameUID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(chmod(parent.path().c_str(), 0777 | S_ISVTX), SyscallSucceeds());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(parent.path(), "some content", 0755));
  const TempPath dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirWith(parent.path(), 0755));
  const TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(parent.path(), file.path()));

  // Drop privileges and change IDs only in child thread, or else this parent
  // thread won't be able to open some log files after the test ends.
  ScopedThread([&] {
    // Drop privileges.
    if (HaveCapability(CAP_FOWNER).ValueOrDie()) {
      EXPECT_NO_ERRNO(SetCapability(CAP_FOWNER, false));
    }

    // Change EGID.
    EXPECT_THAT(
        syscall(SYS_setresgid, -1, absl::GetFlag(FLAGS_scratch_gid), -1),
        SyscallSucceeds());

    // We still have the same EUID.
    std::string new_path = NewTempAbsPath();
    EXPECT_THAT(rename(file.path().c_str(), new_path.c_str()),
                SyscallSucceeds());
    EXPECT_THAT(unlink(new_path.c_str()), SyscallSucceeds());
    EXPECT_THAT(rmdir(dir.path().c_str()), SyscallSucceeds());
    EXPECT_THAT(unlink(link.path().c_str()), SyscallSucceeds());
  });
}

TEST(StickyTest, StickyBitCapFOWNER) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(chmod(parent.path().c_str(), 0777 | S_ISVTX), SyscallSucceeds());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(parent.path(), "some content", 0755));
  const TempPath dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirWith(parent.path(), 0755));
  const TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(parent.path(), file.path()));

  // Drop privileges and change IDs only in child thread, or else this parent
  // thread won't be able to open some log files after the test ends.
  ScopedThread([&] {
    // Set PR_SET_KEEPCAPS.
    EXPECT_THAT(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), SyscallSucceeds());

    // Change EUID and EGID.
    EXPECT_THAT(
        syscall(SYS_setresgid, -1, absl::GetFlag(FLAGS_scratch_gid), -1),
        SyscallSucceeds());
    EXPECT_THAT(
        syscall(SYS_setresuid, -1, absl::GetFlag(FLAGS_scratch_uid), -1),
        SyscallSucceeds());

    EXPECT_NO_ERRNO(SetCapability(CAP_FOWNER, true));
    std::string new_path = NewTempAbsPath();
    EXPECT_THAT(rename(file.path().c_str(), new_path.c_str()),
                SyscallSucceeds());
    EXPECT_THAT(unlink(new_path.c_str()), SyscallSucceeds());
    EXPECT_THAT(rmdir(dir.path().c_str()), SyscallSucceeds());
    EXPECT_THAT(unlink(link.path().c_str()), SyscallSucceeds());
  });
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
