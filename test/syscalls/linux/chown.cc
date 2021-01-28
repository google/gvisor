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
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/synchronization/notification.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

ABSL_FLAG(int32_t, scratch_uid1, 65534, "first scratch UID");
ABSL_FLAG(int32_t, scratch_uid2, 65533, "second scratch UID");
ABSL_FLAG(int32_t, scratch_gid, 65534, "first scratch GID");

namespace gvisor {
namespace testing {

namespace {

TEST(ChownTest, FchownBadF) {
  ASSERT_THAT(fchown(-1, 0, 0), SyscallFailsWithErrno(EBADF));
}

TEST(ChownTest, FchownatBadF) {
  ASSERT_THAT(fchownat(-1, "fff", 0, 0, 0), SyscallFailsWithErrno(EBADF));
}

TEST(ChownTest, FchownFileWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  ASSERT_THAT(fchown(fd.get(), geteuid(), getegid()),
              SyscallFailsWithErrno(EBADF));
}

TEST(ChownTest, FchownDirWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));

  ASSERT_THAT(fchown(fd.get(), geteuid(), getegid()),
              SyscallFailsWithErrno(EBADF));
}

TEST(ChownTest, FchownatWithOpath) {
  SKIP_IF(IsRunningWithVFS1());
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  const auto dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_PATH));
  ASSERT_THAT(
      fchownat(dirfd.get(), file.path().c_str(), geteuid(), getegid(), 0),
      SyscallSucceeds());
}

TEST(ChownTest, FchownatEmptyPath) {
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY | O_RDONLY));
  ASSERT_THAT(fchownat(fd.get(), "", 0, 0, 0), SyscallFailsWithErrno(ENOENT));
}

using Chown =
    std::function<PosixError(const std::string&, uid_t owner, gid_t group)>;

class ChownParamTest : public ::testing::TestWithParam<Chown> {};

TEST_P(ChownParamTest, ChownFileSucceeds) {
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_CHOWN))) {
    ASSERT_NO_ERRNO(SetCapability(CAP_CHOWN, false));
  }

  const auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // At least *try* setting to a group other than the EGID.
  gid_t gid;
  EXPECT_THAT(gid = getegid(), SyscallSucceeds());
  int num_groups;
  EXPECT_THAT(num_groups = getgroups(0, nullptr), SyscallSucceeds());
  if (num_groups > 0) {
    std::vector<gid_t> list(num_groups);
    EXPECT_THAT(getgroups(list.size(), list.data()), SyscallSucceeds());
    // Scan the list of groups for a valid gid. Note that if a group is not
    // defined in this local user namespace, then we will see 65534, and the
    // group will not chown below as expected. So only change if we find a
    // valid group in this list.
    for (const gid_t other_gid : list) {
      if (other_gid != 65534) {
        gid = other_gid;
        break;
      }
    }
  }

  EXPECT_NO_ERRNO(GetParam()(file.path(), geteuid(), gid));

  struct stat s = {};
  ASSERT_THAT(stat(file.path().c_str(), &s), SyscallSucceeds());
  EXPECT_EQ(s.st_uid, geteuid());
  EXPECT_EQ(s.st_gid, gid);
}

TEST_P(ChownParamTest, ChownFilePermissionDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0777));
  EXPECT_THAT(chmod(GetAbsoluteTestTmpdir().c_str(), 0777), SyscallSucceeds());

  // Drop privileges and change IDs only in child thread, or else this parent
  // thread won't be able to open some log files after the test ends.
  ScopedThread([&] {
    // Drop privileges.
    if (HaveCapability(CAP_CHOWN).ValueOrDie()) {
      EXPECT_NO_ERRNO(SetCapability(CAP_CHOWN, false));
    }

    // Change EUID and EGID.
    //
    // See note about POSIX below.
    EXPECT_THAT(
        syscall(SYS_setresgid, -1, absl::GetFlag(FLAGS_scratch_gid), -1),
        SyscallSucceeds());
    EXPECT_THAT(
        syscall(SYS_setresuid, -1, absl::GetFlag(FLAGS_scratch_uid1), -1),
        SyscallSucceeds());

    EXPECT_THAT(GetParam()(file.path(), geteuid(), getegid()),
                PosixErrorIs(EPERM, ::testing::ContainsRegex("chown")));
  });
}

TEST_P(ChownParamTest, ChownFileSucceedsAsRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_CHOWN))));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability((CAP_SETUID))));

  const std::string filename = NewTempAbsPath();
  EXPECT_THAT(chmod(GetAbsoluteTestTmpdir().c_str(), 0777), SyscallSucceeds());

  absl::Notification fileCreated, fileChowned;
  // Change UID only in child thread, or else this parent thread won't be able
  // to open some log files after the test ends.
  ScopedThread t([&] {
    // POSIX requires that all threads in a process share the same UIDs, so
    // the NPTL setresuid wrappers use signals to make all threads execute the
    // setresuid syscall. However, we want this thread to have its own set of
    // credentials different from the parent process, so we use the raw
    // syscall.
    EXPECT_THAT(
        syscall(SYS_setresuid, -1, absl::GetFlag(FLAGS_scratch_uid2), -1),
        SyscallSucceeds());

    // Create file and immediately close it.
    FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_CREAT | O_RDWR, 0644));
    fd.reset();  // Close the fd.

    fileCreated.Notify();
    fileChowned.WaitForNotification();

    EXPECT_THAT(open(filename.c_str(), O_RDWR), SyscallFailsWithErrno(EACCES));
    FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_RDONLY));
  });

  fileCreated.WaitForNotification();

  // Set file's owners to someone different.
  EXPECT_NO_ERRNO(GetParam()(filename, absl::GetFlag(FLAGS_scratch_uid1),
                             absl::GetFlag(FLAGS_scratch_gid)));

  struct stat s;
  EXPECT_THAT(stat(filename.c_str(), &s), SyscallSucceeds());
  EXPECT_EQ(s.st_uid, absl::GetFlag(FLAGS_scratch_uid1));
  EXPECT_EQ(s.st_gid, absl::GetFlag(FLAGS_scratch_gid));

  fileChowned.Notify();
}

PosixError errorFromReturn(const std::string& name, int ret) {
  if (ret == -1) {
    return PosixError(errno, absl::StrCat(name, " failed"));
  }
  return NoError();
}

INSTANTIATE_TEST_SUITE_P(
    ChownKinds, ChownParamTest,
    ::testing::Values(
        [](const std::string& path, uid_t owner, gid_t group) -> PosixError {
          int rc = chown(path.c_str(), owner, group);
          MaybeSave();
          return errorFromReturn("chown", rc);
        },
        [](const std::string& path, uid_t owner, gid_t group) -> PosixError {
          int rc = lchown(path.c_str(), owner, group);
          MaybeSave();
          return errorFromReturn("lchown", rc);
        },
        [](const std::string& path, uid_t owner, gid_t group) -> PosixError {
          ASSIGN_OR_RETURN_ERRNO(auto fd, Open(path, O_RDWR));
          int rc = fchown(fd.get(), owner, group);
          MaybeSave();
          return errorFromReturn("fchown", rc);
        },
        [](const std::string& path, uid_t owner, gid_t group) -> PosixError {
          ASSIGN_OR_RETURN_ERRNO(auto fd, Open(path, O_RDWR));
          int rc = fchownat(fd.get(), "", owner, group, AT_EMPTY_PATH);
          MaybeSave();
          return errorFromReturn("fchownat-fd", rc);
        },
        [](const std::string& path, uid_t owner, gid_t group) -> PosixError {
          ASSIGN_OR_RETURN_ERRNO(auto dirfd, Open(std::string(Dirname(path)),
                                                  O_DIRECTORY | O_RDONLY));
          int rc = fchownat(dirfd.get(), std::string(Basename(path)).c_str(),
                            owner, group, 0);
          MaybeSave();
          return errorFromReturn("fchownat-dirfd", rc);
        },
        [](const std::string& path, uid_t owner, gid_t group) -> PosixError {
          ASSIGN_OR_RETURN_ERRNO(auto dirfd, Open(std::string(Dirname(path)),
                                                  O_DIRECTORY | O_PATH));
          int rc = fchownat(dirfd.get(), std::string(Basename(path)).c_str(),
                            owner, group, 0);
          MaybeSave();
          return errorFromReturn("fchownat-opathdirfd", rc);
        }));

}  // namespace

}  // namespace testing
}  // namespace gvisor
