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

#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

ABSL_FLAG(std::vector<std::string>, groups, std::vector<std::string>({}),
          "groups the test can use");

constexpr gid_t kNobody = 65534;

namespace gvisor {
namespace testing {

namespace {

constexpr int kDirmodeMask = 07777;
constexpr int kDirmodeSgid = S_ISGID | 0777;
constexpr int kDirmodeNoExec = S_ISGID | 0767;
constexpr int kDirmodeNoSgid = 0777;

// Sets effective GID and returns a Cleanup that restores the original.
PosixErrorOr<Cleanup> Setegid(gid_t egid) {
  gid_t old_gid = getegid();
  if (setegid(egid) < 0) {
    return PosixError(errno, absl::StrFormat("setegid(%d)", egid));
  }
  return Cleanup(
      [old_gid]() { EXPECT_THAT(setegid(old_gid), SyscallSucceeds()); });
}

// Returns a pair of groups that the user is a member of.
PosixErrorOr<std::pair<gid_t, gid_t>> Groups() {
  // Were we explicitly passed GIDs?
  std::vector<std::string> flagged_groups = absl::GetFlag(FLAGS_groups);
  if (flagged_groups.size() >= 2) {
    int group1;
    int group2;
    if (!absl::SimpleAtoi(flagged_groups[0], &group1) ||
        !absl::SimpleAtoi(flagged_groups[1], &group2)) {
      return PosixError(EINVAL, "failed converting group flags to ints");
    }
    return std::pair<gid_t, gid_t>(group1, group2);
  }

  // See whether the user is a member of at least 2 groups.
  std::vector<gid_t> groups(64);
  for (; groups.size() <= NGROUPS_MAX; groups.resize(groups.size() * 2)) {
    int ngroups = getgroups(groups.size(), groups.data());
    if (ngroups < 0 && errno == EINVAL) {
      // Need a larger list.
      continue;
    }
    if (ngroups < 0) {
      return PosixError(errno, absl::StrFormat("getgroups(%d, %p)",
                                               groups.size(), groups.data()));
    }

    if (ngroups < 2) {
      // There aren't enough groups.
      break;
    }

    // TODO(b/181878080): Read /proc/sys/fs/overflowgid once it is supported in
    // gVisor.
    if (groups[0] == kNobody || groups[1] == kNobody) {
      // These groups aren't mapped into our user namespace, so we can't use
      // them.
      break;
    }
    return std::pair<gid_t, gid_t>(groups[0], groups[1]);
  }

  // If we're running in gVisor and are root in the root user namespace, we can
  // set our GID to whatever we want. Try that before giving up.
  //
  // This won't work in native tests, as despite having CAP_SETGID, the gofer
  // process will be sandboxed and unable to change file GIDs.
  if (!IsRunningOnGvisor()) {
    return PosixError(EPERM, "no valid groups for native testing");
  }
  PosixErrorOr<bool> capable = HaveCapability(CAP_SETGID);
  if (!capable.ok()) {
    return capable.error();
  }
  if (!capable.ValueOrDie()) {
    return PosixError(EPERM, "missing CAP_SETGID");
  }
  gid_t gid = getegid();
  auto cleanup1 = Setegid(gid);
  if (!cleanup1.ok()) {
    return cleanup1.error();
  }
  auto cleanup2 = Setegid(kNobody);
  if (!cleanup2.ok()) {
    return cleanup2.error();
  }
  return std::pair<gid_t, gid_t>(gid, kNobody);
}

class SetgidDirTest : public ::testing::Test {
 protected:
  void SetUp() override {
    original_gid_ = getegid();

    SKIP_IF(IsRunningWithVFS1());

    // If we can't find two usable groups, we're in an unsupporting environment.
    // Skip the test.
    PosixErrorOr<std::pair<gid_t, gid_t>> groups = Groups();
    SKIP_IF(!groups.ok());
    groups_ = groups.ValueOrDie();

    auto cleanup = Setegid(groups_.first);
    temp_dir_ = ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  }

  void TearDown() override {
    EXPECT_THAT(setegid(original_gid_), SyscallSucceeds());
  }

  void MkdirAsGid(gid_t gid, const std::string& path, mode_t mode) {
    auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(gid));
    ASSERT_THAT(mkdir(path.c_str(), mode), SyscallSucceeds());
  }

  PosixErrorOr<struct stat> Stat(const std::string& path) {
    struct stat stats;
    if (stat(path.c_str(), &stats) < 0) {
      return PosixError(errno, absl::StrFormat("stat(%s, _)", path));
    }
    return stats;
  }

  PosixErrorOr<struct stat> Stat(const FileDescriptor& fd) {
    struct stat stats;
    if (fstat(fd.get(), &stats) < 0) {
      return PosixError(errno, "fstat(_, _)");
    }
    return stats;
  }

  TempPath temp_dir_;
  std::pair<gid_t, gid_t> groups_;
  gid_t original_gid_;
};

// The control test. Files created with a given GID are owned by that group.
TEST_F(SetgidDirTest, Control) {
  // Set group to G1 and create a directory.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, 0777));

  // Set group to G2, create a file in g1owned, and confirm that G2 owns it.
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups_.second));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(g1owned, "g2owned").c_str(), O_CREAT | O_RDWR, 0777));
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.second);
}

// Setgid directories cause created files to inherit GID.
TEST_F(SetgidDirTest, CreateFile) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeSgid));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeSgid), SyscallSucceeds());

  // Set group to G2, create a file, and confirm that G1 owns it.
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups_.second));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(g1owned, "g2created").c_str(), O_CREAT | O_RDWR, 0666));
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.first);
}

// Setgid directories cause created directories to inherit GID.
TEST_F(SetgidDirTest, CreateDir) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeSgid));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeSgid), SyscallSucceeds());

  // Set group to G2, create a directory, confirm that G1 owns it, and that the
  // setgid bit is enabled.
  auto g2created = JoinPath(g1owned, "g2created");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.second, g2created, 0666));
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(g2created));
  EXPECT_EQ(stats.st_gid, groups_.first);
  EXPECT_EQ(stats.st_mode & S_ISGID, S_ISGID);
}

// Setgid directories with group execution disabled still cause GID inheritance.
TEST_F(SetgidDirTest, NoGroupExec) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeNoExec));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeNoExec), SyscallSucceeds());

  // Set group to G2, create a directory, confirm that G2 owns it, and that the
  // setgid bit is enabled.
  auto g2created = JoinPath(g1owned, "g2created");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.second, g2created, 0666));
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(g2created));
  EXPECT_EQ(stats.st_gid, groups_.first);
  EXPECT_EQ(stats.st_mode & S_ISGID, S_ISGID);
}

// Setting the setgid bit on directories with an existing file does not change
// the file's group.
TEST_F(SetgidDirTest, OldFile) {
  // Set group to G1 and create a directory.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeNoSgid));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeNoSgid), SyscallSucceeds());

  // Set group to G2, create a file, confirm that G2 owns it.
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups_.second));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(g1owned, "g2created").c_str(), O_CREAT | O_RDWR, 0666));
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.second);

  // Enable setgid.
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeSgid), SyscallSucceeds());

  // Confirm that the file's group is still G2.
  stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.second);
}

// Setting the setgid bit on directories with an existing subdirectory does not
// change the subdirectory's group.
TEST_F(SetgidDirTest, OldDir) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeNoSgid));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeNoSgid), SyscallSucceeds());

  // Set group to G2, create a directory, confirm that G2 owns it.
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(Setegid(groups_.second));
  auto g2created = JoinPath(g1owned, "g2created");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.second, g2created, 0666));
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(g2created));
  EXPECT_EQ(stats.st_gid, groups_.second);

  // Enable setgid.
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeSgid), SyscallSucceeds());

  // Confirm that the file's group is still G2.
  stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(g2created));
  EXPECT_EQ(stats.st_gid, groups_.second);
}

// Chowning a file clears the setgid and setuid bits.
TEST_F(SetgidDirTest, ChownFileClears) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeMask));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeMask), SyscallSucceeds());

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(g1owned, "newfile").c_str(), O_CREAT | O_RDWR, 0666));
  ASSERT_THAT(fchmod(fd.get(), 0777 | S_ISUID | S_ISGID), SyscallSucceeds());
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.first);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), S_ISUID | S_ISGID);

  // Change the owning group.
  ASSERT_THAT(fchown(fd.get(), -1, groups_.second), SyscallSucceeds());

  // The setgid and setuid bits should be cleared.
  stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.second);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), 0);
}

// Chowning a file with setgid enabled, but not the group exec bit, does not
// clear the setgid bit. Such files are mandatory locked.
TEST_F(SetgidDirTest, ChownNoExecFileDoesNotClear) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeNoExec));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeNoExec), SyscallSucceeds());

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(g1owned, "newdir").c_str(), O_CREAT | O_RDWR, 0666));
  ASSERT_THAT(fchmod(fd.get(), 0766 | S_ISUID | S_ISGID), SyscallSucceeds());
  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.first);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), S_ISUID | S_ISGID);

  // Change the owning group.
  ASSERT_THAT(fchown(fd.get(), -1, groups_.second), SyscallSucceeds());

  // Only the setuid bit is cleared.
  stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(fd));
  EXPECT_EQ(stats.st_gid, groups_.second);
  EXPECT_EQ(stats.st_mode & (S_ISUID | S_ISGID), S_ISGID);
}

// Chowning a directory with setgid enabled does not clear the bit.
TEST_F(SetgidDirTest, ChownDirDoesNotClear) {
  // Set group to G1, create a directory, and enable setgid.
  auto g1owned = JoinPath(temp_dir_.path(), "g1owned/");
  ASSERT_NO_FATAL_FAILURE(MkdirAsGid(groups_.first, g1owned, kDirmodeMask));
  ASSERT_THAT(chmod(g1owned.c_str(), kDirmodeMask), SyscallSucceeds());

  // Change the owning group.
  ASSERT_THAT(chown(g1owned.c_str(), -1, groups_.second), SyscallSucceeds());

  struct stat stats = ASSERT_NO_ERRNO_AND_VALUE(Stat(g1owned));
  EXPECT_EQ(stats.st_gid, groups_.second);
  EXPECT_EQ(stats.st_mode & kDirmodeMask, kDirmodeMask);
}

struct FileModeTestcase {
  std::string name;
  mode_t mode;
  mode_t result_mode;

  FileModeTestcase(const std::string& name, mode_t mode, mode_t result_mode)
      : name(name), mode(mode), result_mode(result_mode) {}
};

class FileModeTest : public ::testing::TestWithParam<FileModeTestcase> {};

TEST_P(FileModeTest, WriteToFile) {
  SKIP_IF(IsRunningWithVFS1());
  PosixErrorOr<std::pair<gid_t, gid_t>> groups = Groups();
  SKIP_IF(!groups.ok());

  auto cleanup = Setegid(groups.ValueOrDie().first);
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto path = JoinPath(temp_dir.path(), GetParam().name);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.c_str(), O_CREAT | O_RDWR, 0666));
  ASSERT_THAT(fchmod(fd.get(), GetParam().mode), SyscallSucceeds());
  struct stat stats;
  ASSERT_THAT(fstat(fd.get(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_mode & kDirmodeMask, GetParam().mode);

  // For security reasons, writing to the file clears the SUID bit, and clears
  // the SGID bit when the group executable bit is unset (which is not a true
  // SGID binary).
  constexpr char kInput = 'M';
  ASSERT_THAT(write(fd.get(), &kInput, sizeof(kInput)),
              SyscallSucceedsWithValue(sizeof(kInput)));

  ASSERT_THAT(fstat(fd.get(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_mode & kDirmodeMask, GetParam().result_mode);
}

TEST_P(FileModeTest, TruncateFile) {
  SKIP_IF(IsRunningWithVFS1());
  PosixErrorOr<std::pair<gid_t, gid_t>> groups = Groups();
  SKIP_IF(!groups.ok());

  auto cleanup = Setegid(groups.ValueOrDie().first);
  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0777 /* mode */));
  auto path = JoinPath(temp_dir.path(), GetParam().name);
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.c_str(), O_CREAT | O_RDWR, 0666));

  // Write something to the file, as truncating an empty file is a no-op.
  constexpr char c = 'M';
  ASSERT_THAT(write(fd.get(), &c, sizeof(c)),
              SyscallSucceedsWithValue(sizeof(c)));
  ASSERT_THAT(fchmod(fd.get(), GetParam().mode), SyscallSucceeds());

  // For security reasons, truncating the file clears the SUID bit, and clears
  // the SGID bit when the group executable bit is unset (which is not a true
  // SGID binary).
  ASSERT_THAT(ftruncate(fd.get(), 0), SyscallSucceeds());

  struct stat stats;
  ASSERT_THAT(fstat(fd.get(), &stats), SyscallSucceeds());
  EXPECT_EQ(stats.st_mode & kDirmodeMask, GetParam().result_mode);
}

INSTANTIATE_TEST_SUITE_P(
    FileModes, FileModeTest,
    ::testing::ValuesIn<FileModeTestcase>(
        {FileModeTestcase("normal file", 0777, 0777),
         FileModeTestcase("setuid", S_ISUID | 0777, 00777),
         FileModeTestcase("setgid", S_ISGID | 0777, 00777),
         FileModeTestcase("setuid and setgid", S_ISUID | S_ISGID | 0777, 00777),
         FileModeTestcase("setgid without exec", S_ISGID | 0767,
                          S_ISGID | 0767),
         FileModeTestcase("setuid and setgid without exec",
                          S_ISGID | S_ISUID | 0767, S_ISGID | 0767)}));

}  // namespace

}  // namespace testing
}  // namespace gvisor
