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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

ABSL_FLAG(int32_t, scratch_uid, 65534, "scratch UID");

namespace gvisor {
namespace testing {

namespace {

// IsSameFile returns true if both filenames have the same device and inode.
bool IsSameFile(const std::string& f1, const std::string& f2) {
  // Use lstat rather than stat, so that symlinks are not followed.
  struct stat stat1 = {};
  EXPECT_THAT(lstat(f1.c_str(), &stat1), SyscallSucceeds());
  struct stat stat2 = {};
  EXPECT_THAT(lstat(f2.c_str(), &stat2), SyscallSucceeds());

  return stat1.st_dev == stat2.st_dev && stat1.st_ino == stat2.st_ino;
}

TEST(LinkTest, CanCreateLinkFile) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname = NewTempAbsPath();

  // Get the initial link count.
  uint64_t initial_link_count =
      ASSERT_NO_ERRNO_AND_VALUE(Links(oldfile.path()));

  EXPECT_THAT(link(oldfile.path().c_str(), newname.c_str()), SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));

  // Link count should be incremented.
  EXPECT_THAT(Links(oldfile.path()),
              IsPosixErrorOkAndHolds(initial_link_count + 1));

  // Delete the link.
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());

  // Link count should be back to initial.
  EXPECT_THAT(Links(oldfile.path()),
              IsPosixErrorOkAndHolds(initial_link_count));
}

TEST(LinkTest, PermissionDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FOWNER)));

  // We are going to switch to user 'nobody', which may not have permissions to
  // navigate to the link directory. Create and open the directory now so we can
  // make this work.
  const std::string parent = NewTempAbsPath();
  ASSERT_THAT(mkdir(parent.c_str(), 0777), SyscallSucceeds());
  const FileDescriptor parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent, O_DIRECTORY | O_RDONLY));

  // Create unwritable file, making it readable not but writable, and thus
  // unsafe to link.
  const std::string unwritable_base = "unwritable";
  const std::string unwritable = JoinPath(parent, unwritable_base);
  const FileDescriptor unwritable_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(unwritable, O_CREAT | O_RDWR, 0400));

  // Create the same file with setuid bit. It should be linkable.
  const std::string setuid_base = "setuid";
  const std::string setuid = JoinPath(parent, setuid_base);
  const FileDescriptor setuid_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(setuid, O_CREAT | O_RDWR, 0400));

  const std::string newname = NewTempAbsPath();

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting this
  // test. Otherwise, the files are created by root (UID before the test), but
  // cannot be opened by the `uid` set below after the test. After calling
  // setuid(non-zero-UID), there is no way to get root privileges back.
  ScopedThread([&] {
    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. POSIX threads, however, require that all
    // threads have the same UIDs, so using the setuid wrapper sets all threads'
    // real UID.
    // Also drops capabilities.
    EXPECT_THAT(syscall(SYS_setuid, absl::GetFlag(FLAGS_scratch_uid)),
                SyscallSucceeds());

    EXPECT_THAT(linkat(parent_fd.get(), unwritable_base.c_str(), AT_FDCWD,
                       newname.c_str(), 0),
                SyscallFailsWithErrno(EPERM));

    if (!IsRunningWithVFS1()) {
      EXPECT_THAT(linkat(parent_fd.get(), setuid_base.c_str(), AT_FDCWD,
                         newname.c_str(), 0),
                  SyscallFailsWithErrno(EPERM));
    }
  });
}

TEST(LinkTest, CannotLinkDirectory) {
  auto olddir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string newdir = NewTempAbsPath();

  EXPECT_THAT(link(olddir.path().c_str(), newdir.c_str()),
              SyscallFailsWithErrno(EPERM));

  EXPECT_THAT(rmdir(olddir.path().c_str()), SyscallSucceeds());
}

TEST(LinkTest, CannotLinkWithSlash) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  // Put a final "/" on newname.
  const std::string newname = absl::StrCat(NewTempAbsPath(), "/");

  EXPECT_THAT(link(oldfile.path().c_str(), newname.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, OldnameIsEmpty) {
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(link("", newname.c_str()), SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, OldnameDoesNotExist) {
  const std::string oldname = NewTempAbsPath();
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(link("", newname.c_str()), SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, NewnameCannotExist) {
  const std::string newname =
      JoinPath(GetAbsoluteTestTmpdir(), "thisdoesnotexist", "foo");
  EXPECT_THAT(link("/thisdoesnotmatter", newname.c_str()),
              SyscallFailsWithErrno(ENOENT));
}

TEST(LinkTest, WithOldDirFD) {
  const std::string oldname_parent = NewTempAbsPath();
  const std::string oldname_base = "child";
  const std::string oldname = JoinPath(oldname_parent, oldname_base);
  const std::string newname = NewTempAbsPath();

  // Create oldname_parent directory, and get an FD.
  ASSERT_THAT(mkdir(oldname_parent.c_str(), 0777), SyscallSucceeds());
  const FileDescriptor oldname_parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(oldname_parent, O_DIRECTORY | O_RDONLY));

  // Create oldname file.
  const FileDescriptor oldname_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(oldname, O_CREAT | O_RDWR, 0666));

  // Link oldname to newname, using oldname_parent_fd.
  EXPECT_THAT(linkat(oldname_parent_fd.get(), oldname_base.c_str(), AT_FDCWD,
                     newname.c_str(), 0),
              SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldname, newname));

  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(oldname.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(oldname_parent.c_str()), SyscallSucceeds());
}

TEST(LinkTest, BogusFlags) {
  ASSERT_THAT(linkat(1, "foo", 2, "bar", 3), SyscallFailsWithErrno(EINVAL));
}

TEST(LinkTest, WithNewDirFD) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname_parent = NewTempAbsPath();
  const std::string newname_base = "child";
  const std::string newname = JoinPath(newname_parent, newname_base);

  // Create newname_parent directory, and get an FD.
  EXPECT_THAT(mkdir(newname_parent.c_str(), 0777), SyscallSucceeds());
  const FileDescriptor newname_parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(newname_parent, O_DIRECTORY | O_RDONLY));

  // Link newname to oldfile, using newname_parent_fd.
  EXPECT_THAT(linkat(AT_FDCWD, oldfile.path().c_str(), newname_parent_fd.get(),
                     newname.c_str(), 0),
              SyscallSucceeds());

  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));

  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
  EXPECT_THAT(rmdir(newname_parent.c_str()), SyscallSucceeds());
}

TEST(LinkTest, RelPathsWithNonDirFDs) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Create a file that will be passed as the directory fd for old/new names.
  const std::string filename = NewTempAbsPath();
  const FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_CREAT | O_RDWR, 0666));

  // Using file_fd as olddirfd will fail.
  EXPECT_THAT(linkat(file_fd.get(), "foo", AT_FDCWD, "bar", 0),
              SyscallFailsWithErrno(ENOTDIR));

  // Using file_fd as newdirfd will fail.
  EXPECT_THAT(linkat(AT_FDCWD, oldfile.path().c_str(), file_fd.get(), "bar", 0),
              SyscallFailsWithErrno(ENOTDIR));
}

TEST(LinkTest, AbsPathsWithNonDirFDs) {
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string newname = NewTempAbsPath();

  // Create a file that will be passed as the directory fd for old/new names.
  const std::string filename = NewTempAbsPath();
  const FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_CREAT | O_RDWR, 0666));

  // Using file_fd as the dirfds is OK as long as paths are absolute.
  EXPECT_THAT(linkat(file_fd.get(), oldfile.path().c_str(), file_fd.get(),
                     newname.c_str(), 0),
              SyscallSucceeds());
}

TEST(LinkTest, LinkDoesNotFollowSymlinks) {
  // Create oldfile, and oldsymlink which points to it.
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string oldsymlink = NewTempAbsPath();
  EXPECT_THAT(symlink(oldfile.path().c_str(), oldsymlink.c_str()),
              SyscallSucceeds());

  // Now hard link newname to oldsymlink.
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(link(oldsymlink.c_str(), newname.c_str()), SyscallSucceeds());

  // The link should not have resolved the symlink, so newname and oldsymlink
  // are the same.
  EXPECT_TRUE(IsSameFile(oldsymlink, newname));
  EXPECT_FALSE(IsSameFile(oldfile.path(), newname));

  EXPECT_THAT(unlink(oldsymlink.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(LinkTest, LinkatDoesNotFollowSymlinkByDefault) {
  // Create oldfile, and oldsymlink which points to it.
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string oldsymlink = NewTempAbsPath();
  EXPECT_THAT(symlink(oldfile.path().c_str(), oldsymlink.c_str()),
              SyscallSucceeds());

  // Now hard link newname to oldsymlink.
  const std::string newname = NewTempAbsPath();
  EXPECT_THAT(
      linkat(AT_FDCWD, oldsymlink.c_str(), AT_FDCWD, newname.c_str(), 0),
      SyscallSucceeds());

  // The link should not have resolved the symlink, so newname and oldsymlink
  // are the same.
  EXPECT_TRUE(IsSameFile(oldsymlink, newname));
  EXPECT_FALSE(IsSameFile(oldfile.path(), newname));

  EXPECT_THAT(unlink(oldsymlink.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

TEST(LinkTest, LinkatWithSymlinkFollow) {
  // Create oldfile, and oldsymlink which points to it.
  auto oldfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const std::string oldsymlink = NewTempAbsPath();
  ASSERT_THAT(symlink(oldfile.path().c_str(), oldsymlink.c_str()),
              SyscallSucceeds());

  // Now hard link newname to oldsymlink, and pass AT_SYMLINK_FOLLOW flag.
  const std::string newname = NewTempAbsPath();
  ASSERT_THAT(linkat(AT_FDCWD, oldsymlink.c_str(), AT_FDCWD, newname.c_str(),
                     AT_SYMLINK_FOLLOW),
              SyscallSucceeds());

  // The link should have resolved the symlink, so oldfile and newname are the
  // same.
  EXPECT_TRUE(IsSameFile(oldfile.path(), newname));
  EXPECT_FALSE(IsSameFile(oldsymlink, newname));

  EXPECT_THAT(unlink(oldsymlink.c_str()), SyscallSucceeds());
  EXPECT_THAT(unlink(newname.c_str()), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
