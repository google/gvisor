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

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/openat2.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

int openat2(int dirfd, const std::string& path, const void* how, size_t size) {
  return syscall(SYS_openat2, dirfd, path.c_str(), how, size);
}

class Openat2Test : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!IsRunningOnGvisor()) {
      // openat2(2) was added in Linux 5.6.
      auto kernel = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
      SKIP_IF(kernel.major < 5 || (kernel.major == 5 && kernel.minor < 6));
    }

    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    dirfd_ =
        ASSERT_NO_ERRNO_AND_VALUE(Open(dir_.path(), O_RDONLY | O_DIRECTORY));
  }

  TempPath dir_;
  FileDescriptor dirfd_;
};

// Basic openat2(2) behavior, mirroring plain openat(2).

TEST_F(Openat2Test, Basic) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir_.path(), "hello", 0644));
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(dirfd_.get(), std::string(Basename(file.path())), O_RDONLY));

  char buf[16] = {};
  ASSERT_THAT(read(fd.get(), buf, sizeof(buf) - 1),
              SyscallSucceedsWithValue(5));
  EXPECT_STREQ(buf, "hello");
}

TEST_F(Openat2Test, AbsolutePath) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  EXPECT_NO_ERRNO(OpenAt2(AT_FDCWD, file.path(), O_RDONLY));
}

TEST_F(Openat2Test, Create) {
  const std::string path = JoinPath(dir_.path(), "created");
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), "created", O_WRONLY | O_CREAT, 0644));

  EXPECT_THAT(unlink(path.c_str()), SyscallSucceeds());
}

TEST_F(Openat2Test, Nonexistent) {
  EXPECT_THAT(OpenAt2(dirfd_.get(), "nonexistent", O_RDONLY),
              PosixErrorIs(ENOENT));
}

TEST_F(Openat2Test, Directory) {
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), ".", O_RDONLY | O_DIRECTORY));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  EXPECT_THAT(OpenAt2(dirfd_.get(), std::string(Basename(file.path())),
                      O_RDONLY | O_DIRECTORY),
              PosixErrorIs(ENOTDIR));
}

TEST_F(Openat2Test, NoFollowSymlink) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  auto link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir_.path(), file.path()));
  const std::string name = std::string(Basename(link.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), name, O_RDONLY));
  EXPECT_THAT(OpenAt2(dirfd_.get(), name, O_RDONLY | O_NOFOLLOW),
              PosixErrorIs(ELOOP));
}

TEST_F(Openat2Test, OPath) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  EXPECT_NO_ERRNO(
      OpenAt2(dirfd_.get(), std::string(Basename(file.path())), O_PATH));
}

// struct open_how copy-in.

TEST_F(Openat2Test, SizeTooSmall) {
  struct open_how how = {};
  how.flags = O_RDONLY;
  EXPECT_THAT(openat2(dirfd_.get(), ".", &how, 20),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(openat2(dirfd_.get(), ".", &how, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(Openat2Test, SizeTooBig) {
  struct open_how how = {};
  how.flags = O_RDONLY;
  EXPECT_THAT(openat2(dirfd_.get(), ".", &how, getpagesize() + 1),
              SyscallFailsWithErrno(E2BIG));
}

TEST_F(Openat2Test, SizeExtendedZeroed) {
  // A larger struct whose unknown trailing fields are zero is accepted
  struct {
    struct open_how how;
    uint64_t extra;
  } buf = {};
  buf.how.flags = O_RDONLY;

  const int fd = openat2(dirfd_.get(), ".", &buf, sizeof(buf));
  ASSERT_THAT(fd, SyscallSucceeds());
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_F(Openat2Test, SizeExtendedNonZero) {
  // A non-zero unknown field means userspace is asking for a feature this
  // kernel doesn't implement.
  struct {
    struct open_how how;
    uint64_t extra;
  } buf = {};
  buf.how.flags = O_RDONLY;
  buf.extra = 1;

  EXPECT_THAT(openat2(dirfd_.get(), ".", &buf, sizeof(buf)),
              SyscallFailsWithErrno(E2BIG));
}

TEST_F(Openat2Test, BadHowPointer) {
  EXPECT_THAT(openat2(dirfd_.get(), ".", nullptr, sizeof(struct open_how)),
              SyscallFailsWithErrno(EFAULT));
}

// Argument validation. Unlike openat(2), openat2(2) rejects unknown or
// contradictory arguments.

TEST_F(Openat2Test, InvalidOpenFlag) {
  EXPECT_THAT(OpenAt2(dirfd_.get(), ".", O_RDONLY | (1 << 30)),
              PosixErrorIs(EINVAL));
}

TEST_F(Openat2Test, InvalidResolveFlag) {
  EXPECT_THAT(OpenAt2(dirfd_.get(), ".", O_RDONLY, 0, 1ULL << 20),
              PosixErrorIs(EINVAL));
}

TEST_F(Openat2Test, UnsupportedResolveFlags) {
  // gVisor-specific test that unsupported flags are rejected.
  SKIP_IF(!IsRunningOnGvisor());

  for (const uint64_t resolve : {RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS,
                                 RESOLVE_NO_SYMLINKS, RESOLVE_IN_ROOT}) {
    EXPECT_THAT(OpenAt2(dirfd_.get(), ".", O_RDONLY, 0, resolve),
                PosixErrorIs(EINVAL))
        << "resolve=" << resolve;
  }
}

TEST_F(Openat2Test, DirectoryWithCreate) {
  EXPECT_THAT(
      OpenAt2(dirfd_.get(), "newdir", O_WRONLY | O_CREAT | O_DIRECTORY, 0644),
      PosixErrorIs(EINVAL));
}

TEST_F(Openat2Test, OPathWithInvalidFlags) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string name = std::string(Basename(file.path()));

  // O_PATH may only be combined with O_DIRECTORY, O_NOFOLLOW and O_CLOEXEC.
  EXPECT_THAT(OpenAt2(dirfd_.get(), name, O_PATH | O_RDWR),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(OpenAt2(dirfd_.get(), name, O_PATH | O_TRUNC),
              PosixErrorIs(EINVAL));
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), name, O_PATH | O_NOFOLLOW | O_CLOEXEC));
}

TEST_F(Openat2Test, ModeWithoutCreate) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  EXPECT_THAT(
      OpenAt2(dirfd_.get(), std::string(Basename(file.path())), O_RDONLY, 0644),
      PosixErrorIs(EINVAL));
}

TEST_F(Openat2Test, InvalidModeBits) {
  EXPECT_THAT(OpenAt2(dirfd_.get(), "created", O_WRONLY | O_CREAT, 010000),
              PosixErrorIs(EINVAL));
}

// RESOLVE_BENEATH.

TEST_F(Openat2Test, BeneathBasic) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), std::string(Basename(file.path())),
                          O_RDONLY, 0, RESOLVE_BENEATH));
}

TEST_F(Openat2Test, BeneathSubdir) {
  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sub.path()));
  const std::string path =
      JoinPath(Basename(sub.path()), Basename(file.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), path, O_RDONLY, 0, RESOLVE_BENEATH));
}

TEST_F(Openat2Test, BeneathAbsolutePath) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  // Absolute paths escape the dirfd by definition, even when they name a file
  // inside it.
  EXPECT_THAT(OpenAt2(dirfd_.get(), file.path(), O_RDONLY, 0, RESOLVE_BENEATH),
              PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, BeneathDotDot) {
  EXPECT_THAT(
      OpenAt2(dirfd_.get(), "..", O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH),
      PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, BeneathDotDotWithinScope) {
  // ".." is fine as long as it doesn't climb above the dirfd.
  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string path =
      JoinPath(Basename(sub.path()), "..", Basename(file.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), path, O_RDONLY, 0, RESOLVE_BENEATH));
}

TEST_F(Openat2Test, BeneathAbsoluteSymlink) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  // The target is inside the dirfd, but absolute symlinks are rejected
  // regardless of where they point.
  auto link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir_.path(), file.path()));
  const std::string name = std::string(Basename(link.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), name, O_RDONLY));
  EXPECT_THAT(OpenAt2(dirfd_.get(), name, O_RDONLY, 0, RESOLVE_BENEATH),
              PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, BeneathEscapingSymlink) {
  auto link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir_.path(), "../.."));

  EXPECT_THAT(OpenAt2(dirfd_.get(), std::string(Basename(link.path())),
                      O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH),
              PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, BeneathSymlinkWithinScope) {
  // A relative symlink that climbs and descends again, without leaving the
  // dirfd, is followed normally.
  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  auto link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      sub.path(), JoinPath("..", Basename(file.path()))));
  const std::string path =
      JoinPath(Basename(sub.path()), Basename(link.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), path, O_RDONLY, 0, RESOLVE_BENEATH));
}

TEST_F(Openat2Test, BeneathMagicSymlink) {
  // Magic links (/proc/[pid]/fd/*) are rejected for scoped lookups even when
  // they point inside the dirfd.
  const FileDescriptor procfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/fd", O_RDONLY | O_DIRECTORY));
  const std::string name = std::to_string(dirfd_.get());

  EXPECT_NO_ERRNO(OpenAt2(procfd.get(), name, O_RDONLY | O_DIRECTORY));
  EXPECT_THAT(
      OpenAt2(procfd.get(), name, O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH),
      PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, BeneathDotDotOverMountpoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string subname = std::string(Basename(sub.path()));

  // Climbing out of the mount and back down to a file in the dirfd stays in
  // scope.
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(),
                          JoinPath(subname, "..", Basename(file.path())),
                          O_RDONLY, 0, RESOLVE_BENEATH));

  // Climbing one level further leaves the dirfd.
  EXPECT_THAT(OpenAt2(dirfd_.get(), JoinPath(subname, "..", ".."),
                      O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH),
              PosixErrorIs(EXDEV));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
