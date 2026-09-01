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

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

using ::testing::AnyOf;
using ::testing::Matches;

#ifndef SYS_openat2
#if defined(__x86_64__)
#define SYS_openat2 437
#elif defined(__aarch64__)
#define SYS_openat2 437
#else
#error "Unknown architecture"
#endif
#endif

namespace gvisor {
namespace testing {

namespace {

int openat2(int dirfd, const std::string& path, const void* how, size_t size) {
  return syscall(SYS_openat2, dirfd, path.c_str(), how, size);
}

// Wrapper around openat2(2) that returns a FileDescriptor.
inline PosixErrorOr<FileDescriptor> OpenAt2(int dirfd, std::string const& path,
                                            uint64_t flags, mode_t mode = 0,
                                            uint64_t resolve = 0) {
  struct open_how how = {
      .flags = static_cast<__u64>(flags),
      .mode = static_cast<__u64>(mode),
      .resolve = resolve,
  };
  int fd = openat2(dirfd, path, &how, sizeof(how));
  if (fd < 0) {
    return PosixError(
        errno, absl::StrFormat("openat2(%d, %s, %#x, %#o, %#x)", dirfd, path,
                               flags, mode, resolve));
  }
  MaybeSave();
  return FileDescriptor(fd);
}

// Returns true if fd and path refer to the same file.
bool SameFile(int fd, const std::string& path) {
  struct stat a = {}, b = {};
  if (fstat(fd, &a) < 0 || stat(path.c_str(), &b) < 0) {
    return false;
  }
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
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
  const FileDescriptor root = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0, 0));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string name = std::string(Basename(file.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenAt2(dirfd_.get(), name, O_RDONLY));
  EXPECT_NO_ERRNO(OpenAt2(root.get(),
                          JoinPath("proc/self/fd", std::to_string(fd.get())),
                          O_RDONLY, 0));
  EXPECT_THAT(
      OpenAt2(root.get(), JoinPath("proc/self/fd", std::to_string(fd.get())),
              O_RDONLY, 0, RESOLVE_BENEATH),
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

// RESOLVE_NO_XDEV.

TEST_F(Openat2Test, BeneathRaceWithMount) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  constexpr int numIterations = 50000;
  std::atomic_bool done = false;

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string path =
      JoinPath(Basename(sub.path()), "..", Basename(file.path()));

  auto t = ScopedThread([&done] {
    // Race with a completely unrelated mount elsewhere on the system.
    // This should still be rejected by RESOLVE_BENEATH.
    auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

    while (!done.load()) {
      // Mount, then unmount, in a loop
      ASSERT_THAT(mount("tmpfs", dir.path().c_str(), "tmpfs", 0, ""),
                  SyscallSucceeds());
      ASSERT_THAT(umount(dir.path().c_str()), SyscallSucceeds());
    }
  });
  auto cleanup = Cleanup([&done] { done.store(true); });

  for (int i = 0; i < numIterations; i++) {
    auto result = OpenAt2(dirfd_.get(), path, O_RDONLY, 0, RESOLVE_BENEATH);
    EXPECT_THAT(result, AnyOf(IsPosixErrorOkMatcher(), PosixErrorIs(EAGAIN)));

    if (Matches(PosixErrorIs(EAGAIN))(result)) {
      // Test condition: at least one call to openat2(RESOLVE_BENEATH) should
      // give EAGAIN due to the mount race
      return;
    }
  }
  FAIL() << "No racing call to openat2() with RESOLVE_BENEATH gave EAGAIN";
}

TEST_F(Openat2Test, BeneathRaceWithRename) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  constexpr int numIterations = 50000;
  std::atomic_bool done = false;

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string path =
      JoinPath(Basename(sub.path()), "..", Basename(file.path()));

  auto t = ScopedThread([this, &done] {
    const auto dirfd = dirfd_.get();

    // Race with a completely unrelated rename elsewhere on the system.
    // This should still be rejected by RESOLVE_BENEATH.
    ASSERT_THAT(openat(dirfd, "0", O_RDONLY | O_CREAT, 0644),
                SyscallSucceeds());
    auto cleanup = Cleanup([&dirfd] {
      unlinkat(dirfd, "0", 0);
      unlinkat(dirfd, "1", 0);
    });

    uint64_t i = 1;
    while (!done.load()) {
      // Rename between "0" and "1" alternately
      const char* oldName;
      const char* newName;
      if (i % 2 == 1) {
        oldName = "0";
        newName = "1";
      } else {
        oldName = "1";
        newName = "0";
      }
      ASSERT_THAT(renameat(dirfd, oldName, dirfd, newName), SyscallSucceeds());

      i++;
    }
  });
  auto cleanup = Cleanup([&done] { done.store(true); });

  for (int i = 0; i < numIterations; i++) {
    auto result = OpenAt2(dirfd_.get(), path, O_RDONLY, 0, RESOLVE_BENEATH);
    EXPECT_THAT(result, AnyOf(IsPosixErrorOkMatcher(), PosixErrorIs(EAGAIN)));

    if (Matches(PosixErrorIs(EAGAIN))(result)) {
      // Test condition: at least one call to openat2(RESOLVE_BENEATH) should
      // give EAGAIN due to the rename race
      return;
    }
  }
  FAIL() << "No racing call to openat2() with RESOLVE_BENEATH gave EAGAIN";
}

TEST_F(Openat2Test, NoXDevWithoutCrossing) {
  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sub.path()));
  const std::string path = JoinPath(
      Basename(sub.path()), "..", Basename(sub.path()), Basename(file.path()));

  // Descending, and "..", within a single mount are unaffected.
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), path, O_RDONLY, 0, RESOLVE_NO_XDEV));
}

TEST_F(Openat2Test, NoXDevAbsoluteSymlinkSameMount) {
  // Following an absolute symlink restarts resolution at the traversal root.
  // When that root is on the same mount as the dirfd, no mountpoint boundary is
  // crossed and gVisor allows it.
  //
  // Linux currently rejects this, but this is likely a bug and may be fixed
  // in the future. See the comment in resolving_path.go:HandleSymlink() for
  // more details.
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  // Adjust dir_ to account for the upcoming chroot
  auto link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      dir_.path(), "/" + std::string(Basename(file.path()))));

  const std::string root = dir_.path();
  const std::string name = std::string(Basename(link.path()));
  const std::string via_dotdot = JoinPath(Basename(sub.path()), "..", name);

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(root.c_str()));
    const int dirfd = open("/", O_RDONLY | O_DIRECTORY);
    TEST_CHECK_SUCCESS(dirfd);

    struct open_how how = {
        .flags = O_RDONLY,
    };
    int fd = openat2(dirfd, name, &how, sizeof(how));
    TEST_CHECK_SUCCESS(fd);
    TEST_CHECK_SUCCESS(close(fd));

    how.resolve = RESOLVE_NO_XDEV;
    fd = openat2(dirfd, name, &how, sizeof(how));
    TEST_CHECK_SUCCESS(fd);
    TEST_CHECK_SUCCESS(close(fd));

    fd = openat2(dirfd, via_dotdot, &how, sizeof(how));
    TEST_CHECK_SUCCESS(fd);
    TEST_CHECK_SUCCESS(close(fd));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_F(Openat2Test, NoXDevAbsoluteSymlinkDifferentMount) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  const FileDescriptor mntfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(sub.path(), O_RDONLY | O_DIRECTORY));

  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  ASSERT_THAT(symlinkat(file.path().c_str(), mntfd.get(), "abslink"),
              SyscallSucceeds());

  EXPECT_NO_ERRNO(OpenAt2(mntfd.get(), "abslink", O_RDONLY));
  EXPECT_THAT(OpenAt2(mntfd.get(), "abslink", O_RDONLY, 0, RESOLVE_NO_XDEV),
              PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, NoXDevIntoMount) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  const std::string subname = std::string(Basename(sub.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), subname, O_RDONLY | O_DIRECTORY));
  EXPECT_THAT(OpenAt2(dirfd_.get(), subname, O_RDONLY | O_DIRECTORY, 0,
                      RESOLVE_NO_XDEV),
              PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, NoXDevOutOfMount) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  const FileDescriptor mntfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(sub.path(), O_RDONLY | O_DIRECTORY));

  // Climbing out of the mount is the same crossing in the other direction.
  EXPECT_NO_ERRNO(OpenAt2(mntfd.get(), "..", O_RDONLY | O_DIRECTORY));
  EXPECT_THAT(
      OpenAt2(mntfd.get(), "..", O_RDONLY | O_DIRECTORY, 0, RESOLVE_NO_XDEV),
      PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, NoXDevMagicSymlink) {
  const FileDescriptor procfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/fd", O_RDONLY | O_DIRECTORY));

  // A magic link landing on procfs, the same mount the dirfd is on, is not a
  // crossing.
  const FileDescriptor same =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/status", O_RDONLY));
  EXPECT_NO_ERRNO(OpenAt2(procfd.get(), std::to_string(same.get()), O_RDONLY, 0,
                          RESOLVE_NO_XDEV));

  // One landing on another mount is.
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const FileDescriptor other =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));
  EXPECT_THAT(OpenAt2(procfd.get(), std::to_string(other.get()), O_RDONLY, 0,
                      RESOLVE_NO_XDEV),
              PosixErrorIs(EXDEV));
}

// RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS.

TEST_F(Openat2Test, NoSymlinks) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  auto link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir_.path(), file.path()));
  const std::string lname = std::string(Basename(link.path()));

  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), std::string(Basename(file.path())),
                          O_RDONLY, 0, RESOLVE_NO_SYMLINKS));
  EXPECT_THAT(OpenAt2(dirfd_.get(), lname, O_RDONLY, 0, RESOLVE_NO_SYMLINKS),
              PosixErrorIs(ELOOP));
  // The symlink itself can still be opened, since that doesn't traverse it.
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), lname, O_PATH | O_NOFOLLOW, 0,
                          RESOLVE_NO_SYMLINKS));
}

TEST_F(Openat2Test, NoSymlinksRejectsMagicLinks) {
  // RESOLVE_NO_SYMLINKS (currently) implies RESOLVE_NO_MAGICLINKS.
  const FileDescriptor procfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/fd", O_RDONLY | O_DIRECTORY));

  EXPECT_THAT(OpenAt2(procfd.get(), std::to_string(dirfd_.get()),
                      O_RDONLY | O_DIRECTORY, 0, RESOLVE_NO_SYMLINKS),
              PosixErrorIs(ELOOP));
}

TEST_F(Openat2Test, NoMagicLinks) {
  const FileDescriptor procfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/fd", O_RDONLY | O_DIRECTORY));

  EXPECT_THAT(OpenAt2(procfd.get(), std::to_string(dirfd_.get()),
                      O_RDONLY | O_DIRECTORY, 0, RESOLVE_NO_MAGICLINKS),
              PosixErrorIs(ELOOP));

  // Ordinary symlinks are unaffected.
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  auto link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir_.path(), file.path()));
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), std::string(Basename(link.path())),
                          O_RDONLY, 0, RESOLVE_NO_MAGICLINKS));
}

// RESOLVE_IN_ROOT. Unlike RESOLVE_BENEATH, escapes are clamped to the dirfd
// rather than rejected, so these check where resolution actually landed.

TEST_F(Openat2Test, InRootAbsolutePathIsScoped) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string absname = "/" + std::string(Basename(file.path()));

  // Without IN_ROOT this path is resolved from the real root, where the file
  // doesn't exist.
  EXPECT_THAT(OpenAt2(dirfd_.get(), absname, O_RDONLY), PosixErrorIs(ENOENT));

  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(dirfd_.get(), absname, O_RDONLY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(fd.get(), file.path()));
}

TEST_F(Openat2Test, InRootDotDotClamps) {
  // Climbing above the dirfd is a no-op rather than an error.
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(OpenAt2(
      dirfd_.get(), "../../..", O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(fd.get(), dir_.path()));
}

TEST_F(Openat2Test, InRootAbsoluteSymlink) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  // The target names nothing at the real root, so resolving it at all proves
  // it was reinterpreted relative to the dirfd.
  auto link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      dir_.path(), "/" + std::string(Basename(file.path()))));

  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(dirfd_.get(), std::string(Basename(link.path())), O_RDONLY, 0,
              RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(fd.get(), file.path()));
}

TEST_F(Openat2Test, InRootEscapingSymlink) {
  auto link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir_.path(), "../.."));

  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(dirfd_.get(), std::string(Basename(link.path())),
              O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(fd.get(), dir_.path()));
}

TEST_F(Openat2Test, InRootMagicLink) {
  // Magic links are rejected for any scoped lookup, as with RESOLVE_BENEATH.
  const FileDescriptor root = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0, 0));
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir_.path()));
  const std::string name = std::string(Basename(file.path()));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenAt2(dirfd_.get(), name, O_RDONLY));

  EXPECT_NO_ERRNO(OpenAt2(root.get(),
                          JoinPath("/proc/self/fd", std::to_string(fd.get())),
                          O_RDONLY, 0));
  EXPECT_THAT(
      OpenAt2(root.get(), JoinPath("/proc/self/fd", std::to_string(fd.get())),
              O_RDONLY, 0, RESOLVE_IN_ROOT),
      PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, InRootWithBeneath) {
  // The two scoping flags are mutually exclusive.
  EXPECT_THAT(OpenAt2(dirfd_.get(), ".", O_RDONLY, 0,
                      RESOLVE_IN_ROOT | RESOLVE_BENEATH),
              PosixErrorIs(EINVAL));
}

TEST_F(Openat2Test, InRootOverMountpoint) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  const std::string subname = std::string(Basename(sub.path()));
  const FileDescriptor mntfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(sub.path(), O_RDONLY | O_DIRECTORY));
  // Lives in the tmpfs, so it goes away with the mount.
  ASSERT_NO_ERRNO(OpenAt(mntfd.get(), "inner", O_CREAT | O_WRONLY, 0644));

  // IN_ROOT bounds the subtree, not the device, so crossing into a mount below
  // the dirfd is still allowed.
  const FileDescriptor in = ASSERT_NO_ERRNO_AND_VALUE(OpenAt2(
      dirfd_.get(), JoinPath(subname, "inner"), O_RDONLY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(in.get(), JoinPath(sub.path(), "inner")));

  // Climbing back out of the mount and past the dirfd clamps at the dirfd.
  const FileDescriptor up = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(dirfd_.get(), JoinPath(subname, "..", "..", ".."),
              O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(up.get(), dir_.path()));
}

TEST_F(Openat2Test, InRootFromMountRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  const FileDescriptor mntfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(sub.path(), O_RDONLY | O_DIRECTORY));
  // Both live in the tmpfs, so they go away with the mount.
  ASSERT_NO_ERRNO(OpenAt(mntfd.get(), "inner", O_CREAT | O_WRONLY, 0644));
  ASSERT_THAT(symlinkat("/inner", mntfd.get(), "abslink"), SyscallSucceeds());
  const std::string inner = JoinPath(sub.path(), "inner");

  // ".." at a scope root that is itself a mount root clamps, rather than
  // popping out to the directory the mount is stacked on.
  const FileDescriptor up = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(mntfd.get(), "..", O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(up.get(), sub.path()));

  // Absolute paths and absolute symlinks are scoped to the mount root.
  const FileDescriptor abs = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(mntfd.get(), "/inner", O_RDONLY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(abs.get(), inner));

  const FileDescriptor via = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt2(mntfd.get(), "abslink", O_RDONLY, 0, RESOLVE_IN_ROOT));
  EXPECT_TRUE(SameFile(via.get(), inner));
}

TEST_F(Openat2Test, InRootWithNoXDev) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto sub = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir_.path()));
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", sub.path(), "tmpfs", 0, "", MNT_DETACH));
  const std::string subname = std::string(Basename(sub.path()));

  // Unlike RESOLVE_BENEATH, IN_ROOT composes with NO_XDEV; the two constrain
  // different things.
  EXPECT_NO_ERRNO(OpenAt2(dirfd_.get(), subname, O_RDONLY | O_DIRECTORY, 0,
                          RESOLVE_IN_ROOT));
  EXPECT_THAT(OpenAt2(dirfd_.get(), subname, O_RDONLY | O_DIRECTORY, 0,
                      RESOLVE_IN_ROOT | RESOLVE_NO_XDEV),
              PosixErrorIs(EXDEV));
}

TEST_F(Openat2Test, InRootRaceWithMount) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  constexpr int numIterations = 50000;
  std::atomic_bool done = false;

  auto t = ScopedThread([&done] {
    // Race with a completely unrelated mount elsewhere on the system.
    // This should still be rejected by RESOLVE_IN_ROOT.
    auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

    while (!done.load()) {
      // Mount, then unmount, in a loop
      ASSERT_THAT(mount("tmpfs", dir.path().c_str(), "tmpfs", 0, ""),
                  SyscallSucceeds());
      ASSERT_THAT(umount(dir.path().c_str()), SyscallSucceeds());
    }
  });
  auto cleanup = Cleanup([&done] { done.store(true); });

  for (int i = 0; i < numIterations; i++) {
    const auto result = OpenAt2(dirfd_.get(), "../../..",
                                O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT);
    EXPECT_THAT(result, AnyOf(IsPosixErrorOkMatcher(), PosixErrorIs(EAGAIN)));

    if (Matches(PosixErrorIs(EAGAIN))(result)) {
      // Test condition: at least one call to openat2(RESOLVE_IN_ROOT) should
      // give EAGAIN due to the mount race
      return;
    } else {
      const auto fd = result.ValueOrDie().get();
      EXPECT_TRUE(SameFile(fd, dir_.path()));
    }
  }
  FAIL() << "No racing call to openat2() with RESOLVE_IN_ROOT gave EAGAIN";
}

TEST_F(Openat2Test, InRootRaceWithRename) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  constexpr int numIterations = 50000;
  std::atomic_bool done = false;

  auto t = ScopedThread([this, &done] {
    const auto dirfd = dirfd_.get();

    // Race with a completely unrelated rename elsewhere on the system.
    // This should still be rejected by RESOLVE_IN_ROOT.
    ASSERT_THAT(openat(dirfd, "0", O_RDONLY | O_CREAT, 0644),
                SyscallSucceeds());
    auto cleanup = Cleanup([&dirfd] {
      unlinkat(dirfd, "0", 0);
      unlinkat(dirfd, "1", 0);
    });

    uint64_t i = 1;
    while (!done.load()) {
      // Rename between "0" and "1" alternately
      const char* oldName;
      const char* newName;
      if (i % 2 == 1) {
        oldName = "0";
        newName = "1";
      } else {
        oldName = "1";
        newName = "0";
      }
      ASSERT_THAT(renameat(dirfd, oldName, dirfd, newName), SyscallSucceeds());

      i++;
    }
  });
  auto cleanup = Cleanup([&done] { done.store(true); });

  for (int i = 0; i < numIterations; i++) {
    const auto result = OpenAt2(dirfd_.get(), "../../..",
                                O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT);
    EXPECT_THAT(result, AnyOf(IsPosixErrorOkMatcher(), PosixErrorIs(EAGAIN)));

    if (Matches(PosixErrorIs(EAGAIN))(result)) {
      // Test condition: at least one call to openat2(RESOLVE_IN_ROOT) should
      // give EAGAIN due to the mount race
      return;
    } else {
      const auto fd = result.ValueOrDie().get();
      EXPECT_TRUE(SameFile(fd, dir_.path()));
    }
  }
  FAIL() << "No racing call to openat2() with RESOLVE_IN_ROOT gave EAGAIN";
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
