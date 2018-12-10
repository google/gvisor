// Copyright 2018 Google LLC
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
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::HasSubstr;
using ::testing::Not;

namespace gvisor {
namespace testing {

namespace {

TEST(ChrootTest, Success) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(chroot(temp_dir.path().c_str()), SyscallSucceeds());
}

TEST(ChrootTest, PermissionDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE may override Execute permission on
  // directories.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateDirWith(GetAbsoluteTestTmpdir(), 0666 /* mode */));
  EXPECT_THAT(chroot(temp_dir.path().c_str()), SyscallFailsWithErrno(EACCES));
}

TEST(ChrootTest, NotDir) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  EXPECT_THAT(chroot(temp_file.path().c_str()), SyscallFailsWithErrno(ENOTDIR));
}

TEST(ChrootTest, NotExist) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  EXPECT_THAT(chroot("/foo/bar"), SyscallFailsWithErrno(ENOENT));
}

TEST(ChrootTest, WithoutCapability) {
  // Unset CAP_SYS_CHROOT.
  ASSERT_NO_ERRNO(SetCapability(CAP_SYS_CHROOT, false));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(chroot(temp_dir.path().c_str()), SyscallFailsWithErrno(EPERM));
}

TEST(ChrootTest, CreatesNewRoot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Grab the initial cwd.
  char initial_cwd[1024];
  ASSERT_THAT(syscall(__NR_getcwd, initial_cwd, sizeof(initial_cwd)),
              SyscallSucceeds());

  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file_in_new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(new_root.path()));

  // chroot into new_root.
  ASSERT_THAT(chroot(new_root.path().c_str()), SyscallSucceeds());

  // getcwd should return "(unreachable)" followed by the initial_cwd.
  char cwd[1024];
  ASSERT_THAT(syscall(__NR_getcwd, cwd, sizeof(cwd)), SyscallSucceeds());
  std::string expected_cwd = "(unreachable)";
  expected_cwd += initial_cwd;
  EXPECT_STREQ(cwd, expected_cwd.c_str());

  // Should not be able to stat file by its full path.
  struct stat statbuf;
  EXPECT_THAT(stat(file_in_new_root.path().c_str(), &statbuf),
              SyscallFailsWithErrno(ENOENT));

  // Should be able to stat file at new rooted path.
  auto basename = std::string(Basename(file_in_new_root.path()));
  auto rootedFile = "/" + basename;
  ASSERT_THAT(stat(rootedFile.c_str(), &statbuf), SyscallSucceeds());

  // Should be able to stat cwd at '.' even though it's outside root.
  ASSERT_THAT(stat(".", &statbuf), SyscallSucceeds());

  // chdir into new root.
  ASSERT_THAT(chdir("/"), SyscallSucceeds());

  // getcwd should return "/".
  EXPECT_THAT(syscall(__NR_getcwd, cwd, sizeof(cwd)), SyscallSucceeds());
  EXPECT_STREQ(cwd, "/");

  // Statting '.', '..', '/', and '/..' all return the same dev and inode.
  struct stat statbuf_dot;
  ASSERT_THAT(stat(".", &statbuf_dot), SyscallSucceeds());
  struct stat statbuf_dotdot;
  ASSERT_THAT(stat("..", &statbuf_dotdot), SyscallSucceeds());
  EXPECT_EQ(statbuf_dot.st_dev, statbuf_dotdot.st_dev);
  EXPECT_EQ(statbuf_dot.st_ino, statbuf_dotdot.st_ino);
  struct stat statbuf_slash;
  ASSERT_THAT(stat("/", &statbuf_slash), SyscallSucceeds());
  EXPECT_EQ(statbuf_dot.st_dev, statbuf_slash.st_dev);
  EXPECT_EQ(statbuf_dot.st_ino, statbuf_slash.st_ino);
  struct stat statbuf_slashdotdot;
  ASSERT_THAT(stat("/..", &statbuf_slashdotdot), SyscallSucceeds());
  EXPECT_EQ(statbuf_dot.st_dev, statbuf_slashdotdot.st_dev);
  EXPECT_EQ(statbuf_dot.st_ino, statbuf_slashdotdot.st_ino);
}

TEST(ChrootTest, DotDotFromOpenFD) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto dir_outside_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(dir_outside_root.path(), O_RDONLY | O_DIRECTORY));
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  // chroot into new_root.
  ASSERT_THAT(chroot(new_root.path().c_str()), SyscallSucceeds());

  // openat on fd with path .. will succeed.
  int other_fd;
  ASSERT_THAT(other_fd = openat(fd.get(), "..", O_RDONLY), SyscallSucceeds());
  EXPECT_THAT(close(other_fd), SyscallSucceeds());

  // getdents on fd should not error.
  char buf[1024];
  ASSERT_THAT(syscall(SYS_getdents, fd.get(), buf, sizeof(buf)),
              SyscallSucceeds());
}

// Test that link resolution in a chroot can escape the root by following an
// open proc fd.
TEST(ChrootTest, ProcFdLinkResolutionInChroot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  const TempPath file_outside_chroot =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file_outside_chroot.path(), O_RDONLY));

  const FileDescriptor proc_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc", O_DIRECTORY | O_RDONLY | O_CLOEXEC));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(chroot(temp_dir.path().c_str()), SyscallSucceeds());

  // Opening relative to an already open fd to a node outside the chroot works.
  const FileDescriptor proc_self_fd = ASSERT_NO_ERRNO_AND_VALUE(
      OpenAt(proc_fd.get(), "self/fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC));

  // Proc fd symlinks can escape the chroot if the fd the symlink refers to
  // refers to an object outside the chroot.
  struct stat s = {};
  EXPECT_THAT(
      fstatat(proc_self_fd.get(), absl::StrCat(fd.get()).c_str(), &s, 0),
      SyscallSucceeds());

  // Try to stat the stdin fd. Internally, this is handled differently from a
  // proc fd entry pointing to a file, since stdin is backed by a host fd, and
  // isn't a walkable path on the filesystem inside the sandbox.
  EXPECT_THAT(fstatat(proc_self_fd.get(), "0", &s, 0), SyscallSucceeds());
}

// This test will verify that when you hold a fd to proc before entering
// a chroot that any files inside the chroot will appear rooted to the
// base chroot when examining /proc/self/fd/{num}.
TEST(ChrootTest, ProcMemSelfFdsNoEscapeProcOpen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Get a FD to /proc before we enter the chroot.
  const FileDescriptor proc =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

  // Create and enter a chroot directory.
  const auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(chroot(temp_dir.path().c_str()), SyscallSucceeds());

  // Open a file inside the chroot at /foo.
  const FileDescriptor foo =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/foo", O_CREAT | O_RDONLY, 0644));

  // Examine /proc/self/fd/{foo_fd} to see if it exposes the fact that we're
  // inside a chroot, the path should be /foo and NOT {chroot_dir}/foo.
  const std::string fd_path = absl::StrCat("self/fd/", foo.get());
  char buf[1024] = {};
  size_t bytes_read = 0;
  ASSERT_THAT(bytes_read =
                  readlinkat(proc.get(), fd_path.c_str(), buf, sizeof(buf) - 1),
              SyscallSucceeds());

  // The link should resolve to something.
  ASSERT_GT(bytes_read, 0);

  // Assert that the link doesn't contain the chroot path and is only /foo.
  EXPECT_STREQ(buf, "/foo");
}

// This test will verify that a file inside a chroot when mmapped will not
// expose the full file path via /proc/self/maps and instead honor the chroot.
TEST(ChrootTest, ProcMemSelfMapsNoEscapeProcOpen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Get a FD to /proc before we enter the chroot.
  const FileDescriptor proc =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

  // Create and enter a chroot directory.
  const auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(chroot(temp_dir.path().c_str()), SyscallSucceeds());

  // Open a file inside the chroot at /foo.
  const FileDescriptor foo =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/foo", O_CREAT | O_RDONLY, 0644));

  // Mmap the newly created file.
  void* foo_map = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                       foo.get(), 0);
  ASSERT_THAT(reinterpret_cast<int64_t>(foo_map), SyscallSucceeds());

  // Always unmap.
  auto cleanup_map = Cleanup(
      [&] { EXPECT_THAT(munmap(foo_map, kPageSize), SyscallSucceeds()); });

  // Examine /proc/self/maps to be sure that /foo doesn't appear to be
  // mapped with the full chroot path.
  const FileDescriptor maps =
      ASSERT_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), "self/maps", O_RDONLY));

  size_t bytes_read = 0;
  char buf[8 * 1024] = {};
  ASSERT_THAT(bytes_read = ReadFd(maps.get(), buf, sizeof(buf)),
              SyscallSucceeds());

  // The maps file should have something.
  ASSERT_GT(bytes_read, 0);

  // Finally we want to make sure the maps don't contain the chroot path
  ASSERT_EQ(std::string(buf, bytes_read).find(temp_dir.path()), std::string::npos);
}

// Test that mounts outside the chroot will not appear in /proc/self/mounts or
// /proc/self/mountinfo.
TEST(ChrootTest, ProcMountsMountinfoNoEscape) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // We are going to create some mounts and then chroot. In order to be able to
  // unmount the mounts after the test run, we must chdir to the root and use
  // relative paths for all mounts. That way, as long as we never chdir into
  // the new root, we can access the mounts via relative paths and unmount them.
  ASSERT_THAT(chdir("/"), SyscallSucceeds());

  // Create nested tmpfs mounts. Note the use of relative paths in Mount calls.
  auto const outer_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const outer_mount = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      "none", JoinPath(".", outer_dir.path()), "tmpfs", 0, "mode=0700", 0));

  auto const inner_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(outer_dir.path()));
  auto const inner_mount = ASSERT_NO_ERRNO_AND_VALUE(Mount(
      "none", JoinPath(".", inner_dir.path()), "tmpfs", 0, "mode=0700", 0));

  // Filenames that will be checked for mounts, all relative to /proc dir.
  std::string paths[3] = {"mounts", "self/mounts", "self/mountinfo"};

  for (const std::string& path : paths) {
    // We should have both inner and outer mounts.
    const std::string contents =
        ASSERT_NO_ERRNO_AND_VALUE(GetContents(JoinPath("/proc", path)));
    EXPECT_THAT(contents, AllOf(HasSubstr(outer_dir.path()),
                                HasSubstr(inner_dir.path())));
    // We better have at least two mounts: the mounts we created plus the root.
    std::vector<absl::string_view> submounts =
        absl::StrSplit(contents, '\n', absl::SkipWhitespace());
    EXPECT_GT(submounts.size(), 2);
  }

  // Get a FD to /proc before we enter the chroot.
  const FileDescriptor proc =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

  // Chroot to outer mount.
  ASSERT_THAT(chroot(outer_dir.path().c_str()), SyscallSucceeds());

  for (const std::string& path : paths) {
    const FileDescriptor proc_file =
        ASSERT_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), path, O_RDONLY));

    // Only two mounts visible from this chroot: the inner and outer.  Both
    // paths should be relative to the new chroot.
    const std::string contents =
        ASSERT_NO_ERRNO_AND_VALUE(GetContentsFD(proc_file.get()));
    EXPECT_THAT(contents,
                AllOf(HasSubstr(absl::StrCat(Basename(inner_dir.path()))),
                      Not(HasSubstr(outer_dir.path())),
                      Not(HasSubstr(inner_dir.path()))));
    std::vector<absl::string_view> submounts =
        absl::StrSplit(contents, '\n', absl::SkipWhitespace());
    EXPECT_EQ(submounts.size(), 2);
  }

  // Chroot to inner mount.  We must use an absolute path accessible to our
  // chroot.
  const std::string inner_dir_basename =
      absl::StrCat("/", Basename(inner_dir.path()));
  ASSERT_THAT(chroot(inner_dir_basename.c_str()), SyscallSucceeds());

  for (const std::string& path : paths) {
    const FileDescriptor proc_file =
        ASSERT_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), path, O_RDONLY));
    const std::string contents =
        ASSERT_NO_ERRNO_AND_VALUE(GetContentsFD(proc_file.get()));

    // Only the inner mount visible from this chroot.
    std::vector<absl::string_view> submounts =
        absl::StrSplit(contents, '\n', absl::SkipWhitespace());
    EXPECT_EQ(submounts.size(), 1);
  }

  // Chroot back to ".".
  ASSERT_THAT(chroot("."), SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
