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
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::HasSubstr;
using ::testing::Not;

namespace gvisor {
namespace testing {

namespace {

TEST(ChrootTest, Success) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  const auto rest = [] {
    auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    TEST_CHECK_SUCCESS(chroot(temp_dir.path().c_str()));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(ChrootTest, PermissionDenied) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE may override Execute permission
  // on directories.
  AutoCapability cap_search(CAP_DAC_READ_SEARCH, false);
  AutoCapability cap_override(CAP_DAC_OVERRIDE, false);

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
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETPCAP)));

  // Unset CAP_SYS_CHROOT.
  AutoCapability cap(CAP_SYS_CHROOT, false);

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

  const auto rest = [&] {
    // chroot into new_root.
    TEST_CHECK_SUCCESS(chroot(new_root.path().c_str()));

    // getcwd should return "(unreachable)" followed by the initial_cwd.
    char cwd[1024];
    TEST_CHECK_SUCCESS(syscall(__NR_getcwd, cwd, sizeof(cwd)));
    std::string expected_cwd = "(unreachable)";
    expected_cwd += initial_cwd;
    TEST_CHECK(strcmp(cwd, expected_cwd.c_str()) == 0);

    // Should not be able to stat file by its full path.
    struct stat statbuf;
    TEST_CHECK_ERRNO(stat(file_in_new_root.path().c_str(), &statbuf), ENOENT);

    // Should be able to stat file at new rooted path.
    auto basename = std::string(Basename(file_in_new_root.path()));
    auto rootedFile = "/" + basename;
    TEST_CHECK_SUCCESS(stat(rootedFile.c_str(), &statbuf));

    // Should be able to stat cwd at '.' even though it's outside root.
    TEST_CHECK_SUCCESS(stat(".", &statbuf));

    // chdir into new root.
    TEST_CHECK_SUCCESS(chdir("/"));

    // getcwd should return "/".
    TEST_CHECK_SUCCESS(syscall(__NR_getcwd, cwd, sizeof(cwd)));
    TEST_CHECK_SUCCESS(strcmp(cwd, "/") == 0);

    // Statting '.', '..', '/', and '/..' all return the same dev and inode.
    struct stat statbuf_dot;
    TEST_CHECK_SUCCESS(stat(".", &statbuf_dot));
    struct stat statbuf_dotdot;
    TEST_CHECK_SUCCESS(stat("..", &statbuf_dotdot));
    TEST_CHECK(statbuf_dot.st_dev == statbuf_dotdot.st_dev);
    TEST_CHECK(statbuf_dot.st_ino == statbuf_dotdot.st_ino);
    struct stat statbuf_slash;
    TEST_CHECK_SUCCESS(stat("/", &statbuf_slash));
    TEST_CHECK(statbuf_dot.st_dev == statbuf_slash.st_dev);
    TEST_CHECK(statbuf_dot.st_ino == statbuf_slash.st_ino);
    struct stat statbuf_slashdotdot;
    TEST_CHECK_SUCCESS(stat("/..", &statbuf_slashdotdot));
    TEST_CHECK(statbuf_dot.st_dev == statbuf_slashdotdot.st_dev);
    TEST_CHECK(statbuf_dot.st_ino == statbuf_slashdotdot.st_ino);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(ChrootTest, DotDotFromOpenFD) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  auto dir_outside_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(dir_outside_root.path(), O_RDONLY | O_DIRECTORY));
  auto new_root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const auto rest = [&] {
    // chroot into new_root.
    TEST_CHECK_SUCCESS(chroot(new_root.path().c_str()));

    // openat on fd with path .. will succeed.
    int other_fd;
    TEST_CHECK_SUCCESS(other_fd = openat(fd.get(), "..", O_RDONLY));
    TEST_CHECK_SUCCESS(close(other_fd));

    // getdents on fd should not error.
    char buf[1024];
    TEST_CHECK_SUCCESS(syscall(SYS_getdents64, fd.get(), buf, sizeof(buf)));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// Test that link resolution in a chroot can escape the root by following an
// open proc fd. Regression test for b/32316719.
TEST(ChrootTest, ProcFdLinkResolutionInChroot) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  const TempPath file_outside_chroot =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file_outside_chroot.path(), O_RDONLY));

  const FileDescriptor proc_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc", O_DIRECTORY | O_RDONLY | O_CLOEXEC));

  const auto rest = [&] {
    auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    TEST_CHECK_SUCCESS(chroot(temp_dir.path().c_str()));

    // Opening relative to an already open fd to a node outside the chroot
    // works.
    const FileDescriptor proc_self_fd = TEST_CHECK_NO_ERRNO_AND_VALUE(
        OpenAt(proc_fd.get(), "self/fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC));

    // Proc fd symlinks can escape the chroot if the fd the symlink refers to
    // refers to an object outside the chroot.
    struct stat s = {};
    TEST_CHECK_SUCCESS(
        fstatat(proc_self_fd.get(), absl::StrCat(fd.get()).c_str(), &s, 0));

    // Try to stat the stdin fd. Internally, this is handled differently from a
    // proc fd entry pointing to a file, since stdin is backed by a host fd, and
    // isn't a walkable path on the filesystem inside the sandbox.
    TEST_CHECK_SUCCESS(fstatat(proc_self_fd.get(), "0", &s, 0));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// This test will verify that when you hold a fd to proc before entering
// a chroot that any files inside the chroot will appear rooted to the
// base chroot when examining /proc/self/fd/{num}.
TEST(ChrootTest, ProcMemSelfFdsNoEscapeProcOpen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Get a FD to /proc before we enter the chroot.
  const FileDescriptor proc =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

  const auto rest = [&] {
    // Create and enter a chroot directory.
    const auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    TEST_CHECK_SUCCESS(chroot(temp_dir.path().c_str()));

    // Open a file inside the chroot at /foo.
    const FileDescriptor foo =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/foo", O_CREAT | O_RDONLY, 0644));

    // Examine /proc/self/fd/{foo_fd} to see if it exposes the fact that we're
    // inside a chroot, the path should be /foo and NOT {chroot_dir}/foo.
    const std::string fd_path = absl::StrCat("self/fd/", foo.get());
    char buf[1024] = {};
    size_t bytes_read = 0;
    TEST_CHECK_SUCCESS(bytes_read = readlinkat(proc.get(), fd_path.c_str(), buf,
                                               sizeof(buf) - 1));

    // The link should resolve to something.
    TEST_CHECK(bytes_read > 0);

    // Assert that the link doesn't contain the chroot path and is only /foo.
    TEST_CHECK(strcmp(buf, "/foo") == 0);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// This test will verify that a file inside a chroot when mmapped will not
// expose the full file path via /proc/self/maps and instead honor the chroot.
TEST(ChrootTest, ProcMemSelfMapsNoEscapeProcOpen) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Get a FD to /proc before we enter the chroot.
  const FileDescriptor proc =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

  const auto rest = [&] {
    // Create and enter a chroot directory.
    const auto temp_dir = TEST_CHECK_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    TEST_CHECK_SUCCESS(chroot(temp_dir.path().c_str()));

    // Open a file inside the chroot at /foo.
    const FileDescriptor foo =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/foo", O_CREAT | O_RDONLY, 0644));

    // Mmap the newly created file.
    void* foo_map = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE, foo.get(), 0);
    TEST_CHECK_SUCCESS(reinterpret_cast<int64_t>(foo_map));

    // Always unmap.
    auto cleanup_map =
        Cleanup([&] { TEST_CHECK_SUCCESS(munmap(foo_map, kPageSize)); });

    // Examine /proc/self/maps to be sure that /foo doesn't appear to be
    // mapped with the full chroot path.
    const FileDescriptor maps = TEST_CHECK_NO_ERRNO_AND_VALUE(
        OpenAt(proc.get(), "self/maps", O_RDONLY));

    size_t bytes_read = 0;
    char buf[8 * 1024] = {};
    TEST_CHECK_SUCCESS(bytes_read = ReadFd(maps.get(), buf, sizeof(buf)));

    // The maps file should have something.
    TEST_CHECK(bytes_read > 0);

    // Finally we want to make sure the maps don't contain the chroot path
    TEST_CHECK(std::string(buf, bytes_read).find(temp_dir.path()) ==
               std::string::npos);
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// Test that mounts outside the chroot will not appear in /proc/self/mounts or
// /proc/self/mountinfo.
TEST(ChrootTest, ProcMountsMountinfoNoEscape) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Create nested tmpfs mounts.
  auto const outer_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto const outer_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("none", outer_dir.path(), "tmpfs", 0, "mode=0700", 0));

  auto const inner_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(outer_dir.path()));
  auto const inner_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("none", inner_dir.path(), "tmpfs", 0, "mode=0700", 0));

  const auto rest = [&outer_dir, &inner_dir] {
    // Filenames that will be checked for mounts, all relative to /proc dir.
    std::string paths[3] = {"mounts", "self/mounts", "self/mountinfo"};

    for (const std::string& path : paths) {
      // We should have both inner and outer mounts.
      const std::string contents =
          TEST_CHECK_NO_ERRNO_AND_VALUE(GetContents(JoinPath("/proc", path)));
      EXPECT_THAT(contents, AllOf(HasSubstr(outer_dir.path()),
                                  HasSubstr(inner_dir.path())));
      // We better have at least two mounts: the mounts we created plus the
      // root.
      std::vector<absl::string_view> submounts =
          absl::StrSplit(contents, '\n', absl::SkipWhitespace());
      TEST_CHECK(submounts.size() > 2);
    }

    // Get a FD to /proc before we enter the chroot.
    const FileDescriptor proc =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

    // Chroot to outer mount.
    TEST_CHECK_SUCCESS(chroot(outer_dir.path().c_str()));

    for (const std::string& path : paths) {
      const FileDescriptor proc_file =
          TEST_CHECK_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), path, O_RDONLY));

      // Only two mounts visible from this chroot: the inner and outer.  Both
      // paths should be relative to the new chroot.
      const std::string contents =
          TEST_CHECK_NO_ERRNO_AND_VALUE(GetContentsFD(proc_file.get()));
      EXPECT_THAT(contents,
                  AllOf(HasSubstr(absl::StrCat(Basename(inner_dir.path()))),
                        Not(HasSubstr(outer_dir.path())),
                        Not(HasSubstr(inner_dir.path()))));
      std::vector<absl::string_view> submounts =
          absl::StrSplit(contents, '\n', absl::SkipWhitespace());
      TEST_CHECK(submounts.size() == 2);
    }

    // Chroot to inner mount.  We must use an absolute path accessible to our
    // chroot.
    const std::string inner_dir_basename =
        absl::StrCat("/", Basename(inner_dir.path()));
    TEST_CHECK_SUCCESS(chroot(inner_dir_basename.c_str()));

    for (const std::string& path : paths) {
      const FileDescriptor proc_file =
          TEST_CHECK_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), path, O_RDONLY));
      const std::string contents =
          TEST_CHECK_NO_ERRNO_AND_VALUE(GetContentsFD(proc_file.get()));

      // Only the inner mount visible from this chroot.
      std::vector<absl::string_view> submounts =
          absl::StrSplit(contents, '\n', absl::SkipWhitespace());
      TEST_CHECK(submounts.size() == 1);
    }
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
