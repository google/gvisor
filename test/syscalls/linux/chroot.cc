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

#include <algorithm>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
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

// Async-signal-safe conversion from integer to string, appending the string
// (including a terminating NUL) to buf, which is a buffer of size len bytes.
// Returns the number of bytes written, or 0 if the buffer is too small.
//
// Preconditions: 2 <= radix <= 16.
template <typename T>
size_t SafeItoa(T val, char* buf, size_t len, int radix) {
  size_t n = 0;
#define _WRITE_OR_FAIL(c) \
  do {                    \
    if (len == 0) {       \
      return 0;           \
    }                     \
    buf[n] = (c);         \
    n++;                  \
    len--;                \
  } while (false)
  if (val == 0) {
    _WRITE_OR_FAIL('0');
  } else {
    // Write digits in reverse order, then reverse them at the end.
    bool neg = val < 0;
    while (val != 0) {
      // C/C++ define modulo such that the result is negative if exactly one of
      // the dividend or divisor is negative, so this handles both positive and
      // negative values.
      char c = "fedcba9876543210123456789abcdef"[val % radix + 15];
      _WRITE_OR_FAIL(c);
      val /= 10;
    }
    if (neg) {
      _WRITE_OR_FAIL('-');
    }
    std::reverse(buf, buf + n);
  }
  _WRITE_OR_FAIL('\0');
  return n;
#undef _WRITE_OR_FAIL
}

TEST(ChrootTest, Success) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));
  auto temp_dir = TempPath::CreateDir().ValueOrDie();
  const std::string temp_dir_path = temp_dir.path();

  const auto rest = [&] { TEST_CHECK_SUCCESS(chroot(temp_dir_path.c_str())); };
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
  const std::string new_root_path = new_root.path();
  auto file_in_new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(new_root.path()));
  const std::string file_in_new_root_path = file_in_new_root.path();

  const auto rest = [&] {
    // chroot into new_root.
    TEST_CHECK_SUCCESS(chroot(new_root_path.c_str()));

    // getcwd should return "(unreachable)" followed by the initial_cwd.
    char buf[1024];
    TEST_CHECK_SUCCESS(syscall(__NR_getcwd, buf, sizeof(buf)));
    constexpr char kUnreachablePrefix[] = "(unreachable)";
    TEST_CHECK(
        strncmp(buf, kUnreachablePrefix, sizeof(kUnreachablePrefix) - 1) == 0);
    TEST_CHECK(strcmp(buf + sizeof(kUnreachablePrefix) - 1, initial_cwd) == 0);

    // Should not be able to stat file by its full path.
    struct stat statbuf;
    TEST_CHECK_ERRNO(stat(file_in_new_root_path.c_str(), &statbuf), ENOENT);

    // Should be able to stat file at new rooted path.
    buf[0] = '/';
    absl::string_view basename = Basename(file_in_new_root_path);
    TEST_CHECK(basename.length() < (sizeof(buf) - 2));
    memcpy(buf + 1, basename.data(), basename.length());
    buf[basename.length() + 1] = '\0';
    TEST_CHECK_SUCCESS(stat(buf, &statbuf));

    // Should be able to stat cwd at '.' even though it's outside root.
    TEST_CHECK_SUCCESS(stat(".", &statbuf));

    // chdir into new root.
    TEST_CHECK_SUCCESS(chdir("/"));

    // getcwd should return "/".
    TEST_CHECK_SUCCESS(syscall(__NR_getcwd, buf, sizeof(buf)));
    TEST_CHECK_SUCCESS(strcmp(buf, "/") == 0);

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
  const std::string new_root_path = new_root.path();

  const auto rest = [&] {
    // chroot into new_root.
    TEST_CHECK_SUCCESS(chroot(new_root_path.c_str()));

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
  const std::string file_outside_chroot_path = file_outside_chroot.path();
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file_outside_chroot.path(), O_RDONLY));

  const FileDescriptor proc_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open("/proc", O_DIRECTORY | O_RDONLY | O_CLOEXEC));

  auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string temp_dir_path = temp_dir.path();

  const auto rest = [&] {
    TEST_CHECK_SUCCESS(chroot(temp_dir_path.c_str()));

    // Opening relative to an already open fd to a node outside the chroot
    // works.
    const FileDescriptor proc_self_fd = TEST_CHECK_NO_ERRNO_AND_VALUE(
        OpenAt(proc_fd.get(), "self/fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC));

    // Proc fd symlinks can escape the chroot if the fd the symlink refers to
    // refers to an object outside the chroot.
    char fd_buf[11];
    TEST_CHECK(SafeItoa(fd.get(), fd_buf, sizeof(fd_buf), 10));
    struct stat s = {};
    TEST_CHECK_SUCCESS(fstatat(proc_self_fd.get(), fd_buf, &s, 0));

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

  const auto temp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string temp_dir_path = temp_dir.path();

  const auto rest = [&] {
    // Enter the chroot directory.
    TEST_CHECK_SUCCESS(chroot(temp_dir_path.c_str()));

    // Open a file inside the chroot at /foo.
    const FileDescriptor foo =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/foo", O_CREAT | O_RDONLY, 0644));

    // Examine /proc/self/fd/{foo_fd} to see if it exposes the fact that we're
    // inside a chroot, the path should be /foo and NOT {chroot_dir}/foo.
    constexpr char kSelfFdRelpath[] = "self/fd/";
    char path_buf[20];
    strcpy(path_buf, kSelfFdRelpath);  // NOLINT: need async-signal-safety
    TEST_CHECK(SafeItoa(foo.get(), path_buf + sizeof(kSelfFdRelpath) - 1,
                        sizeof(path_buf) - (sizeof(kSelfFdRelpath) - 1), 10));
    char buf[1024] = {};
    size_t bytes_read = 0;
    TEST_CHECK_SUCCESS(
        bytes_read = readlinkat(proc.get(), path_buf, buf, sizeof(buf) - 1));

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

  const auto temp_dir = TEST_CHECK_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string temp_dir_path = temp_dir.path();

  const auto rest = [&] {
    // Enter the chroot directory.
    TEST_CHECK_SUCCESS(chroot(temp_dir_path.c_str()));

    // Open a file inside the chroot at /foo.
    const FileDescriptor foo =
        TEST_CHECK_NO_ERRNO_AND_VALUE(Open("/foo", O_CREAT | O_RDONLY, 0644));

    // Mmap the newly created file.
    void* foo_map = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE, foo.get(), 0);
    TEST_CHECK_SUCCESS(reinterpret_cast<int64_t>(foo_map));

    // Always unmap. Since this function is called between fork() and execve(),
    // we can't use gvisor::testing::Cleanup, which uses std::function
    // and thus may heap-allocate (which is async-signal-unsafe); instead, use
    // absl::Cleanup, which is templated on the callback type.
    auto cleanup_map = absl::MakeCleanup(
        [&] { TEST_CHECK_SUCCESS(munmap(foo_map, kPageSize)); });

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
    TEST_CHECK(
        !absl::StrContains(absl::string_view(buf, bytes_read), temp_dir_path));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// Test that mounts outside the chroot will not appear in /proc/self/mounts or
// /proc/self/mountinfo.
TEST(ChrootTest, ProcMountsMountinfoNoEscape) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_CHROOT)));

  // Create nested tmpfs mounts.
  const auto outer_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string outer_dir_path = outer_dir.path();
  const auto outer_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("none", outer_dir_path, "tmpfs", 0, "mode=0700", 0));

  const auto inner_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(outer_dir_path));
  const std::string inner_dir_path = inner_dir.path();
  const auto inner_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("none", inner_dir_path, "tmpfs", 0, "mode=0700", 0));
  const std::string inner_dir_in_outer_chroot_path =
      absl::StrCat("/", Basename(inner_dir_path));

  // Filenames that will be checked for mounts, all relative to /proc dir.
  std::string paths[3] = {"mounts", "self/mounts", "self/mountinfo"};

  for (const std::string& path : paths) {
    // We should have both inner and outer mounts.
    const std::string contents =
        ASSERT_NO_ERRNO_AND_VALUE(GetContents(JoinPath("/proc", path)));
    EXPECT_THAT(contents,
                AllOf(HasSubstr(outer_dir_path), HasSubstr(inner_dir_path)));
    // We better have at least two mounts: the mounts we created plus the
    // root.
    std::vector<absl::string_view> submounts =
        absl::StrSplit(contents, '\n', absl::SkipWhitespace());
    ASSERT_GT(submounts.size(), 2);
  }

  // Get a FD to /proc before we enter the chroot.
  const FileDescriptor proc =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc", O_RDONLY));

  const auto rest = [&] {
    // Chroot to outer mount.
    TEST_CHECK_SUCCESS(chroot(outer_dir_path.c_str()));

    char buf[8 * 1024];
    for (const std::string& path : paths) {
      const FileDescriptor proc_file =
          TEST_CHECK_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), path, O_RDONLY));

      // Only two mounts visible from this chroot: the inner and outer.  Both
      // paths should be relative to the new chroot.
      ssize_t n = ReadFd(proc_file.get(), buf, sizeof(buf));
      TEST_PCHECK(n >= 0);
      buf[n] = '\0';
      TEST_CHECK(absl::StrContains(buf, Basename(inner_dir_path)));
      TEST_CHECK(!absl::StrContains(buf, outer_dir_path));
      TEST_CHECK(!absl::StrContains(buf, inner_dir_path));
      TEST_CHECK(std::count(buf, buf + n, '\n') == 2);
    }

    // Chroot to inner mount.  We must use an absolute path accessible to our
    // chroot.
    TEST_CHECK_SUCCESS(chroot(inner_dir_in_outer_chroot_path.c_str()));

    for (const std::string& path : paths) {
      const FileDescriptor proc_file =
          TEST_CHECK_NO_ERRNO_AND_VALUE(OpenAt(proc.get(), path, O_RDONLY));

      // Only the inner mount visible from this chroot.
      ssize_t n = ReadFd(proc_file.get(), buf, sizeof(buf));
      TEST_PCHECK(n >= 0);
      buf[n] = '\0';
      TEST_CHECK(std::count(buf, buf + n, '\n') == 1);
    }
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
