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

#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Where the directory passed to open(O_TMPFILE) lives.
enum class Location {
  // A directory under TEST_TMPDIR, whose filesystem is chosen by the test
  // runner.
  kTestTmpdir,
  // A freshly mounted tmpfs.
  kTmpfsMount,
};

class TmpfileTest : public ::testing::TestWithParam<Location> {
 protected:
  void SetUp() override {
    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    if (GetParam() == Location::kTmpfsMount) {
      SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
      mount_ = ASSERT_NO_ERRNO_AND_VALUE(
          Mount("", dir_.path(), "tmpfs", 0, "mode=0777", 0));
    }
    // gVisor only supports O_TMPFILE on tmpfs and overlay.
    if (IsRunningOnGvisor()) {
      const bool tmpfs = ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(dir_.path()));
      const bool overlay = ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(dir_.path()));
      SKIP_IF(!tmpfs && !overlay);
    }
  }

  const std::string& dir() const { return dir_.path(); }

  PosixErrorOr<FileDescriptor> OpenTmpfile(int flags, mode_t mode) {
    return Open(dir(), O_TMPFILE | flags, mode);
  }

 private:
  TempPath dir_;
  Cleanup mount_;
};

// Names the file open on fd by linking /proc/self/fd/N. This works on every
// kernel version, unlike linkat(AT_EMPTY_PATH), which needs
// CAP_DAC_READ_SEARCH before Linux 6.10.
int LinkViaProcSelfFd(int fd, const std::string& newpath) {
  const std::string oldpath = absl::StrCat("/proc/self/fd/", fd);
  return linkat(AT_FDCWD, oldpath.c_str(), AT_FDCWD, newpath.c_str(),
                AT_SYMLINK_FOLLOW);
}

TEST_P(TmpfileTest, CreatesUnnamedRegularFile) {
  const mode_t old_umask = umask(0022);
  const Cleanup restore_umask([old_umask] { umask(old_umask); });

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0666));

  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st.st_mode));
  EXPECT_EQ(st.st_mode & 0777, 0644u);
  EXPECT_EQ(st.st_nlink, 0u);
  EXPECT_EQ(st.st_uid, geteuid());
  EXPECT_EQ(st.st_size, 0);

  // The file has no name in the directory.
  const std::vector<std::string> entries =
      ASSERT_NO_ERRNO_AND_VALUE(ListDir(dir(), /*skipdots=*/true));
  EXPECT_TRUE(entries.empty());
}

TEST_P(TmpfileTest, ReadWrite) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0600));
  const std::string data = "tmpfile";
  ASSERT_THAT(pwrite(fd.get(), data.data(), data.size(), 0),
              SyscallSucceedsWithValue(data.size()));
  char buf[16] = {};
  ASSERT_THAT(pread(fd.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(std::string(buf, data.size()), data);
}

TEST_P(TmpfileTest, Mmap) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0600));
  ASSERT_THAT(ftruncate(fd.get(), kPageSize), SyscallSucceeds());
  void* addr =
      mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
  ASSERT_NE(addr, MAP_FAILED);
  const Cleanup unmap([addr] { munmap(addr, kPageSize); });
  memset(addr, 'x', kPageSize);

  std::vector<char> buf(kPageSize);
  ASSERT_THAT(pread(fd.get(), buf.data(), buf.size(), 0),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_EQ(buf.front(), 'x');
  EXPECT_EQ(buf.back(), 'x');
}

TEST_P(TmpfileTest, ReadOnlyIsInvalid) {
  EXPECT_THAT(open(dir().c_str(), O_TMPFILE | O_RDONLY, 0600),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(TmpfileTest, CreatIsInvalid) {
  EXPECT_THAT(open(dir().c_str(), O_TMPFILE | O_RDWR | O_CREAT, 0600),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(TmpfileTest, NonDirectory) {
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir()));
  EXPECT_THAT(open(file.path().c_str(), O_TMPFILE | O_RDWR, 0600),
              SyscallFailsWithErrno(ENOTDIR));
}

TEST_P(TmpfileTest, UnwritableDirectory) {
  // CAP_DAC_OVERRIDE bypasses the directory permission check.
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_DAC_OVERRIDE)));
  const TempPath subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirWith(dir(), 0555));
  EXPECT_THAT(open(subdir.path().c_str(), O_TMPFILE | O_RDWR, 0600),
              SyscallFailsWithErrno(EACCES));
}

TEST_P(TmpfileTest, LinkViaProcSelfFd) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0600));
  const std::string data = "named";
  ASSERT_THAT(write(fd.get(), data.data(), data.size()),
              SyscallSucceedsWithValue(data.size()));

  const std::string newpath = NewTempAbsPathInDir(dir());
  ASSERT_THAT(LinkViaProcSelfFd(fd.get(), newpath), SyscallSucceeds());

  struct stat fd_st;
  struct stat path_st;
  ASSERT_THAT(fstat(fd.get(), &fd_st), SyscallSucceeds());
  ASSERT_THAT(stat(newpath.c_str(), &path_st), SyscallSucceeds());
  EXPECT_EQ(fd_st.st_nlink, 1u);
  EXPECT_EQ(fd_st.st_ino, path_st.st_ino);
  EXPECT_EQ(fd_st.st_dev, path_st.st_dev);
  EXPECT_EQ(ASSERT_NO_ERRNO_AND_VALUE(GetContents(newpath)), data);

  // Now that it has a name, the file can be linked again like any other.
  const std::string newpath2 = NewTempAbsPathInDir(dir());
  ASSERT_THAT(link(newpath.c_str(), newpath2.c_str()), SyscallSucceeds());
  ASSERT_THAT(fstat(fd.get(), &fd_st), SyscallSucceeds());
  EXPECT_EQ(fd_st.st_nlink, 2u);
}

TEST_P(TmpfileTest, LinkWithEmptyPath) {
  if (!IsRunningOnGvisor()) {
    // Before Linux 6.10, linkat(AT_EMPTY_PATH) requires CAP_DAC_READ_SEARCH.
    const KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if (version.major < 6 || (version.major == 6 && version.minor < 10)) {
      SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_DAC_READ_SEARCH)));
    }
  }

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0600));
  const std::string newpath = NewTempAbsPathInDir(dir());
  ASSERT_THAT(linkat(fd.get(), "", AT_FDCWD, newpath.c_str(), AT_EMPTY_PATH),
              SyscallSucceeds());

  struct stat fd_st;
  struct stat path_st;
  ASSERT_THAT(fstat(fd.get(), &fd_st), SyscallSucceeds());
  ASSERT_THAT(stat(newpath.c_str(), &path_st), SyscallSucceeds());
  EXPECT_EQ(fd_st.st_nlink, 1u);
  EXPECT_EQ(fd_st.st_ino, path_st.st_ino);
}

TEST_P(TmpfileTest, ExclIsNotLinkable) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR | O_EXCL, 0600));
  const std::string newpath = NewTempAbsPathInDir(dir());
  EXPECT_THAT(LinkViaProcSelfFd(fd.get(), newpath),
              SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(access(newpath.c_str(), F_OK), SyscallFailsWithErrno(ENOENT));
}

// Linux's d_tmpfile() names the dentry after its inode number and keeps the
// directory as its parent, so d_path() shows it as a deleted child.
TEST_P(TmpfileTest, ProcSelfFdShowsDeleted) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0600));
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  const std::string target = ASSERT_NO_ERRNO_AND_VALUE(
      ReadLink(absl::StrCat("/proc/self/fd/", fd.get())));
  EXPECT_EQ(target, absl::StrCat(dir(), "/#", st.st_ino, " (deleted)"));
}

// Scoped resolution only constrains the lookup of the directory; the unnamed
// file created in it is beneath it.
TEST_P(TmpfileTest, ScopedOpen) {
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir(), O_RDONLY | O_DIRECTORY));
  for (const uint64_t resolve : {RESOLVE_BENEATH, RESOLVE_IN_ROOT}) {
    SCOPED_TRACE(absl::StrCat("resolve=", resolve));
    struct open_how how = {
        .flags = O_TMPFILE | O_RDWR,
        .mode = 0600,
        .resolve = resolve,
    };
    const int rawfd =
        syscall(SYS_openat2, dirfd.get(), ".", &how, sizeof(how));
    if (rawfd < 0 && errno == ENOSYS) {
      GTEST_SKIP() << "openat2(2) is not supported";
    }
    ASSERT_THAT(rawfd, SyscallSucceeds());
    const FileDescriptor fd(rawfd);
    struct stat st;
    ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
    EXPECT_TRUE(S_ISREG(st.st_mode));
    EXPECT_EQ(st.st_nlink, 0u);
  }
}

// Reads every event queued on a non-blocking inotify fd as (mask, name).
std::vector<std::pair<uint32_t, std::string>> ReadInotifyEvents(int fd) {
  std::vector<std::pair<uint32_t, std::string>> events;
  alignas(struct inotify_event) char buf[4096];
  ssize_t len;
  while ((len = read(fd, buf, sizeof(buf))) > 0) {
    for (const char* p = buf; p < buf + len;) {
      const auto* ev = reinterpret_cast<const struct inotify_event*>(p);
      events.emplace_back(ev->mask, ev->len > 0 ? std::string(ev->name) : "");
      p += sizeof(*ev) + ev->len;
    }
  }
  return events;
}

// A watch on the directory sees the unnamed file as a child named after its
// inode number, as it does on Linux.
TEST_P(TmpfileTest, InotifyParentEvents) {
  const FileDescriptor inotify(inotify_init1(IN_NONBLOCK));
  ASSERT_THAT(inotify.get(), SyscallSucceeds());
  ASSERT_THAT(inotify_add_watch(inotify.get(), dir().c_str(), IN_ALL_EVENTS),
              SyscallSucceeds());

  struct stat st;
  {
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(OpenTmpfile(O_RDWR, 0600));
    ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
    ASSERT_THAT(write(fd.get(), "x", 1), SyscallSucceedsWithValue(1));
  }

  const std::string name = absl::StrCat("#", st.st_ino);
  const std::vector<std::pair<uint32_t, std::string>> want = {
      {IN_OPEN, name}, {IN_MODIFY, name}, {IN_CLOSE_WRITE, name}};
  EXPECT_EQ(ReadInotifyEvents(inotify.get()), want);
}

INSTANTIATE_TEST_SUITE_P(Locations, TmpfileTest,
                         ::testing::Values(Location::kTestTmpdir,
                                           Location::kTmpfsMount));

// On overlay, the directory may exist only on the lower layer, in which case
// it must be copied up before the file can be created on the upper layer.
// Under the test runner's overlay configuration, any directory from the rootfs
// that this test binary has not written to is such a directory.
TEST(TmpfileOverlayTest, LowerLayerDirectory) {
  constexpr char kDir[] = "/usr";
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(kDir)));
  SKIP_IF(access(kDir, W_OK) != 0);

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(kDir, O_TMPFILE | O_RDWR, 0600));
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st.st_mode));
  EXPECT_EQ(st.st_nlink, 0u);

  const std::string data = "lower";
  ASSERT_THAT(pwrite(fd.get(), data.data(), data.size(), 0),
              SyscallSucceedsWithValue(data.size()));
  char buf[16] = {};
  ASSERT_THAT(pread(fd.get(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(std::string(buf, data.size()), data);
}

// The unnamed file keeps its directory alive only for as long as it is open,
// as in Linux, even once it has been linked elsewhere: the directory's inode
// must be released when the last FD on the unnamed file is closed, not when
// the linked file is finally removed.
TEST(TmpfileTmpfsTest, LinkedFileDoesNotPinDirectory) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const TempPath mnt = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // Room for the root, one directory and one file.
  const Cleanup cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", mnt.path(), "tmpfs", 0, "mode=0777,nr_inodes=3", 0));

  const std::string origin = JoinPath(mnt.path(), "origin");
  ASSERT_THAT(mkdir(origin.c_str(), 0777), SyscallSucceeds());
  const std::string published = JoinPath(mnt.path(), "published");
  {
    const FileDescriptor fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(origin, O_TMPFILE | O_RDWR, 0600));
    ASSERT_THAT(LinkViaProcSelfFd(fd.get(), published), SyscallSucceeds());
  }
  ASSERT_THAT(rmdir(origin.c_str()), SyscallSucceeds());

  // Removing origin freed its inode, so another file fits.
  const std::string extra = JoinPath(mnt.path(), "extra");
  const FileDescriptor extra_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(extra, O_CREAT | O_RDWR, 0600));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
