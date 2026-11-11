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
#include <linux/limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <set>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::UnorderedElementsAreArray;

constexpr char kTmpfs[] = "tmpfs";

// Returns ",userxattr" when writing trusted.* xattrs is not permitted on dir
// (such as inside an unprivileged user namespace on Linux), and "" otherwise so
// tmpfs overlays also work on Linux < 6.6 in the initial user namespace.
std::string OverlayXattrOpt(const std::string& dir) {
  if (removexattr(dir.c_str(), "trusted.overlay.opaque") < 0 &&
      errno == EPERM) {
    return ",userxattr";
  }
  return "";
}

// Returns true when dir's filesystem supports the xattr namespace needed for a
// writable overlay upper layer (for example, Linux tmpfs before 6.6 rejects
// user.* xattrs with EOPNOTSUPP inside an unprivileged user namespace).
bool SupportsOverlayUpperXattrs(const std::string& dir) {
  if (OverlayXattrOpt(dir).empty()) {
    return true;
  }
  return !(removexattr(dir.c_str(), "user.overlay.opaque") < 0 &&
           errno == EOPNOTSUPP);
}

// OverlayOnTmpfs is a tmpfs mount holding lower, upper, work, and merged
// directories. MountOverlay mounts an overlay of lower and upper at merged.
struct OverlayOnTmpfs {
  TempPath base;
  Cleanup tmpfs_mount;
  std::string lower;
  std::string upper;
  std::string work;
  std::string merged;
  Cleanup overlay_mount;

  std::string LowerPath(absl::string_view rel) const {
    return JoinPath(lower, rel);
  }
  std::string UpperPath(absl::string_view rel) const {
    return JoinPath(upper, rel);
  }
  std::string MergedPath(absl::string_view rel) const {
    return JoinPath(merged, rel);
  }

  PosixError MountOverlay(uint64_t mountflags = 0) {
    std::string opts = absl::StrCat("lowerdir=", lower, ",upperdir=", upper,
                                    ",workdir=", work, OverlayXattrOpt(upper));
    ASSIGN_OR_RETURN_ERRNO(overlay_mount, Mount("overlay", merged, "overlay",
                                                mountflags, opts, MNT_DETACH));
    return NoError();
  }
};

// CreateOverlayOnTmpfs mounts a tmpfs and creates the overlay directories in
// it. The overlay itself is not mounted yet, so that the caller can populate
// lower and upper first.
PosixErrorOr<OverlayOnTmpfs> CreateOverlayOnTmpfs(
    absl::string_view parent = "") {
  OverlayOnTmpfs o;
  if (parent.empty()) {
    ASSIGN_OR_RETURN_ERRNO(o.base, TempPath::CreateDir());
  } else {
    ASSIGN_OR_RETURN_ERRNO(o.base, TempPath::CreateDirIn(parent));
  }
  ASSIGN_OR_RETURN_ERRNO(
      o.tmpfs_mount, Mount(kTmpfs, o.base.path(), kTmpfs, 0, "", MNT_DETACH));
  o.lower = JoinPath(o.base.path(), "lower");
  o.upper = JoinPath(o.base.path(), "upper");
  o.work = JoinPath(o.base.path(), "work");
  o.merged = JoinPath(o.base.path(), "merged");
  for (const std::string* dir : {&o.lower, &o.upper, &o.work, &o.merged}) {
    if (mkdir(dir->c_str(), 0755) != 0) {
      return PosixError(errno, absl::StrCat("mkdir ", *dir));
    }
  }
  return o;
}

// Base fixture that requires CAP_SYS_ADMIN and prepares an unmounted
// OverlayOnTmpfs so tests can populate lower/upper layers before mounting.
class OverlayOnTmpfsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    o_ = ASSERT_NO_ERRNO_AND_VALUE(CreateOverlayOnTmpfs(ParentDir()));
    SKIP_IF(!SupportsOverlayUpperXattrs(o_.upper));
  }

  virtual absl::string_view ParentDir() const { return ""; }

  std::string LowerPath(absl::string_view rel) const {
    return o_.LowerPath(rel);
  }
  std::string UpperPath(absl::string_view rel) const {
    return o_.UpperPath(rel);
  }
  std::string MergedPath(absl::string_view rel) const {
    return o_.MergedPath(rel);
  }
  PosixError MountOverlay(uint64_t mountflags = 0) {
    return o_.MountOverlay(mountflags);
  }

  OverlayOnTmpfs o_;
};

// Returns true if path is an overlay whiteout character device (0:0).
PosixErrorOr<bool> IsWhiteout(const std::string& path) {
  struct stat st;
  if (lstat(path.c_str(), &st) != 0) {
    if (errno == ENOENT) {
      return false;
    }
    return PosixError(errno, absl::StrCat("lstat ", path));
  }
  return S_ISCHR(st.st_mode) && major(st.st_rdev) == 0 &&
         minor(st.st_rdev) == 0;
}

// Builds a sockaddr_un for path, returning ENAMETOOLONG if it exceeds sun_path.
PosixErrorOr<struct sockaddr_un> MakeUnixAddr(absl::string_view path) {
  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    return PosixError(ENAMETOOLONG,
                      absl::StrCat("UNIX socket path too long: ", path));
  }
  memcpy(addr.sun_path, path.data(), path.size());
  return addr;
}

// RecursivelyCollectSubPaths collects all directory entries recursively under
// dir, stripping prefix from collected paths before inserting into paths.
PosixError RecursivelyCollectSubPaths(absl::string_view prefix,
                                      absl::string_view dir,
                                      std::set<std::string>* paths) {
  ASSIGN_OR_RETURN_ERRNO(auto contents, ListDir(dir, true));
  for (const std::string& child : contents) {
    const std::string path = JoinPath(dir, child);
    paths->insert(std::string(absl::StripPrefix(path, prefix)));
    ASSIGN_OR_RETURN_ERRNO(struct stat st, Lstat(path));
    if (S_ISDIR(st.st_mode)) {
      RETURN_IF_ERRNO(RecursivelyCollectSubPaths(prefix, path, paths));
    }
  }
  return NoError();
}

// OpenDeletedOverlayDirWithLowerFile creates dir/file on the lower layer of
// o, which must not be mounted yet, and mounts the overlay. It then removes
// dir through the overlay while holding an FD to it, and returns the FD.
// Removing dir deletes its upper copy, which makes dir/file from the lower
// layer visible again through the deleted overlay directory.
PosixErrorOr<FileDescriptor> OpenDeletedOverlayDirWithLowerFile(
    OverlayOnTmpfs& o) {
  if (mkdir(o.LowerPath("dir").c_str(), 0755) != 0) {
    return PosixError(errno, "mkdir lower/dir");
  }
  if (PosixError err = CreateWithContents(o.LowerPath("dir/file"), "");
      !err.ok()) {
    return err;
  }
  if (PosixError err = o.MountOverlay(); !err.ok()) {
    return err;
  }

  const std::string dir = o.MergedPath("dir");
  FileDescriptor dirfd;
  ASSIGN_OR_RETURN_ERRNO(dirfd, Open(dir, O_RDONLY | O_DIRECTORY));
  if (unlink(JoinPath(dir, "file").c_str()) != 0) {
    return PosixError(errno, "unlink merged/dir/file");
  }
  if (rmdir(dir.c_str()) != 0) {
    return PosixError(errno, "rmdir merged/dir");
  }
  return dirfd;
}

// ============================================================================
// Mount lock and namespace restriction tests
// ============================================================================

// Linux's clone_private_mount() refuses an overlay layer that has a locked
// mount at or below it, or whose mount is in another mount namespace. See
// https://github.com/torvalds/linux/commit/427215d85e8d, which first
// appears in Linux 5.14.
class OverlayLockedMountTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    if (!IsRunningOnGvisor()) {
      auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
      SKIP_IF(version.major < 5 || (version.major == 5 && version.minor < 14));
    }
    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    dir_mount_ = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("", dir_.path(), kTmpfs, 0, "", MNT_DETACH));
    merged_ = SubPath("merged");
    ASSERT_THAT(mkdir(merged_.c_str(), 0755), SyscallSucceeds());
  }

  std::string SubPath(absl::string_view rel) const {
    return JoinPath(dir_.path(), rel);
  }

  void Mkdirs(std::initializer_list<std::string> paths) {
    for (const std::string& path : paths) {
      ASSERT_THAT(mkdir(path.c_str(), 0755), SyscallSucceeds());
    }
  }

  TempPath dir_;
  Cleanup dir_mount_;
  std::string merged_;
};

TEST_F(OverlayLockedMountTest, LockedMountStopsOverlayLowerdir) {
  const std::string layer = SubPath("layer");
  const std::string hidden = JoinPath(layer, "hidden");
  const std::string other = SubPath("other");
  Mkdirs({layer, hidden, other});
  if (HasFatalFailure()) {
    return;
  }
  const Cleanup hidden_mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", hidden, kTmpfs, 0, "", MNT_DETACH));
  const std::string refused_opts = absl::StrCat("lowerdir=", layer, ":", other);
  const std::string admitted_opts =
      absl::StrCat("lowerdir=", hidden, ":", other);

  const std::function<void()> child = [&] {
    TEST_CHECK_ERRNO(
        mount("overlay", merged_.c_str(), "overlay", 0, refused_opts.c_str()),
        EINVAL);
    TEST_CHECK_SUCCESS(
        mount("overlay", merged_.c_str(), "overlay", 0, admitted_opts.c_str()));
    TEST_CHECK_SUCCESS(umount2(merged_.c_str(), 0));
  };
  EXPECT_THAT(InForkedUserMountNamespace([] {}, child),
              IsPosixErrorOkAndHolds(0));
}

TEST_F(OverlayLockedMountTest, LockedMountStopsOverlayUpperdir) {
  const std::string lower = SubPath("lower");
  const std::string upper = SubPath("upper");
  const std::string hidden = JoinPath(upper, "hidden");
  const std::string work = SubPath("work");
  Mkdirs({lower, upper, hidden, work});
  if (HasFatalFailure()) {
    return;
  }
  SKIP_IF(removexattr(upper.c_str(), "user.overlay.opaque") < 0 &&
          errno == EOPNOTSUPP);
  const Cleanup hidden_mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", hidden, kTmpfs, 0, "", MNT_DETACH));
  const std::string opts = absl::StrCat("lowerdir=", lower, ",upperdir=", upper,
                                        ",workdir=", work, ",userxattr");

  const std::function<void()> child = [&] {
    TEST_CHECK_ERRNO(
        mount("overlay", merged_.c_str(), "overlay", 0, opts.c_str()), EINVAL);
  };
  EXPECT_THAT(InForkedUserMountNamespace([] {}, child),
              IsPosixErrorOkAndHolds(0));
}

TEST_F(OverlayLockedMountTest, LockedMountStopsOverlayOfSysfs) {
  const std::string sys = SubPath("sys");
  const std::string other = SubPath("other");
  Mkdirs({sys, other});
  if (HasFatalFailure()) {
    return;
  }
  uint64_t sys_flags = 0;
  if (!ASSERT_NO_ERRNO_AND_VALUE(InInitialUserNamespace())) {
    // Preserve locked mount flags from /sys so Linux's mount_too_revealing()
    // permits mounting sysfs in a non-initial user namespace.
    sys_flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    struct statvfs st;
    if (statvfs("/sys", &st) == 0) {
      if ((st.f_flag & ST_RDONLY) != 0) {
        sys_flags |= MS_RDONLY;
      }
      if ((st.f_flag & ST_NOATIME) != 0) {
        sys_flags |= MS_NOATIME;
      } else if ((st.f_flag & ST_RELATIME) != 0) {
        sys_flags |= MS_RELATIME;
      } else {
        sys_flags |= MS_STRICTATIME;
      }
    }
  }
  PosixErrorOr<Cleanup> sys_mount =
      Mount("sysfs", sys, "sysfs", sys_flags, "", MNT_DETACH);
  // Skip on native Linux when /sys has locked submounts over non-empty
  // directories and mount_too_revealing() rejects unprivileged sysfs mounts.
  SKIP_IF(!IsRunningOnGvisor() && !sys_mount.ok() &&
          sys_mount.error().errno_value() == EPERM);
  ASSERT_NO_ERRNO(sys_mount);
  const Cleanup kernel_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("", JoinPath(sys, "kernel"), kTmpfs, 0, "", MNT_DETACH));
  const std::string opts = absl::StrCat("lowerdir=", sys, ":", other);

  const std::function<void()> child = [&] {
    TEST_CHECK_ERRNO(
        mount("overlay", merged_.c_str(), "overlay", 0, opts.c_str()), EINVAL);
  };
  EXPECT_THAT(InForkedUserMountNamespace([] {}, child),
              IsPosixErrorOkAndHolds(0));
}

TEST_F(OverlayLockedMountTest, RefusesLayerFromAnotherMountNamespace) {
  const std::string layer = SubPath("layer");
  const std::string other = SubPath("other");
  Mkdirs({layer, other});
  if (HasFatalFailure()) {
    return;
  }
  const FileDescriptor layer_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(layer, O_RDONLY | O_DIRECTORY));
  const std::string opts =
      absl::StrCat("lowerdir=/proc/self/fd/", layer_fd.get(), ":", other);

  const std::function<void()> child = [&] {
    TEST_CHECK_ERRNO(
        mount("overlay", merged_.c_str(), "overlay", 0, opts.c_str()), EINVAL);
  };
  EXPECT_THAT(InForkedUserMountNamespace([] {}, child),
              IsPosixErrorOkAndHolds(0));
}

// ============================================================================
// Standalone mount topology and capability tests
// ============================================================================

TEST(OverlayTest, SgidBitIsCopiedUp) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto base_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // Overlayfs cannot be used as upper layer for another overlayfs mount. If
  // running in overlayfs, create a tmpfs mount to use as the upper layer.
  //
  // In Linux, mounting overlayfs in a user namespace can fail with
  // EACCES when the layers are on TEST_TMPDIR's filesystem.
  bool in_overlayfs = ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(base_dir.path()));
  bool use_tmpfs = in_overlayfs || GvisorPlatform() == Platform::kNative;
  if (use_tmpfs) {
    ASSERT_THAT(mount(kTmpfs, base_dir.path().c_str(), kTmpfs, 0, "mode=1777"),
                SyscallSucceeds());
  }
  auto tmpfs_cleanup = Cleanup([&base_dir, use_tmpfs] {
    if (use_tmpfs) {
      ASSERT_THAT(umount2(base_dir.path().c_str(), MNT_DETACH),
                  SyscallSucceeds());
    }
  });

  // Create the files under test in `lower` and set the S_ISGID bit on them.
  auto lower =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  struct FileUT {
    absl::string_view name;
    void (*create)(const std::string& path);
  };
  static constexpr std::array kFilesUnderTest = {
      FileUT{"setgid_dir",
             [](const std::string& path) {
               ASSERT_THAT(mkdir(path.c_str(), 0755), SyscallSucceeds());
             }},
      FileUT{"setgid_empty_file",
             [](const std::string& path) {
               ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_CREAT | O_RDWR, 0755));
             }},
      FileUT{"setgid_nonempty_file",
             [](const std::string& path) {
               ASSERT_NO_ERRNO(CreateWithContents(path, "junk", 0755));
             }},
  };
  for (const auto& file_ut : kFilesUnderTest) {
    std::string lower_target = JoinPath(lower.path(), file_ut.name);
    file_ut.create(lower_target);

    struct stat st_lower;
    ASSERT_THAT(stat(lower_target.c_str(), &st_lower), SyscallSucceeds());
    ASSERT_THAT(chmod(lower_target.c_str(), st_lower.st_mode | S_ISGID),
                SyscallSucceeds());
    ASSERT_THAT(stat(lower_target.c_str(), &st_lower), SyscallSucceeds());
    ASSERT_TRUE(st_lower.st_mode & S_ISGID);
  }

  auto upper =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  SKIP_IF(!SupportsOverlayUpperXattrs(upper.path()));
  auto work = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto merged =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  std::string opts =
      absl::StrCat("lowerdir=", lower.path(), ",upperdir=", upper.path(),
                   ",workdir=", work.path(), OverlayXattrOpt(upper.path()));
  Cleanup overlay_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("overlay", merged.path(), "overlay", 0, opts, MNT_DETACH));

  for (const auto& file_ut : kFilesUnderTest) {
    SCOPED_TRACE(file_ut.name);

    // The S_ISGID bit is visible before any copy-up took place.
    std::string merged_target = JoinPath(merged.path(), file_ut.name);
    struct stat st_merged;
    ASSERT_THAT(stat(merged_target.c_str(), &st_merged), SyscallSucceeds());
    ASSERT_TRUE(st_merged.st_mode & S_ISGID);

    // Touch the target to force a copy-up to `upper`.
    ASSERT_THAT(utimensat(AT_FDCWD, merged_target.c_str(), nullptr, 0),
                SyscallSucceeds());

    // The S_ISGID bit must also be copied up.
    std::string upper_target = JoinPath(upper.path(), file_ut.name);
    struct stat upper_st_after_touch;
    ASSERT_THAT(stat(upper_target.c_str(), &upper_st_after_touch),
                SyscallSucceeds());
    EXPECT_TRUE(upper_st_after_touch.st_mode & S_ISGID);
    struct stat merged_st_after_touch;
    ASSERT_THAT(stat(merged_target.c_str(), &merged_st_after_touch),
                SyscallSucceeds());
    EXPECT_TRUE(merged_st_after_touch.st_mode & S_ISGID);
  }
}

// Renaming a directory on an overlay inside a user namespace requires
// user.overlay.* xattrs to mark the directory opaque.
TEST(OverlayTest, DirectoryRenameInUserNamespace) {
  // Test fails in gVisor running on <6.0 due to fsgofer getting permission
  // errors on `mknod`.
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(GetHostKernelVersion()).major < 6);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  auto base_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  bool in_overlayfs = ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(base_dir.path()));
  // Before Linux 6.6, tmpfs doesn't support the user.* xattrs needed.
  KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
  bool use_tmpfs =
      in_overlayfs ||
      (GvisorPlatform() == Platform::kNative &&
       (version.major > 6 || (version.major == 6 && version.minor >= 6)));

  const std::function<void()> parent = [] {};
  const std::function<void()> child = [&base_dir, use_tmpfs] {
    // Overlayfs cannot be used as upper layer for another overlayfs mount. If
    // running in overlayfs or on Linux 6.6 or later, create a tmpfs mount to
    // use as the upper layer.
    if (use_tmpfs) {
      TEST_CHECK_SUCCESS(mount(kTmpfs, base_dir.path().c_str(), kTmpfs, 0,
                               "mode=1777,size=10m"));
    }
    auto tmpfs_cleanup = Cleanup([&base_dir, use_tmpfs] {
      if (use_tmpfs) {
        TEST_CHECK_SUCCESS(umount2(base_dir.path().c_str(), 0));
      }
    });

    auto lower = JoinPath(base_dir.path(), "lower");
    auto upper = JoinPath(base_dir.path(), "upper");
    auto work = JoinPath(base_dir.path(), "work");
    auto merged = JoinPath(base_dir.path(), "merged");
    for (const std::string* dir : {&lower, &upper, &work, &merged}) {
      TEST_CHECK_SUCCESS(mkdir(dir->c_str(), 0755));
    }

    // 1. Create the destination directory in lower (empty so POSIX rename
    // allows overwriting it).
    TEST_CHECK_SUCCESS(mkdir(JoinPath(lower, "renamed").c_str(), 0755));

    std::string opts = absl::StrCat("lowerdir=", lower, ",upperdir=", upper,
                                    ",workdir=", work, ",userxattr");
    TEST_CHECK_SUCCESS(
        mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()));
    auto overlayfs_cleanup =
        Cleanup([&merged] { TEST_CHECK_SUCCESS(umount2(merged.c_str(), 0)); });

    // 2. Create a pure-upper source directory directly in merged.
    auto mydir = JoinPath(merged, "mydir");
    TEST_CHECK_SUCCESS(mkdir(mydir.c_str(), 0755));

    int fd =
        open(JoinPath(mydir, "file.txt").c_str(), O_WRONLY | O_CREAT, 0644);
    TEST_CHECK(fd >= 0);
    TEST_CHECK_SUCCESS(close(fd));

    // 3. Rename the pure-upper directory over the existing lower directory.
    // This forces the kernel to apply user.overlay.opaque="y" to 'renamed' so
    // that 'lower/renamed' is hidden.
    auto renamed = JoinPath(merged, "renamed");
    TEST_CHECK_SUCCESS(rename(mydir.c_str(), renamed.c_str()));

    // 4. Verify the rename succeeded and contents are intact.
    struct stat st;
    TEST_CHECK_SUCCESS(stat(renamed.c_str(), &st));
    TEST_CHECK(S_ISDIR(st.st_mode));
    TEST_CHECK(stat(mydir.c_str(), &st) == -1 && errno == ENOENT);
    TEST_CHECK_SUCCESS(stat(JoinPath(renamed, "file.txt").c_str(), &st));
    TEST_CHECK(S_ISREG(st.st_mode));
  };

  EXPECT_THAT(InForkedUserMountNamespace(parent, child),
              IsPosixErrorOkAndHolds(0));
}

// Tests that overlay can be mounted with a gofer upper layer and confirms basic
// overlayfs operations.
TEST(OverlayTest, OnGoferBehavior) {
  // Test fails in gVisor running on <6.0 due to fsgofer getting permission
  // errors on `mknod`.
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(GetHostKernelVersion()).major < 6);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto base_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsGoferfs(base_dir.path())));

  auto lower =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto upper =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto work = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto merged =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));

  const std::string kTestFile = "testfile";
  const std::string kTestFileContent = "lower_content";
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(lower.path(), kTestFile),
                                     kTestFileContent, 0644));
  const std::string kTestDirName = "testdir";
  ASSERT_THAT(mkdir(JoinPath(lower.path(), kTestDirName).c_str(), 0755),
              SyscallSucceeds());
  const std::string kCopyUpFile = "copyupfile";
  std::string lower_copyup_file = JoinPath(lower.path(), kCopyUpFile);
  ASSERT_NO_ERRNO(CreateWithContents(lower_copyup_file, "initial", 0644));
  bool xattr_supported = true;
  if (setxattr(lower_copyup_file.c_str(), "user.test", "value", 5, 0) < 0) {
    if (errno == EOPNOTSUPP) {
      xattr_supported = false;
    } else {
      ASSERT_NO_ERRNO(PosixError(errno, "setxattr failed"));
    }
  }

  std::string opts =
      absl::StrCat("lowerdir=", lower.path(), ",upperdir=", upper.path(),
                   ",workdir=", work.path(), ",userxattr");
  Cleanup overlay_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("overlay", merged.path(), "overlay", 0, opts, 0));

  std::string merged_file = JoinPath(merged.path(), kTestFile);
  EXPECT_THAT(GetContents(merged_file),
              IsPosixErrorOkAndHolds(kTestFileContent));

  const std::string kNewFile = "newfile";
  const std::string kNewFileContent = "new";
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(merged.path(), kNewFile),
                                     kNewFileContent, 0644));
  EXPECT_THAT(GetContents(JoinPath(upper.path(), kNewFile)),
              IsPosixErrorOkAndHolds(kNewFileContent));

  ASSERT_THAT(unlink(merged_file.c_str()), SyscallSucceeds());
  EXPECT_THAT(IsWhiteout(JoinPath(upper.path(), kTestFile)),
              IsPosixErrorOkAndHolds(true));

  std::string merged_dir = JoinPath(merged.path(), kTestDirName);
  ASSERT_THAT(rmdir(merged_dir.c_str()), SyscallSucceeds());
  ASSERT_THAT(mkdir(merged_dir.c_str(), 0755), SyscallSucceeds());

  std::string upper_dir = JoinPath(upper.path(), kTestDirName);
  char opaque_buf[16] = {};
  ASSERT_THAT(getxattr(upper_dir.c_str(), "user.overlay.opaque", opaque_buf,
                       sizeof(opaque_buf)),
              SyscallSucceeds());
  EXPECT_EQ(opaque_buf[0], 'y');

  std::string merged_copyup_file = JoinPath(merged.path(), kCopyUpFile);
  ASSERT_NO_ERRNO(SetContents(merged_copyup_file, "modified"));
  if (xattr_supported) {
    char xattr_buf[16] = {};
    ASSERT_THAT(getxattr(merged_copyup_file.c_str(), "user.test", xattr_buf,
                         sizeof(xattr_buf)),
                SyscallSucceeds());
    EXPECT_STREQ(xattr_buf, "value");
  }
}

// Files across layers of a nested overlay have distinct (st_dev, st_ino) pairs.
TEST(OverlayTest, NestedDeviceInodeNumberUniqueness) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  OverlayOnTmpfs inner = ASSERT_NO_ERRNO_AND_VALUE(CreateOverlayOnTmpfs());
  SKIP_IF(!SupportsOverlayUpperXattrs(inner.upper));
  const std::string outer_upper = JoinPath(inner.base.path(), "outer_upper");
  const std::string outer_work = JoinPath(inner.base.path(), "outer_work");
  const std::string outer_merged = JoinPath(inner.base.path(), "outer_merged");
  for (const std::string& dir : {outer_upper, outer_work, outer_merged}) {
    ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  }

  constexpr char kUpperFile[] = "upper";
  constexpr char kLowerFile1[] = "lower1";
  constexpr char kLowerFile2[] = "lower2";
  ASSERT_THAT(
      mknod(JoinPath(outer_upper, kUpperFile).c_str(), S_IFREG | 0644, 0),
      SyscallSucceeds());
  ASSERT_THAT(mknod(inner.UpperPath(kLowerFile1).c_str(), S_IFREG | 0644, 0),
              SyscallSucceeds());
  ASSERT_THAT(mknod(inner.LowerPath(kLowerFile2).c_str(), S_IFREG | 0644, 0),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(inner.MountOverlay());
  Cleanup outer_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("overlay", outer_merged, "overlay", 0,
            absl::StrCat("lowerdir=", inner.merged, ",upperdir=", outer_upper,
                         ",workdir=", outer_work, OverlayXattrOpt(outer_upper)),
            MNT_DETACH));

  auto ovl_upper_stat =
      ASSERT_NO_ERRNO_AND_VALUE(Stat(JoinPath(outer_merged, kUpperFile)));
  auto ovl_lower1_stat =
      ASSERT_NO_ERRNO_AND_VALUE(Stat(JoinPath(outer_merged, kLowerFile1)));
  auto ovl_lower2_stat =
      ASSERT_NO_ERRNO_AND_VALUE(Stat(JoinPath(outer_merged, kLowerFile2)));
  EXPECT_FALSE(ovl_upper_stat.st_dev == ovl_lower1_stat.st_dev &&
               ovl_upper_stat.st_ino == ovl_lower1_stat.st_ino)
      << "files " << kUpperFile << " and " << kLowerFile1
      << " both have device number " << ovl_upper_stat.st_dev
      << " and inode number " << ovl_upper_stat.st_ino;
  EXPECT_FALSE(ovl_upper_stat.st_dev == ovl_lower2_stat.st_dev &&
               ovl_upper_stat.st_ino == ovl_lower2_stat.st_ino)
      << "files " << kUpperFile << " and " << kLowerFile2
      << " both have device number " << ovl_upper_stat.st_dev
      << " and inode number " << ovl_upper_stat.st_ino;
  EXPECT_FALSE(ovl_lower1_stat.st_dev == ovl_lower2_stat.st_dev &&
               ovl_lower1_stat.st_ino == ovl_lower2_stat.st_ino)
      << "files " << kLowerFile1 << " and " << kLowerFile2
      << " both have device number " << ovl_lower1_stat.st_dev
      << " and inode number " << ovl_lower2_stat.st_ino;
}

// Linux resolves relative pathnames in overlayfs mount options against the
// working directory of the mounting process.
TEST(OverlayTest, RelativePaths) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto base_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Cleanup tmpfs_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(kTmpfs, base_dir.path(), kTmpfs, 0, "mode=1777", MNT_DETACH));

  // Fixed names, so that the mount options below can name them relatively.
  // "sub" is the directory the mount is performed from; it is deliberately not
  // the parent of the mount target, so that resolving against the working
  // directory is distinguishable from resolving against the target's parent.
  for (const char* name : {"l0", "l1", "u", "w", "m", "sub"}) {
    ASSERT_THAT(mkdir(JoinPath(base_dir.path(), name).c_str(), 0755),
                SyscallSucceeds());
  }
  const std::string upper_dir = JoinPath(base_dir.path(), "u");
  SKIP_IF(!SupportsOverlayUpperXattrs(upper_dir));
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(base_dir.path(), "l0", "from_l0"),
                                     "l0", 0644));
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(base_dir.path(), "l1", "from_l1"),
                                     "l1", 0644));

  const std::string old_cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
  ASSERT_THAT(chdir(JoinPath(base_dir.path(), "sub").c_str()),
              SyscallSucceeds());
  auto cwd_cleanup = Cleanup(
      [&old_cwd] { EXPECT_THAT(chdir(old_cwd.c_str()), SyscallSucceeds()); });

  // Only the pathnames inside the option string are relative. They traverse
  // "..", which resolves correctly only if the working directory is the
  // starting point.
  const std::string merged = JoinPath(base_dir.path(), "m");
  const std::string opts =
      absl::StrCat("lowerdir=../l0:../l1,upperdir=../u,workdir=../w",
                   OverlayXattrOpt(upper_dir));
  Cleanup overlay_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("overlay", merged, "overlay", 0, opts, MNT_DETACH));

  // Both lower layers resolved, so both are visible through the merged dir.
  EXPECT_THAT(GetContents(JoinPath(merged, "from_l0")),
              IsPosixErrorOkAndHolds("l0"));
  EXPECT_THAT(GetContents(JoinPath(merged, "from_l1")),
              IsPosixErrorOkAndHolds("l1"));

  // The workdir resolved: overlayfs created its "work" directory inside it.
  // A failed MkdirAt on workdir is only logged, so without this the mount
  // succeeds even when workdir resolved somewhere else.
  struct stat work_st;
  ASSERT_THAT(stat(JoinPath(base_dir.path(), "w", "work").c_str(), &work_st),
              SyscallSucceeds());

  // The upper layer resolved too: a new file lands in it rather than anywhere
  // else.
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(merged, "written"), "up", 0644));
  EXPECT_THAT(GetContents(JoinPath(upper_dir, "written")),
              IsPosixErrorOkAndHolds("up"));
}

TEST(OverlayTest, RejectsEmptyOptions) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  auto base_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Cleanup tmpfs_mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount(kTmpfs, base_dir.path(), kTmpfs, 0, "mode=1777", MNT_DETACH));

  auto lower =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto upper =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto work = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));
  auto merged =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_dir.path()));

  const std::string opts[] = {
      absl::StrCat("lowerdir=,upperdir=", upper.path(),
                   ",workdir=", work.path()),
      absl::StrCat("lowerdir=", lower.path(),
                   ",upperdir=,workdir=", work.path()),
      absl::StrCat("lowerdir=", lower.path(), ",upperdir=", upper.path(),
                   ",workdir="),
  };
  for (const std::string& opt : opts) {
    SCOPED_TRACE(opt);
    EXPECT_THAT(
        mount("overlay", merged.path().c_str(), "overlay", 0, opt.c_str()),
        SyscallFailsWithErrno(EINVAL));
  }
}

// ============================================================================
// Security capability xattr tests
// ============================================================================

struct VfsCapDataV2 {
  uint32_t magic_etc;
  uint32_t permitted_lo;
  uint32_t inheritable_lo;
  uint32_t permitted_hi;
  uint32_t inheritable_hi;
};

class OverlaySecurityCapTest : public OverlayOnTmpfsTest {
 protected:
  void SetUp() override {
    OverlayOnTmpfsTest::SetUp();
    if (IsSkipped() || HasFatalFailure()) {
      return;
    }
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETFCAP)));
    ASSERT_NO_ERRNO(MountOverlay());
    cap_data_ = {};
    cap_data_.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE;
    cap_data_.permitted_lo = 1 << CAP_SETUID;
    file_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(o_.merged));
  }

  VfsCapDataV2 cap_data_;
  TempPath file_;
};

TEST_F(OverlaySecurityCapTest, SecurityCapabilityRequiresSetFcap) {
  // Setting security.capability with CAP_SETFCAP should succeed.
  ASSERT_THAT(setxattr(file_.path().c_str(), "security.capability", &cap_data_,
                       sizeof(cap_data_), 0),
              SyscallSucceeds());

  // Setting security.capability without CAP_SETFCAP should fail.
  AutoCapability set_fcap(CAP_SETFCAP, false);
  ASSERT_THAT(setxattr(file_.path().c_str(), "security.capability", &cap_data_,
                       sizeof(cap_data_), 0),
              SyscallFailsWithErrno(EPERM));
}

TEST_F(OverlaySecurityCapTest, SecurityCapabilityTranslatesRootID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));

  ASSERT_THAT(setxattr(file_.path().c_str(), "security.capability", &cap_data_,
                       sizeof(cap_data_), 0),
              SyscallSucceeds());

  constexpr uint32_t kChildUID = 1000;
  const uint32_t parent_uid = geteuid();
  const uint32_t parent_gid = getegid();
  EXPECT_THAT(
      InForkedProcess([&] {
        TEST_PCHECK(unshare(CLONE_NEWUSER) == 0);

        int fd = open("/proc/self/uid_map", O_WRONLY);
        TEST_PCHECK(fd >= 0);
        std::string map = absl::StrCat(kChildUID, " ", parent_uid, " 1");
        TEST_PCHECK(write(fd, map.data(), map.size()) ==
                    static_cast<ssize_t>(map.size()));
        TEST_PCHECK(close(fd) == 0);

        // Denying setgroups is a prerequisite for writing gid_map without
        // CAP_SETGID in the parent user namespace.
        int setgroups_fd = open("/proc/self/setgroups", O_WRONLY);
        if (setgroups_fd >= 0) {
          TEST_PCHECK(write(setgroups_fd, "deny", 4) == 4);
          TEST_PCHECK(close(setgroups_fd) == 0);
        }
        int gid_fd = open("/proc/self/gid_map", O_WRONLY);
        if (gid_fd >= 0) {
          std::string gid_map = absl::StrCat(kChildUID, " ", parent_gid, " 1");
          TEST_PCHECK(write(gid_fd, gid_map.data(), gid_map.size()) ==
                      static_cast<ssize_t>(gid_map.size()));
          TEST_PCHECK(close(gid_fd) == 0);
        }

        struct {
          uint32_t magic_etc;
          uint32_t permitted_lo;
          uint32_t inheritable_lo;
          uint32_t permitted_hi;
          uint32_t inheritable_hi;
          uint32_t rootid;
        } cap_data_v3 = {};

        ssize_t ret = getxattr(file_.path().c_str(), "security.capability",
                               &cap_data_v3, sizeof(cap_data_v3));
        TEST_CHECK_SUCCESS(ret);
        TEST_CHECK_MSG(ret == sizeof(cap_data_v3), "wrong size returned");
        TEST_CHECK_MSG((cap_data_v3.magic_etc & VFS_CAP_REVISION_MASK) ==
                           VFS_CAP_REVISION_3,
                       "wrong revision");
        TEST_CHECK_MSG(cap_data_v3.rootid == kChildUID, "wrong rootid");
      }),
      IsPosixErrorOkAndHolds(0));
}

// ============================================================================
// File, mmap, read-only, and socket tests
// ============================================================================

class OverlayFileTest : public OverlayOnTmpfsTest {};

// Opening a regular file in an overlay that exists in both the upper and lower
// filesystems exclusively uses the upper file.
TEST_F(OverlayFileTest, UpperContentIsPreferred) {
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("file"), "upper"));
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  EXPECT_THAT(GetContents(MergedPath("file")), IsPosixErrorOkAndHolds("upper"));
}

// Character device /dev/zero can be memory-mapped through an overlay.
TEST_F(OverlayFileTest, MmapDevZero) {
  int ret =
      mknod(UpperPath("zero_upper").c_str(), S_IFCHR | 0666, makedev(1, 5));
  // CAP_MKNOD is required in the initial user namespace on Linux; native tests
  // running in a user namespace cannot create device nodes.
  SKIP_IF(Value(ret, SyscallFailsWithErrno(EPERM)));
  ASSERT_THAT(ret, SyscallSucceeds());
  ASSERT_THAT(
      mknod(LowerPath("zero_lower").c_str(), S_IFCHR | 0666, makedev(1, 5)),
      SyscallSucceeds());
  ASSERT_NO_ERRNO(MountOverlay());

  FileDescriptor upper_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(MergedPath("zero_upper"), O_RDWR | O_CLOEXEC));
  Mapping const upper_map = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
           upper_fd.get(), 0));

  FileDescriptor lower_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(MergedPath("zero_lower"), O_RDONLY | O_CLOEXEC));
  Mapping const lower_map = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, 2 * kPageSize, PROT_READ, MAP_SHARED, lower_fd.get(), 0));
}

// Opening a lower file writably on a read-only overlay fails with EROFS and
// does not copy up to upper.
TEST_F(OverlayFileTest, ReadonlyOpenDoesNotCopyUp) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "hello"));
  ASSERT_NO_ERRNO(MountOverlay(MS_RDONLY));

  EXPECT_THAT(open(MergedPath("file").c_str(), O_RDWR),
              SyscallFailsWithErrno(EROFS));
  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(false));
}

// Roots the overlay under /tmp so UNIX socket paths fit in sockaddr_un.
class OverlaySocketTest : public OverlayOnTmpfsTest {
 protected:
  absl::string_view ParentDir() const override { return "/tmp"; }
};

// Opening a bound UNIX domain socket in an overlay returns ENXIO per open(2).
TEST_F(OverlaySocketTest, BindSocketThenOpen) {
  ASSERT_NO_ERRNO(MountOverlay());

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  const std::string sock_path = MergedPath("bar");
  struct sockaddr_un addr = ASSERT_NO_ERRNO_AND_VALUE(MakeUnixAddr(sock_path));

  ASSERT_THAT(
      bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());
  EXPECT_THAT(open(sock_path.c_str(), O_WRONLY), SyscallFailsWithErrno(ENXIO));
}

// Connecting through an overlay to a UNIX domain socket bound in the lower
// layer succeeds in gVisor.
TEST_F(OverlaySocketTest, ConnectToSocketInLower) {
  // Linux af_unix keys bound sockets by the underlying inode and returns
  // ECONNREFUSED when connecting via an overlay dentry; gVisor delegates
  // BoundEndpointAt to the lower layer.
  SKIP_IF(!IsRunningOnGvisor());

  FileDescriptor listener =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  struct sockaddr_un bind_addr =
      ASSERT_NO_ERRNO_AND_VALUE(MakeUnixAddr(LowerPath("sock")));
  ASSERT_THAT(
      bind(listener.get(), reinterpret_cast<struct sockaddr*>(&bind_addr),
           sizeof(bind_addr)),
      SyscallSucceeds());
  ASSERT_THAT(listen(listener.get(), 1), SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  struct sockaddr_un conn_addr =
      ASSERT_NO_ERRNO_AND_VALUE(MakeUnixAddr(MergedPath("sock")));
  FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(
      connect(client.get(), reinterpret_cast<struct sockaddr*>(&conn_addr),
              sizeof(conn_addr)),
      SyscallSucceeds());
  FileDescriptor accepted =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listener.get(), nullptr, nullptr));
}

// ============================================================================
// Copy-up tests
// ============================================================================

class OverlayCopyUpTest : public OverlayOnTmpfsTest {};

// Opening a file writable causes it to be copied up.
TEST_F(OverlayCopyUpTest, OpenFile) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "data"));
  ASSERT_NO_ERRNO(MountOverlay());

  FileDescriptor const file =
      ASSERT_NO_ERRNO_AND_VALUE(Open(MergedPath("file"), O_RDWR));
  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(true));
}

// Trying to open a read-only file writably does not cause it to be copied up.
TEST_F(OverlayCopyUpTest, OpenReadOnlyFile) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "", 0444));
  ASSERT_NO_ERRNO(MountOverlay());

  // Drop CAP_DAC_OVERRIDE so file permission bits are enforced.
  AutoCapability cap(CAP_DAC_OVERRIDE, false);
  EXPECT_THAT(Open(MergedPath("file"), O_RDWR), PosixErrorIs(EACCES));
  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(false));
}

// Creating a file causes its parent directory to be copied up.
TEST_F(OverlayCopyUpTest, Create) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  EXPECT_NO_ERRNO(TempPath::CreateFileIn(MergedPath("dir")));
  EXPECT_THAT(Exists(UpperPath("dir")), IsPosixErrorOkAndHolds(true));
}

// Creating a directory causes its parent directory to be copied up.
TEST_F(OverlayCopyUpTest, Mkdir) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  ASSERT_NO_ERRNO(TempPath::CreateDirIn(MergedPath("dir")));
  EXPECT_THAT(Exists(UpperPath("dir")), IsPosixErrorOkAndHolds(true));
}

// Creating a symlink causes its parent directory to be copied up.
TEST_F(OverlayCopyUpTest, Symlink) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string link_path = MergedPath("dir/link");
  ASSERT_THAT(symlink("/dangling", link_path.c_str()), SyscallSucceeds());
  EXPECT_THAT(Exists(UpperPath("dir")), IsPosixErrorOkAndHolds(true));
  ASSERT_THAT(unlink(link_path.c_str()), SyscallSucceeds());
}

// Creating a hardlink causes both its target file and parent directory to be
// copied up.
TEST_F(OverlayCopyUpTest, Link) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "data"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string link_path = MergedPath("dir/link");
  ASSERT_THAT(link(MergedPath("file").c_str(), link_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(UpperPath("dir")), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(true));
  ASSERT_THAT(unlink(link_path.c_str()), SyscallSucceeds());
}

// Creating a FIFO causes its parent directory to be copied up.
TEST_F(OverlayCopyUpTest, Mknod) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  ASSERT_THAT(mknod(MergedPath("dir/fifo").c_str(), S_IFIFO | S_IRUSR, 0),
              SyscallSucceeds());
  EXPECT_THAT(Exists(UpperPath("dir")), IsPosixErrorOkAndHolds(true));
}

// Renaming a file to outside the overlay fails with EXDEV.
TEST_F(OverlayCopyUpTest, RenameDenied) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "data"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string outside_path = JoinPath(o_.base.path(), "outside");
  EXPECT_THAT(rename(MergedPath("file").c_str(), outside_path.c_str()),
              SyscallFailsWithErrno(EXDEV));
}

// Truncating a file causes it to be copied up, even if the size does not
// change.
TEST_F(OverlayCopyUpTest, Truncate) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), ""));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_file = MergedPath("file");
  ASSERT_THAT(truncate(overlay_file.c_str(), 0), SyscallSucceeds());

  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(true));
  auto st = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_file));
  EXPECT_EQ(0, st.st_size);
}

// Changing the permissions of a file causes it to be copied up.
TEST_F(OverlayCopyUpTest, Chmod) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), ""));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(chmod(overlay_path.c_str(), 0111), SyscallSucceeds());

  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(true));
  auto st = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));
  EXPECT_EQ(0111, st.st_mode & 0777);
}

// Changing the owner of a file causes it to be copied up.
TEST_F(OverlayCopyUpTest, Chown) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_CHOWN)));

  constexpr uid_t kUid = 65534;
  constexpr gid_t kGid = 65534;
  // Skip if kUid/kGid are not mapped in the current user namespace.
  const std::string probe_path = JoinPath(o_.base.path(), "probe");
  ASSERT_NO_ERRNO(CreateWithContents(probe_path, ""));
  if (chown(probe_path.c_str(), kUid, kGid) < 0) {
    SKIP_IF(errno == EINVAL);
    FAIL() << "chown(" << probe_path << ") failed with errno " << errno;
  }

  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), ""));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(chown(overlay_path.c_str(), kUid, kGid), SyscallSucceeds());

  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(true));
  auto st = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));
  EXPECT_EQ(kUid, st.st_uid);
  EXPECT_EQ(kGid, st.st_gid);
}

// Changing the timestamps of a file causes it to be copied up.
TEST_F(OverlayCopyUpTest, Utimes) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), ""));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  struct timeval times[2] = {{1, 0}, {2, 0}};
  ASSERT_THAT(utimes(overlay_path.c_str(), times), SyscallSucceeds());

  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(true));
  auto st = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));
  EXPECT_EQ(1, st.st_atime);
  EXPECT_EQ(2, st.st_mtime);
}

// Inode attributes are preserved across copy up.
TEST_F(OverlayCopyUpTest, InodeAttributes) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "hello"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  auto initial = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));

  // Force a copy up.
  FileDescriptor const file =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_WRONLY));

  auto after_copy = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));

  // N.B. Link count is not preserved because hardlinks are broken across copy
  // up, st_dev/st_ino may change on non-directory copy up, and st_ctime is
  // updated to current time.
  EXPECT_EQ(initial.st_mode, after_copy.st_mode);
  EXPECT_EQ(initial.st_uid, after_copy.st_uid);
  EXPECT_EQ(initial.st_gid, after_copy.st_gid);
  EXPECT_EQ(initial.st_rdev, after_copy.st_rdev);
  EXPECT_EQ(initial.st_size, after_copy.st_size);
  EXPECT_EQ(initial.st_blksize, after_copy.st_blksize);
  EXPECT_EQ(initial.st_blocks, after_copy.st_blocks);
  EXPECT_EQ(initial.st_atime, after_copy.st_atime);
  EXPECT_EQ(initial.st_mtime, after_copy.st_mtime);
}

// Advisory locks remain effective on files across copy up.
TEST_F(OverlayCopyUpTest, FileLocks) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "data"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  FileDescriptor rfile =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_RDONLY));
  EXPECT_THAT(flock(rfile.get(), LOCK_EX | LOCK_NB), SyscallSucceeds());

  // Trigger copy up.
  FileDescriptor const wfile =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_WRONLY));
  EXPECT_THAT(flock(wfile.get(), LOCK_EX | LOCK_NB),
              SyscallFailsWithErrno(EAGAIN));

  rfile.reset();
  EXPECT_THAT(flock(wfile.get(), LOCK_EX | LOCK_NB), SyscallSucceeds());
}

// Mapped memory reflects file contents across copy up even when mapped before
// copy up occurs.
TEST_F(OverlayCopyUpTest, MappedMemory) {
  // Linux overlayfs documents ("Non-standard behavior") that a read-only
  // MAP_SHARED mapping created prior to copy-up continues referencing the lower
  // file and does not observe subsequent writes; gVisor updates mappings across
  // copy-up.
  SKIP_IF(!IsRunningOnGvisor());

  std::string lower_content(kPageSize, 'a');
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), lower_content, 0666));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  FileDescriptor const rfile =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_RDONLY));
  Mapping const map = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, 2 * kPageSize, PROT_READ, MAP_SHARED, rfile.get(), 0));

  // Fault in the mapping before triggering copy up.
  EXPECT_EQ(0, memcmp(map.ptr(), lower_content.c_str(), kPageSize));

  std::string upper_content(kPageSize, 'b');
  FileDescriptor const wfile =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_WRONLY));
  ASSERT_THAT(WriteFd(wfile.get(), upper_content.data(), kPageSize),
              SyscallSucceedsWithValue(kPageSize));

  EXPECT_EQ(0, memcmp(map.ptr(), upper_content.c_str(), kPageSize));
}

// Truncating a file that was mapped read-only before copy up delivers SIGBUS.
TEST_F(OverlayCopyUpTest, TruncateMappedFileCausesSIGBUS) {
  // Linux overlayfs keeps pre-copy-up read-only MAP_SHARED mappings backed by
  // the untouched lower file; gVisor switches mappings across copy-up.
  SKIP_IF(!IsRunningOnGvisor());

  std::string lower_content(kPageSize, 'a');
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), lower_content, 0666));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  FileDescriptor const rfile =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_RDONLY));
  Mapping const map = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, 2 * kPageSize, PROT_READ, MAP_SHARED, rfile.get(), 0));

  EXPECT_EQ(0, memcmp(map.ptr(), lower_content.c_str(), kPageSize));

  ASSERT_THAT(truncate(overlay_path.c_str(), 0), SyscallSucceeds());

  std::vector<char> in(kPageSize);
  EXPECT_EXIT(memcpy(in.data(), map.ptr(), kPageSize),
              ::testing::KilledBySignal(SIGBUS), "");
}

// Non-copy-upable lower files (such as FIFOs) report non-writable via access(2)
// and reject writable open(2) in gVisor.
TEST_F(OverlayCopyUpTest, AccessWritableNonCopyUpableLowerFile) {
  // Linux allows opening and writing to a FIFO residing on a read-only lower
  // layer; gVisor disallows write access to lower special files that cannot be
  // copied up.
  SKIP_IF(!IsRunningOnGvisor());

  ASSERT_THAT(mknod(LowerPath("my_pipe").c_str(), S_IFIFO | 0666, 0),
              SyscallSucceeds());
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string pipe_overlay = MergedPath("my_pipe");
  EXPECT_THAT(access(pipe_overlay.c_str(), W_OK),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(open(pipe_overlay.c_str(), O_WRONLY),
              SyscallFailsWithErrno(EPERM));

  // A FIFO created on the upper layer is writable.
  EXPECT_THAT(unlink(pipe_overlay.c_str()), SyscallSucceeds());
  ASSERT_THAT(mknod(pipe_overlay.c_str(), S_IFIFO | 0666, 0),
              SyscallSucceeds());
  EXPECT_THAT(access(pipe_overlay.c_str(), W_OK), SyscallSucceeds());
}

// ============================================================================
// Directory tests
// ============================================================================

class OverlayDirTest : public OverlayOnTmpfsTest {};

// Looking up a file that only exists in the upper filesystem returns that file.
TEST_F(OverlayDirTest, LookupFileUpperSucceeds) {
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("file"), "upper"));
  ASSERT_NO_ERRNO(MountOverlay());

  EXPECT_THAT(Exists(MergedPath("file")), IsPosixErrorOkAndHolds(true));
}

// Looking up a file that only exists in the lower filesystem returns that file.
TEST_F(OverlayDirTest, LookupFileLowerSucceeds) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  EXPECT_THAT(Exists(MergedPath("file")), IsPosixErrorOkAndHolds(true));
}

// Directory entries in the lower and upper filesystems are merged without
// duplicates.
TEST_F(OverlayDirTest, EntriesAreMerged) {
  // Non-overlapping directories and subdirectories.
  auto upper_subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(o_.upper));
  ASSERT_NO_ERRNO(TempPath::CreateDirIn(upper_subdir.path()));

  auto lower_subdir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(o_.lower));
  ASSERT_NO_ERRNO(TempPath::CreateDirIn(lower_subdir.path()));

  // Overlapping directory entry.
  const std::string shared_rel = NewTempRelPath();
  ASSERT_THAT(mkdir(UpperPath(shared_rel).c_str(), 0555), SyscallSucceeds());
  ASSERT_THAT(mkdir(LowerPath(shared_rel).c_str(), 0555), SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  std::set<std::string> overlay_contents;
  EXPECT_NO_ERRNO(
      RecursivelyCollectSubPaths(o_.merged, o_.merged, &overlay_contents));

  std::set<std::string> component_contents;
  EXPECT_NO_ERRNO(
      RecursivelyCollectSubPaths(o_.upper, o_.upper, &component_contents));
  EXPECT_NO_ERRNO(
      RecursivelyCollectSubPaths(o_.lower, o_.lower, &component_contents));
  EXPECT_THAT(overlay_contents, UnorderedElementsAreArray(component_contents));
}

// Directory inode and device numbers remain unchanged after copy up.
TEST_F(OverlayDirTest, DirInodePersistent) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("subdir")));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_subdir = MergedPath("subdir");
  auto before = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_subdir));

  // chmod(2) triggers directory copy up.
  ASSERT_NO_ERRNO(Chmod(overlay_subdir, 0777));
  auto after = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_subdir));
  EXPECT_EQ(before.st_dev, after.st_dev);
  EXPECT_EQ(before.st_ino, after.st_ino);
}

// ============================================================================
// Rename tests
// ============================================================================

class OverlayRenameTest : public OverlayOnTmpfsTest {};

// A regular file on the lower layer is copied up and renamed, leaving a
// whiteout hiding the lower file.
TEST_F(OverlayRenameTest, FileCopyUp) {
  const std::string src_lower = LowerPath("src");
  ASSERT_NO_ERRNO(CreateWithContents(src_lower, "hello"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string src_path = MergedPath("src");
  const std::string dst_path = MergedPath("dst");
  ASSERT_THAT(rename(src_path.c_str(), dst_path.c_str()), SyscallSucceeds());
  EXPECT_THAT(Exists(dst_path), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(src_lower), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(src_path), IsPosixErrorOkAndHolds(false));
}

// A regular file may replace another regular file on the lower layer.
TEST_F(OverlayRenameTest, FileReplaceLower) {
  constexpr char kRenamedContents[] = "renamed file";
  constexpr char kReplacedContents[] = "replaced file";

  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src"), kRenamedContents));
  const std::string dst_lower = LowerPath("dst");
  ASSERT_NO_ERRNO(CreateWithContents(dst_lower, kReplacedContents));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string dst_path = MergedPath("dst");
  ASSERT_THAT(rename(MergedPath("src").c_str(), dst_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(GetContents(dst_path), IsPosixErrorOkAndHolds(kRenamedContents));
  EXPECT_THAT(GetContents(dst_lower),
              IsPosixErrorOkAndHolds(kReplacedContents));
}

// A regular file may replace another regular file on the upper layer.
TEST_F(OverlayRenameTest, FileReplaceUpper) {
  constexpr char kRenamedContents[] = "renamed file";
  constexpr char kReplacedContents[] = "replaced file";

  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src"), kRenamedContents));
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("dst"), kReplacedContents));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string dst_path = MergedPath("dst");
  ASSERT_THAT(rename(MergedPath("src").c_str(), dst_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(GetContents(dst_path), IsPosixErrorOkAndHolds(kRenamedContents));
}

// Renaming a regular file over a lower-layer directory fails with EISDIR, then
// succeeds after the directory is removed (whited out).
TEST_F(OverlayRenameTest, FileReplaceDirWhiteout) {
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src"), "data"));
  const std::string dst_lower = LowerPath("dst");
  ASSERT_NO_ERRNO(Mkdir(dst_lower));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string src_path = MergedPath("src");
  const std::string dst_path = MergedPath("dst");
  ASSERT_THAT(rename(src_path.c_str(), dst_path.c_str()),
              SyscallFailsWithErrno(EISDIR));
  ASSERT_THAT(rmdir(dst_path.c_str()), SyscallSucceeds());
  ASSERT_THAT(rename(src_path.c_str(), dst_path.c_str()), SyscallSucceeds());
  EXPECT_THAT(IsDirectory(dst_path), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(IsDirectory(dst_lower), IsPosixErrorOkAndHolds(true));
}

// A directory on the lower layer is recursively copied up and renamed in
// gVisor. Nesting two directories below the renamed one makes copy-up lock a
// child and a grandchild directory at the same time.
TEST_F(OverlayRenameTest, DirCopyUp) {
  // Linux overlayfs returns EXDEV when renaming a lower or merged directory
  // unless redirect_dir=on is enabled; gVisor copies up the directory subtree.
  SKIP_IF(!IsRunningOnGvisor());

  ASSERT_NO_ERRNO(Mkdir(LowerPath("src_dir")));
  ASSERT_NO_ERRNO(Mkdir(LowerPath("src_dir/a")));
  ASSERT_NO_ERRNO(Mkdir(LowerPath("src_dir/a/b")));
  const std::string src_file_lower = LowerPath("src_dir/a/b/file");
  ASSERT_NO_ERRNO(CreateWithContents(src_file_lower, "hello"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string src_dir_path = MergedPath("src_dir");
  const std::string dst_dir_path = MergedPath("dst_dir");
  ASSERT_THAT(rename(src_dir_path.c_str(), dst_dir_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(GetContents(JoinPath(dst_dir_path, "a/b/file")),
              IsPosixErrorOkAndHolds("hello"));
  EXPECT_THAT(Exists(src_file_lower), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(src_dir_path), IsPosixErrorOkAndHolds(false));
}

// Exchanging two lower directories copies up both subtrees in gVisor.
TEST_F(OverlayRenameTest, DirExchangeCopyUp) {
  // As in DirCopyUp, Linux returns EXDEV here without redirect_dir=on.
  SKIP_IF(!IsRunningOnGvisor());

  for (const char* dir : {"x", "x/a", "x/a/b", "y", "y/c", "y/c/d"}) {
    ASSERT_NO_ERRNO(Mkdir(LowerPath(dir)));
  }
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("x/a/b/file"), "from x"));
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("y/c/d/file"), "from y"));
  ASSERT_NO_ERRNO(MountOverlay());

  ASSERT_THAT(renameat2(AT_FDCWD, MergedPath("x").c_str(), AT_FDCWD,
                        MergedPath("y").c_str(), RENAME_EXCHANGE),
              SyscallSucceeds());
  EXPECT_THAT(GetContents(MergedPath("x/c/d/file")),
              IsPosixErrorOkAndHolds("from y"));
  EXPECT_THAT(GetContents(MergedPath("y/a/b/file")),
              IsPosixErrorOkAndHolds("from x"));
}

// An upper directory may replace an empty directory on the lower layer.
TEST_F(OverlayRenameTest, DirReplaceLower) {
  ASSERT_NO_ERRNO(Mkdir(UpperPath("src_dir")));
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src_dir/file"), "hi"));
  const std::string dst_dir_lower = LowerPath("dst_dir");
  ASSERT_NO_ERRNO(Mkdir(dst_dir_lower));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string dst_dir_path = MergedPath("dst_dir");
  ASSERT_THAT(rename(MergedPath("src_dir").c_str(), dst_dir_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(JoinPath(dst_dir_path, "file")),
              IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(dst_dir_lower), IsPosixErrorOkAndHolds(true));
}

// An upper directory may replace an empty directory on the upper layer.
TEST_F(OverlayRenameTest, DirReplaceUpper) {
  ASSERT_NO_ERRNO(Mkdir(UpperPath("src_dir")));
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src_dir/file"), "hi"));
  ASSERT_NO_ERRNO(Mkdir(UpperPath("dst_dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string dst_dir_path = MergedPath("dst_dir");
  ASSERT_THAT(rename(MergedPath("src_dir").c_str(), dst_dir_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(JoinPath(dst_dir_path, "file")),
              IsPosixErrorOkAndHolds(true));
}

// Renaming a directory over a non-empty lower directory fails with ENOTEMPTY,
// then succeeds once the destination directory's contents are whited out.
TEST_F(OverlayRenameTest, DirReplaceNonemptyWhiteout) {
  ASSERT_NO_ERRNO(Mkdir(UpperPath("src_dir")));
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src_dir/file"), "hi"));
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dst_dir")));
  const std::string dst_other_lower = LowerPath("dst_dir/other");
  ASSERT_NO_ERRNO(CreateWithContents(dst_other_lower, "old"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string src_dir_path = MergedPath("src_dir");
  const std::string dst_dir_path = MergedPath("dst_dir");
  const std::string dst_other_path = JoinPath(dst_dir_path, "other");
  ASSERT_THAT(rename(src_dir_path.c_str(), dst_dir_path.c_str()),
              SyscallFailsWithErrno(ENOTEMPTY));
  ASSERT_THAT(unlink(dst_other_path.c_str()), SyscallSucceeds());
  ASSERT_THAT(rename(src_dir_path.c_str(), dst_dir_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(JoinPath(dst_dir_path, "file")),
              IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(dst_other_path), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(Exists(dst_other_lower), IsPosixErrorOkAndHolds(true));
}

// Renaming a directory over a regular file on the lower layer fails with
// ENOTDIR, then succeeds once the file is whited out.
TEST_F(OverlayRenameTest, DirReplaceFileWhiteout) {
  ASSERT_NO_ERRNO(Mkdir(UpperPath("src_dir")));
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("src_dir/file"), "hi"));
  const std::string dst_lower = LowerPath("dst");
  ASSERT_NO_ERRNO(CreateWithContents(dst_lower, "old"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string src_dir_path = MergedPath("src_dir");
  const std::string dst_path = MergedPath("dst");
  ASSERT_THAT(rename(src_dir_path.c_str(), dst_path.c_str()),
              SyscallFailsWithErrno(ENOTDIR));
  ASSERT_THAT(unlink(dst_path.c_str()), SyscallSucceeds());
  ASSERT_THAT(rename(src_dir_path.c_str(), dst_path.c_str()),
              SyscallSucceeds());
  EXPECT_THAT(IsDirectory(dst_path), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(IsDirectory(dst_lower), IsPosixErrorOkAndHolds(false));
}

// Renaming a lower file out of an unlinked overlay directory fails with ENOENT.
TEST_F(OverlayRenameTest, RenameFromDeletedDirFails) {
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenDeletedOverlayDirWithLowerFile(o_));

  const std::string dst = MergedPath("dst");
  EXPECT_THAT(renameat(dirfd.get(), "file", AT_FDCWD, dst.c_str()),
              SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(Exists(dst), IsPosixErrorOkAndHolds(false));
}

// ============================================================================
// Whiteout tests
// ============================================================================

class OverlayWhiteoutTest : public OverlayOnTmpfsTest {};

// Renaming a file only leaves a whiteout at its origin if the file also
// exists on the lower layer.
TEST_F(OverlayWhiteoutTest, RenameWhiteoutOnlyWhenLowerExists) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("lower_file"), ""));
  ASSERT_NO_ERRNO(MountOverlay());

  // Rename a pure-upper file; no whiteout should be created at its origin.
  ASSERT_NO_ERRNO(CreateWithContents(MergedPath("upper_only"), ""));
  ASSERT_THAT(rename(MergedPath("upper_only").c_str(),
                     MergedPath("upper_renamed").c_str()),
              SyscallSucceeds());
  EXPECT_THAT(Exists(UpperPath("upper_only")), IsPosixErrorOkAndHolds(false));

  // Rename the file that exists on the lower layer; a whiteout must be
  // created.
  ASSERT_THAT(rename(MergedPath("lower_file").c_str(),
                     MergedPath("lower_renamed").c_str()),
              SyscallSucceeds());
  EXPECT_THAT(IsWhiteout(UpperPath("lower_file")),
              IsPosixErrorOkAndHolds(true));
}

// Renaming over a whiteout in a sticky directory must not fail the sticky
// check against the mounter-owned whiteout.
TEST_F(OverlayRenameTest, RenameOverWhiteoutInStickyDir) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  constexpr uid_t kNobody = 65534;
  SKIP_IF(
      !ASSERT_NO_ERRNO_AND_VALUE(IsIDMapped("/proc/self/uid_map", kNobody)));

  // Make o_.base traversable by kNobody after dropping privileges.
  ASSERT_THAT(chmod(o_.base.path().c_str(), 0755), SyscallSucceeds());

  // A sticky directory with lower-only files.
  const std::string lower_dir = LowerPath("dir");
  ASSERT_NO_ERRNO(Mkdir(lower_dir, 0755));
  ASSERT_THAT(chmod(lower_dir.c_str(), 01777), SyscallSucceeds());
  ASSERT_NO_ERRNO(CreateWithContents(JoinPath(lower_dir, "victim"), "lower"));
  ASSERT_NO_ERRNO(
      CreateWithContents(JoinPath(lower_dir, "lower_other"), "lower"));

  ASSERT_NO_ERRNO(MountOverlay());

  // Unlinking it leaves a mounter-owned whiteout.
  const std::string merged_dir = MergedPath("dir");
  ASSERT_THAT(unlink(JoinPath(merged_dir, "victim").c_str()),
              SyscallSucceeds());
  struct stat st;
  ASSERT_THAT(lstat(UpperPath("dir/victim").c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(S_ISCHR(st.st_mode));
  ASSERT_EQ(st.st_rdev, makedev(0, 0));
  ASSERT_EQ(st.st_uid, geteuid());
  ASSERT_NE(st.st_uid, kNobody);
  ASSERT_THAT(stat(JoinPath(merged_dir, "victim").c_str(), &st),
              SyscallFailsWithErrno(ENOENT));
  ASSERT_NO_ERRNO(
      CreateWithContents(JoinPath(merged_dir, "upper_other"), "upper"));

  // An unprivileged user may not rename over visible files it doesn't own,
  // but may rename its own file over the whiteout.
  EXPECT_THAT(
      InForkedProcess([&] {
        TEST_PCHECK(chdir(merged_dir.c_str()) == 0);
        TEST_PCHECK(syscall(SYS_setresuid, kNobody, kNobody, kNobody) == 0);
        int fd = open("mine", O_WRONLY | O_CREAT | O_EXCL, 0644);
        TEST_PCHECK(fd >= 0);
        TEST_PCHECK(close(fd) == 0);
        TEST_CHECK(rename("mine", "lower_other") == -1 && errno == EPERM);
        TEST_CHECK(rename("mine", "upper_other") == -1 && errno == EPERM);
        TEST_PCHECK(rename("mine", "victim") == 0);
      }),
      IsPosixErrorOkAndHolds(0));

  ASSERT_THAT(stat(JoinPath(merged_dir, "victim").c_str(), &st),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISREG(st.st_mode));
  EXPECT_EQ(st.st_uid, kNobody);
  EXPECT_EQ(st.st_size, 0);
  EXPECT_THAT(stat(JoinPath(merged_dir, "mine").c_str(), &st),
              SyscallFailsWithErrno(ENOENT));
  for (const char* name : {"lower_other", "upper_other"}) {
    ASSERT_THAT(stat(JoinPath(merged_dir, name).c_str(), &st),
                SyscallSucceeds());
    EXPECT_NE(st.st_uid, kNobody);
    EXPECT_GT(st.st_size, 0);
  }
}

// Opening writably or unlinking a lower file through an unlinked overlay
// directory fails with ENOENT.
TEST_F(OverlayWhiteoutTest, UnlinkInDeletedDirFails) {
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenDeletedOverlayDirWithLowerFile(o_));

  // Opening the lower file for writing would copy it up into the deleted
  // directory's upper copy.
  EXPECT_THAT(openat(dirfd.get(), "file", O_RDWR),
              SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(unlinkat(dirfd.get(), "file", 0), SyscallFailsWithErrno(ENOENT));
}

// Unlinking a lower-only file creates a whiteout without modifying lower.
TEST_F(OverlayWhiteoutTest, RemoveMakesWhiteoutLowerOnly) {
  const std::string lower_path = LowerPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_path, "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(lower_path), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(false));
}

// Unlinking a file present in both upper and lower creates a whiteout hiding
// the lower file.
TEST_F(OverlayWhiteoutTest, RemoveMakesWhiteoutUpperAndLower) {
  const std::string lower_path = LowerPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_path, "lower"));
  ASSERT_NO_ERRNO(CreateWithContents(UpperPath("file"), "upper"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(lower_path), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(false));
}

// Unlinking a file that exists only on the upper layer does not create a
// whiteout.
TEST_F(OverlayWhiteoutTest, UnlinkUpperOnlyDoesNotMakeWhiteout) {
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(overlay_path, "upper"));
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(UpperPath("file")), IsPosixErrorOkAndHolds(false));
}

// Removing a directory that exists only on the upper layer does not create a
// whiteout.
TEST_F(OverlayWhiteoutTest, RmdirUpperOnlyDoesNotMakeWhiteout) {
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("dir");
  ASSERT_NO_ERRNO(Mkdir(overlay_path));
  ASSERT_THAT(rmdir(overlay_path.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(UpperPath("dir")), IsPosixErrorOkAndHolds(false));
}

// Removing an entry with a name of length NAME_MAX succeeds.
TEST_F(OverlayWhiteoutTest, RemoveMaxFilename) {
  const std::string big_name(NAME_MAX, 'a');
  const std::string lower_path = LowerPath(big_name);
  ASSERT_THAT(mkdir(lower_path.c_str(), 0444), SyscallSucceeds());
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath(big_name);
  ASSERT_THAT(rmdir(overlay_path.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(lower_path), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(false));
}

// A new regular file can be created over a whiteout and gets a fresh inode.
TEST_F(OverlayWhiteoutTest, CreateFileOverWhiteout) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  auto st1 = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));

  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());

  FileDescriptor const fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_CREAT | O_RDONLY, 0444));

  auto st2 = ASSERT_NO_ERRNO_AND_VALUE(Stat(overlay_path));
  EXPECT_FALSE(st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino)
      << "both original and new files have device number " << st1.st_dev
      << " and inode number " << st1.st_ino;
}

// A directory can be created over a whited-out file.
TEST_F(OverlayWhiteoutTest, CreateDirectoryOverWhiteout) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("entry"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("entry");
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());
  EXPECT_THAT(mkdir(overlay_path.c_str(), 0444), SyscallSucceeds());
}

// A directory can be created over a whited-out directory.
TEST_F(OverlayWhiteoutTest, CreateDirectoryOverWhiteoutDirectory) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("dir");
  ASSERT_THAT(rmdir(overlay_path.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(mkdir(overlay_path.c_str(), 0444), SyscallSucceeds());
  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(true));
}

// A symlink can be created over a whiteout.
TEST_F(OverlayWhiteoutTest, CreateSymlinkOverWhiteout) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("entry"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("entry");
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());
  EXPECT_THAT(symlink("/foo", overlay_path.c_str()), SyscallSucceeds());
}

// A hardlink can be created over a whiteout.
TEST_F(OverlayWhiteoutTest, CreateHardlinkOverWhiteout) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("target"), "target"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());
  ASSERT_THAT(link(MergedPath("target").c_str(), overlay_path.c_str()),
              SyscallSucceeds());
}

// Whiteouts persist after recreating and removing a file at the same path.
TEST_F(OverlayWhiteoutTest, WhiteoutPersists) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());

  {
    FileDescriptor const fd =
        ASSERT_NO_ERRNO_AND_VALUE(Open(overlay_path, O_CREAT | O_RDONLY, 0444));
  }

  ASSERT_THAT(unlink(overlay_path.c_str()), SyscallSucceeds());
  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(false));
}

// Renaming a lower file creates a whiteout at the original path.
TEST_F(OverlayWhiteoutTest, RenameCreatesWhiteout) {
  const std::string lower_path = LowerPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_path, "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(rename(overlay_path.c_str(), MergedPath("renamed").c_str()),
              SyscallSucceeds());

  EXPECT_THAT(Exists(lower_path), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(overlay_path), IsPosixErrorOkAndHolds(false));
}

// Attempting to remove a lower-only directory with unlink fails with EISDIR.
TEST_F(OverlayWhiteoutTest, UnlinkLowerDirectory) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("dir")));
  ASSERT_NO_ERRNO(MountOverlay());

  EXPECT_THAT(unlink(MergedPath("dir").c_str()), SyscallFailsWithErrno(EISDIR));
}

// Attempting to remove a lower-only regular file with rmdir fails with ENOTDIR.
TEST_F(OverlayWhiteoutTest, RmdirLowerNonDirectory) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  EXPECT_THAT(rmdir(MergedPath("file").c_str()),
              SyscallFailsWithErrno(ENOTDIR));
}

// Removing a directory fails with ENOTEMPTY when its lower counterpart still
// contains non-whited-out entries.
TEST_F(OverlayWhiteoutTest, RemoveNonEmptyDirectory) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("subdir")));
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("subdir/file"), "hi"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_subdir = MergedPath("subdir");
  auto temp = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(overlay_subdir));
  ASSERT_THAT(unlink(temp.path().c_str()), SyscallSucceeds());

  EXPECT_THAT(rmdir(overlay_subdir.c_str()), SyscallFailsWithErrno(ENOTEMPTY));
}

// Removing a directory succeeds once all lower entries inside it are whited
// out, and recreating the directory keeps the lower entries hidden.
TEST_F(OverlayWhiteoutTest, RemoveDirectoryContainingWhiteout) {
  ASSERT_NO_ERRNO(Mkdir(LowerPath("subdir")));
  const std::string lower_file = LowerPath("subdir/file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_file, "hi"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_subdir = MergedPath("subdir");
  const std::string overlay_file = JoinPath(overlay_subdir, "file");
  ASSERT_THAT(unlink(overlay_file.c_str()), SyscallSucceeds());
  ASSERT_THAT(rmdir(overlay_subdir.c_str()), SyscallSucceeds());

  EXPECT_THAT(Exists(lower_file), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(Exists(overlay_subdir), IsPosixErrorOkAndHolds(false));

  EXPECT_THAT(mkdir(overlay_subdir.c_str(), 0555), SyscallSucceeds());
  EXPECT_THAT(Exists(overlay_file), IsPosixErrorOkAndHolds(false));
}

// RENAME_NOREPLACE succeeds when renaming over a whiteout in the upper layer.
TEST_F(OverlayWhiteoutTest, RenameAt2WithNoReplace) {
  ASSERT_NO_ERRNO(CreateWithContents(LowerPath("lower_orig"), "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  // Lower-backed file: renaming away leaves a whiteout in upper, and renaming
  // back with RENAME_NOREPLACE must ignore that whiteout.
  const std::string lower_orig = MergedPath("lower_orig");
  const std::string lower_tmp = MergedPath("lower_tmp");
  ASSERT_THAT(renameat2(AT_FDCWD, lower_orig.c_str(), AT_FDCWD,
                        lower_tmp.c_str(), RENAME_NOREPLACE),
              SyscallSucceeds());
  EXPECT_THAT(renameat2(AT_FDCWD, lower_tmp.c_str(), AT_FDCWD,
                        lower_orig.c_str(), RENAME_NOREPLACE),
              SyscallSucceeds());

  // Upper-only file: round-trip rename with RENAME_NOREPLACE also succeeds.
  const std::string upper_orig = MergedPath("upper_orig");
  const std::string upper_tmp = MergedPath("upper_tmp");
  ASSERT_NO_ERRNO(CreateWithContents(upper_orig, "upper"));
  ASSERT_THAT(renameat2(AT_FDCWD, upper_orig.c_str(), AT_FDCWD,
                        upper_tmp.c_str(), RENAME_NOREPLACE),
              SyscallSucceeds());
  EXPECT_THAT(renameat2(AT_FDCWD, upper_tmp.c_str(), AT_FDCWD,
                        upper_orig.c_str(), RENAME_NOREPLACE),
              SyscallSucceeds());
}

// ============================================================================
// Extended attribute tests
// ============================================================================

class OverlayXattrTest : public OverlayOnTmpfsTest {
 protected:
  void SetUp() override {
    OverlayOnTmpfsTest::SetUp();
    if (IsSkipped() || HasFatalFailure()) {
      return;
    }
    const std::string probe = JoinPath(o_.base.path(), "xattr_probe");
    ASSERT_NO_ERRNO(CreateWithContents(probe, ""));
    int ret = setxattr(probe.c_str(), "user.probe", nullptr, 0, 0);
    SKIP_IF(!IsRunningOnGvisor() && ret < 0 && errno == EOPNOTSUPP);
    ASSERT_THAT(ret, SyscallSucceeds());
  }

  void CreateOverlappingFile() {
    ASSERT_NO_ERRNO(CreateWithContents(UpperPath("file"), "upper"));
    ASSERT_NO_ERRNO(CreateWithContents(LowerPath("file"), "lower"));
  }
};

// Getting extended attributes of a file present in both upper and lower uses
// the upper file's attributes.
TEST_F(OverlayXattrTest, GetxattrPrefersUpper) {
  CreateOverlappingFile();
  if (HasFatalFailure()) {
    return;
  }

  constexpr char kXattrName[] = "user.test";
  const char upper_val = 'u';
  ASSERT_THAT(setxattr(UpperPath("file").c_str(), kXattrName, &upper_val,
                       sizeof(upper_val), 0),
              SyscallSucceeds());
  const char lower_val = 'l';
  ASSERT_THAT(setxattr(LowerPath("file").c_str(), kXattrName, &lower_val,
                       sizeof(lower_val), 0),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  char val = '-';
  EXPECT_THAT(
      getxattr(MergedPath("file").c_str(), kXattrName, &val, sizeof(val)),
      SyscallSucceedsWithValue(sizeof(val)));
  EXPECT_EQ(val, upper_val);
}

// Listing extended attributes of a file present in both upper and lower uses
// only the upper file's attributes.
TEST_F(OverlayXattrTest, ListxattrPrefersUpper) {
  CreateOverlappingFile();
  if (HasFatalFailure()) {
    return;
  }

  constexpr char kUpperXattr[] = "user.upper";
  constexpr char kLowerXattr[] = "user.lower";
  ASSERT_THAT(setxattr(UpperPath("file").c_str(), kUpperXattr, nullptr, 0, 0),
              SyscallSucceeds());
  ASSERT_THAT(setxattr(LowerPath("file").c_str(), kLowerXattr, nullptr, 0, 0),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  char list[sizeof(kUpperXattr)] = {};
  EXPECT_THAT(listxattr(MergedPath("file").c_str(), list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(kUpperXattr)));
  EXPECT_STREQ(list, kUpperXattr);
}

// An upper file masks extended attributes set on the lower file.
TEST_F(OverlayXattrTest, UpperMasksLower) {
  CreateOverlappingFile();
  if (HasFatalFailure()) {
    return;
  }

  constexpr char kLowerXattr[] = "user.lower";
  ASSERT_THAT(setxattr(LowerPath("file").c_str(), kLowerXattr, nullptr, 0, 0),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  EXPECT_THAT(getxattr(overlay_path.c_str(), kLowerXattr, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(listxattr(overlay_path.c_str(), nullptr, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(removexattr(overlay_path.c_str(), kLowerXattr),
              SyscallFailsWithErrno(ENODATA));
}

// Extended attributes on a lower-only file are visible through the overlay.
TEST_F(OverlayXattrTest, GetListxattrWithNoUpperFile) {
  const std::string lower_path = LowerPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_path, "lower"));

  constexpr char kXattrName[] = "user.lower";
  ASSERT_THAT(setxattr(lower_path.c_str(), kXattrName, nullptr, 0, 0),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  EXPECT_THAT(getxattr(overlay_path.c_str(), kXattrName, nullptr, 0),
              SyscallSucceedsWithValue(0));

  char list[sizeof(kXattrName)] = {};
  EXPECT_THAT(listxattr(overlay_path.c_str(), list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(kXattrName)));
  EXPECT_STREQ(list, kXattrName);
}

// setxattr copies up a lower file without modifying the lower file.
TEST_F(OverlayXattrTest, SetxattrCopiesUp) {
  const std::string lower_path = LowerPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_path, "lower"));
  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  constexpr char kXattrName[] = "user.test";
  ASSERT_THAT(setxattr(overlay_path.c_str(), kXattrName, nullptr, 0, 0),
              SyscallSucceeds());

  EXPECT_THAT(getxattr(UpperPath("file").c_str(), kXattrName, nullptr, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(getxattr(lower_path.c_str(), kXattrName, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(getxattr(overlay_path.c_str(), kXattrName, nullptr, 0),
              SyscallSucceedsWithValue(0));
}

// removexattr copies up a lower file without modifying the lower file.
TEST_F(OverlayXattrTest, RemovexattrCopiesUp) {
  const std::string lower_path = LowerPath("file");
  ASSERT_NO_ERRNO(CreateWithContents(lower_path, "lower"));

  constexpr char kXattrName[] = "user.test";
  ASSERT_THAT(setxattr(lower_path.c_str(), kXattrName, nullptr, 0, 0),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(MountOverlay());

  const std::string overlay_path = MergedPath("file");
  ASSERT_THAT(removexattr(overlay_path.c_str(), kXattrName), SyscallSucceeds());

  EXPECT_THAT(getxattr(UpperPath("file").c_str(), kXattrName, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(getxattr(lower_path.c_str(), kXattrName, nullptr, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(getxattr(overlay_path.c_str(), kXattrName, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
