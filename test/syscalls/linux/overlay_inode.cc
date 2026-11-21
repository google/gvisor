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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Mounts an overlay at target with opts. Tries redirect_dir=on first so that
// Linux renames of lower layer directories succeed. gVisor does not accept the
// redirect_dir option and returns EINVAL.
void MountOverlay(const std::string& target, const std::string& opts) {
  const int ret = mount("overlay", target.c_str(), "overlay", 0,
                        absl::StrCat(opts, ",redirect_dir=on").c_str());
  if (ret == 0) {
    return;
  }
  ASSERT_THAT(ret, SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(mount("overlay", target.c_str(), "overlay", 0, opts.c_str()),
              SyscallSucceeds());
}

// DirentIno returns the directory entry inode number of name in dir.
ino_t DirentIno(const std::string& dir, const std::string& name) {
  DIR* dp = opendir(dir.c_str());
  EXPECT_NE(dp, nullptr) << dir;
  if (dp == nullptr) {
    return 0;
  }
  auto close_dir = Cleanup([dp] { EXPECT_EQ(closedir(dp), 0); });
  while (struct dirent* ent = readdir(dp)) {
    if (name == ent->d_name) {
      return ent->d_ino;
    }
  }
  ADD_FAILURE() << name << " is missing from " << dir;
  return 0;
}

// Mounts an overlay whose layers share one tmpfs and checks that the mount
// publishes one device number, that a directory entry inode matches stat, and
// that copy-up does not change a file's device and inode numbers.
TEST(OverlayInode, StableIdentity) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto umount_base = Cleanup(
      [&base] { EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds()); });

  const std::string lower = JoinPath(base.path(), "lower");
  const std::string upper = JoinPath(base.path(), "upper");
  const std::string work = JoinPath(base.path(), "work");
  const std::string merged = JoinPath(base.path(), "merged");
  for (const std::string& dir : {lower, upper, work, merged}) {
    ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  }
  const std::string sub = JoinPath(lower, "sub");
  ASSERT_THAT(mkdir(sub.c_str(), 0755), SyscallSucceeds());
  const std::string lower_file = JoinPath(sub, "file");
  {
    const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
        Open(lower_file, O_CREAT | O_WRONLY | O_TRUNC, 0644));
    ASSERT_THAT(write(created.get(), "a", 1), SyscallSucceedsWithValue(1));
  }

  const std::string opts =
      absl::StrCat("lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
  ASSERT_THAT(mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()),
              SyscallSucceeds());
  auto umount_merged = Cleanup(
      [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });

  const std::string merged_sub = JoinPath(merged, "sub");
  const std::string merged_file = JoinPath(merged_sub, "file");
  // Keep descriptors open to compare path-based and descriptor-based identity
  // before and after copy-up and checkpoint/restore.
  const FileDescriptor dir_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(merged_sub, O_RDONLY | O_DIRECTORY));
  const FileDescriptor file_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(merged_file, O_RDONLY));
  struct stat dir_stat;
  struct stat file_stat;
  ASSERT_THAT(stat(merged_sub.c_str(), &dir_stat), SyscallSucceeds());
  ASSERT_THAT(stat(merged_file.c_str(), &file_stat), SyscallSucceeds());
  struct stat dir_held;
  struct stat file_held;
  ASSERT_THAT(fstat(dir_fd.get(), &dir_held), SyscallSucceeds());
  ASSERT_THAT(fstat(file_fd.get(), &file_held), SyscallSucceeds());
  EXPECT_EQ(dir_stat.st_dev, file_stat.st_dev);
  EXPECT_EQ(dir_stat.st_ino, dir_held.st_ino);
  EXPECT_EQ(file_stat.st_ino, file_held.st_ino);
  EXPECT_EQ(DirentIno(merged, "sub"), dir_stat.st_ino);
  EXPECT_EQ(DirentIno(merged_sub, "file"), file_stat.st_ino);

  const FileDescriptor append =
      ASSERT_NO_ERRNO_AND_VALUE(Open(merged_file, O_WRONLY | O_APPEND, 0));
  ASSERT_THAT(write(append.get(), "b", 1), SyscallSucceedsWithValue(1));
  struct stat after;
  ASSERT_THAT(stat(merged_file.c_str(), &after), SyscallSucceeds());
  EXPECT_EQ(file_stat.st_dev, after.st_dev);
  EXPECT_EQ(file_stat.st_ino, after.st_ino);
  EXPECT_EQ(dir_stat.st_dev, after.st_dev);

  // Reading names does not require search permission on the directory.
  ASSERT_THAT(chmod(merged_sub.c_str(), 0400), SyscallSucceeds());
  {
    const AutoCapability no_dac_override(CAP_DAC_OVERRIDE, false);
    const AutoCapability no_dac_search(CAP_DAC_READ_SEARCH, false);
    struct stat inaccessible;
    EXPECT_THAT(stat(merged_file.c_str(), &inaccessible),
                SyscallFailsWithErrno(EACCES));
    EXPECT_EQ(DirentIno(merged_sub, "file"), after.st_ino);
  }
}

// Checks that directory entry inodes match stat for subdirectories of a
// directory that both layers supply. The subdirectories come from the lower
// layer, the upper layer, both layers, and the overlay. The test also renames
// a lower layer subdirectory, and moves another lower layer subdirectory into
// a directory that only the upper layer supplies. If a rename fails with
// EXDEV, the test does not check that rename.
class OverlayInodeDirectoryReplacement : public ::testing::TestWithParam<bool> {
};

TEST_P(OverlayInodeDirectoryReplacement, MergedDirectorySubdirectories) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto umount_base = Cleanup(
      [&base] { EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds()); });

  const std::string lower = JoinPath(base.path(), "lower");
  const std::string upper = JoinPath(base.path(), "upper");
  const std::string work = JoinPath(base.path(), "work");
  const std::string merged = JoinPath(base.path(), "merged");
  for (const std::string& dir :
       {lower, upper, work, merged, JoinPath(lower, "sub"),
        JoinPath(lower, "sub/lower_dir"), JoinPath(lower, "sub/to_rename"),
        JoinPath(lower, "sub/to_move"), JoinPath(lower, "sub/both"),
        JoinPath(upper, "sub"), JoinPath(upper, "sub/upper_dir"),
        JoinPath(upper, "sub/both")}) {
    ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  }
  if (GetParam()) {
    ASSERT_THAT(mkdir(JoinPath(lower, "sub/renamed").c_str(), 0755),
                SyscallSucceeds());
  }

  const std::string opts =
      absl::StrCat("lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
  ASSERT_NO_FATAL_FAILURE(MountOverlay(merged, opts));
  auto umount_merged = Cleanup(
      [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });

  const std::string sub = JoinPath(merged, "sub");
  ASSERT_THAT(mkdir(JoinPath(sub, "new_dir").c_str(), 0755), SyscallSucceeds());
  std::vector<std::string> names = {"lower_dir", "both", "upper_dir",
                                    "new_dir"};
  // Keep sub open while its subdirectory is renamed and its descriptor is
  // closed.
  const FileDescriptor sub_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(sub, O_RDONLY | O_DIRECTORY));
  // The descriptor keeps the directory's identity from before the rename.
  FileDescriptor renamed_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(sub, "to_rename"), O_RDONLY | O_DIRECTORY));
  const int rename_ret = rename(JoinPath(sub, "to_rename").c_str(),
                                JoinPath(sub, "renamed").c_str());
  const bool renamed = rename_ret == 0;
  if (renamed) {
    names.push_back("renamed");
  } else {
    ASSERT_FALSE(IsRunningOnGvisor());
    EXPECT_THAT(rename_ret, SyscallFailsWithErrno(EXDEV));
  }

  struct stat sub_stat;
  ASSERT_THAT(stat(sub.c_str(), &sub_stat), SyscallSucceeds());
  for (const std::string& name : names) {
    SCOPED_TRACE(name);
    struct stat st;
    ASSERT_THAT(stat(JoinPath(sub, name).c_str(), &st), SyscallSucceeds());
    EXPECT_EQ(st.st_dev, sub_stat.st_dev);
    EXPECT_EQ(DirentIno(sub, name), st.st_ino);
  }
  if (renamed) {
    struct stat held;
    ASSERT_THAT(fstat(renamed_fd.get(), &held), SyscallSucceeds());
    EXPECT_EQ(DirentIno(sub, "renamed"), held.st_ino);

    // The directory entry still matches stat after the descriptor is closed.
    renamed_fd.reset();
    struct stat st;
    ASSERT_THAT(stat(JoinPath(sub, "renamed").c_str(), &st), SyscallSucceeds());
    EXPECT_EQ(DirentIno(sub, "renamed"), st.st_ino);
  }

  // Only the upper layer supplies new_dir, the destination of this rename.
  const std::string new_dir = JoinPath(sub, "new_dir");
  const FileDescriptor moved_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(sub, "to_move"), O_RDONLY | O_DIRECTORY));
  const int move_ret = rename(JoinPath(sub, "to_move").c_str(),
                              JoinPath(new_dir, "moved").c_str());
  if (move_ret == 0) {
    struct stat held;
    ASSERT_THAT(fstat(moved_fd.get(), &held), SyscallSucceeds());
    EXPECT_EQ(DirentIno(new_dir, "moved"), held.st_ino);
  } else {
    EXPECT_THAT(move_ret, SyscallFailsWithErrno(EXDEV));
  }
}

INSTANTIATE_TEST_SUITE_P(WithAndWithoutDestination,
                         OverlayInodeDirectoryReplacement, ::testing::Bool());

// Checks that directory entry inodes match stat after RENAME_EXCHANGE swaps
// a lower layer subdirectory of a directory that both layers supply with a
// subdirectory of a directory that only the upper layer supplies. Also checks
// an upper layer subdirectory that hides a lower layer file.
TEST(OverlayInode, ExchangedDirectories) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto umount_base = Cleanup(
      [&base] { EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds()); });

  const std::string lower = JoinPath(base.path(), "lower");
  const std::string upper = JoinPath(base.path(), "upper");
  const std::string work = JoinPath(base.path(), "work");
  const std::string merged = JoinPath(base.path(), "merged");
  for (const std::string& dir :
       {lower, upper, work, merged, JoinPath(lower, "sub"),
        JoinPath(lower, "sub/lower_dir"), JoinPath(upper, "sub"),
        JoinPath(upper, "sub/dir_over_file")}) {
    ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  }
  {
    const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
        Open(JoinPath(lower, "sub/dir_over_file"), O_CREAT | O_WRONLY, 0644));
  }

  const std::string opts =
      absl::StrCat("lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
  ASSERT_NO_FATAL_FAILURE(MountOverlay(merged, opts));
  auto umount_merged = Cleanup(
      [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });

  const std::string sub = JoinPath(merged, "sub");
  struct stat st;
  ASSERT_THAT(stat(JoinPath(sub, "dir_over_file").c_str(), &st),
              SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_EQ(DirentIno(sub, "dir_over_file"), st.st_ino);

  const std::string new_dir = JoinPath(sub, "new_dir");
  const std::string peer = JoinPath(new_dir, "peer");
  const std::string lower_dir = JoinPath(sub, "lower_dir");
  ASSERT_THAT(mkdir(new_dir.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(peer.c_str(), 0755), SyscallSucceeds());
  // Keep both parents open while the exchanged descriptors are closed.
  const FileDescriptor sub_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(sub, O_RDONLY | O_DIRECTORY));
  const FileDescriptor new_dir_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(new_dir, O_RDONLY | O_DIRECTORY));
  FileDescriptor lower_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(lower_dir, O_RDONLY | O_DIRECTORY));
  FileDescriptor peer_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(peer, O_RDONLY | O_DIRECTORY));
  const int ret = syscall(SYS_renameat2, AT_FDCWD, lower_dir.c_str(), AT_FDCWD,
                          peer.c_str(), RENAME_EXCHANGE);
  if (ret != 0) {
    EXPECT_THAT(ret, SyscallFailsWithErrno(EXDEV));
    return;
  }

  struct stat lower_held;
  struct stat peer_held;
  ASSERT_THAT(fstat(lower_fd.get(), &lower_held), SyscallSucceeds());
  ASSERT_THAT(fstat(peer_fd.get(), &peer_held), SyscallSucceeds());
  EXPECT_EQ(DirentIno(new_dir, "peer"), lower_held.st_ino);
  EXPECT_EQ(DirentIno(sub, "lower_dir"), peer_held.st_ino);

  // The directory entries still match stat after the descriptors are closed.
  lower_fd.reset();
  peer_fd.reset();
  ASSERT_THAT(stat(peer.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(DirentIno(new_dir, "peer"), st.st_ino);
  ASSERT_THAT(stat(lower_dir.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(DirentIno(sub, "lower_dir"), st.st_ino);
}

class OverlayInodeLowerLayers : public ::testing::TestWithParam<bool> {};

// Checks that directory entry inodes match stat for entries of a directory
// that two lower layers supply. Each entry comes from a different
// combination of layers. If the parameter is true, an upper layer also
// supplies the directory.
TEST_P(OverlayInodeLowerLayers, Subdirectories) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const bool has_upper = GetParam();

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
              SyscallSucceeds());
  auto umount_base = Cleanup(
      [&base] { EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds()); });

  const std::string top = JoinPath(base.path(), "top");
  const std::string bottom = JoinPath(base.path(), "bottom");
  const std::string upper = JoinPath(base.path(), "upper");
  const std::string work = JoinPath(base.path(), "work");
  const std::string merged = JoinPath(base.path(), "merged");
  for (const std::string& dir :
       {top, bottom, upper, work, merged, JoinPath(top, "sub"),
        JoinPath(bottom, "sub"), JoinPath(upper, "sub"),
        JoinPath(top, "sub/all"), JoinPath(bottom, "sub/all"),
        JoinPath(upper, "sub/all"), JoinPath(top, "sub/lower_both"),
        JoinPath(bottom, "sub/lower_both"), JoinPath(upper, "sub/upper_bottom"),
        JoinPath(bottom, "sub/upper_bottom"), JoinPath(top, "sub/top_only"),
        JoinPath(bottom, "sub/bottom_only"), JoinPath(upper, "sub/upper_only"),
        JoinPath(bottom, "sub/file_over_dir")}) {
    ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  }
  {
    const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
        Open(JoinPath(top, "sub/file_over_dir"), O_CREAT | O_WRONLY, 0644));
  }

  std::string opts = absl::StrCat("lowerdir=", top, ":", bottom);
  if (has_upper) {
    absl::StrAppend(&opts, ",upperdir=", upper, ",workdir=", work);
  }
  ASSERT_THAT(mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()),
              SyscallSucceeds());
  auto umount_merged = Cleanup(
      [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });

  const std::string sub = JoinPath(merged, "sub");
  std::vector<std::string> names = {"all",      "lower_both",  "upper_bottom",
                                    "top_only", "bottom_only", "file_over_dir"};
  if (has_upper) {
    names.push_back("upper_only");
  }
  struct stat sub_stat;
  ASSERT_THAT(stat(sub.c_str(), &sub_stat), SyscallSucceeds());
  EXPECT_EQ(DirentIno(merged, "sub"), sub_stat.st_ino);
  for (const std::string& name : names) {
    SCOPED_TRACE(name);
    struct stat st;
    ASSERT_THAT(stat(JoinPath(sub, name).c_str(), &st), SyscallSucceeds());
    EXPECT_EQ(st.st_dev, sub_stat.st_dev);
    EXPECT_EQ(DirentIno(sub, name), st.st_ino);
  }
}

INSTANTIATE_TEST_SUITE_P(WithAndWithoutUpper, OverlayInodeLowerLayers,
                         ::testing::Bool());

enum class FileLayer { kLower, kUpper, kCopiedUp };

class OverlayInodeUnlinked : public ::testing::TestWithParam<bool> {};

// An open, unlinked upper hard link keeps the copied-up file's identity even
// after the other overlay dentry is destroyed.
TEST_P(OverlayInodeUnlinked, HardLinkIdentity) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  TempPath base;
  std::string merged;
  Cleanup umount_base;
  Cleanup umount_merged;
  FileDescriptor held;
  struct stat before;
  {
    const DisableSave ds;
    base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    // An overlay cannot be the upper layer of another overlay mount.
    SKIP_IF(!GetParam() && ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(base.path())));
    if (GetParam()) {
      ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
                  SyscallSucceeds());
      umount_base = Cleanup([&base] {
        EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds());
      });
    }
    const std::string lower = JoinPath(base.path(), "lower");
    const std::string upper = JoinPath(base.path(), "upper");
    const std::string work = JoinPath(base.path(), "work");
    merged = JoinPath(base.path(), "merged");
    for (const std::string& dir : {lower, upper, work, merged}) {
      ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
    }
    {
      const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
          Open(JoinPath(lower, "a"), O_CREAT | O_WRONLY, 0644));
    }
    const std::string opts = absl::StrCat(
        "lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
    ASSERT_THAT(mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()),
                SyscallSucceeds());
    umount_merged = Cleanup(
        [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });
    const std::string a = JoinPath(merged, "a");
    const std::string b = JoinPath(merged, "b");
    {
      const FileDescriptor copied =
          ASSERT_NO_ERRNO_AND_VALUE(Open(a, O_WRONLY));
    }
    ASSERT_THAT(link(a.c_str(), b.c_str()), SyscallSucceeds());
    held = ASSERT_NO_ERRNO_AND_VALUE(Open(b, O_RDWR));
    ASSERT_THAT(fstat(held.get(), &before), SyscallSucceeds());
    ASSERT_THAT(unlink(b.c_str()), SyscallSucceeds());
    ASSERT_THAT(unlink(a.c_str()), SyscallSucceeds());
    struct stat unlinked;
    ASSERT_THAT(fstat(held.get(), &unlinked), SyscallSucceeds());
    EXPECT_EQ(unlinked.st_nlink, 0);
    EXPECT_EQ(unlinked.st_dev, before.st_dev);
    EXPECT_EQ(unlinked.st_ino, before.st_ino);
  }

  MaybeSave();
  struct stat after;
  ASSERT_THAT(fstat(held.get(), &after), SyscallSucceeds());
  EXPECT_EQ(after.st_nlink, 0);
  EXPECT_EQ(after.st_dev, before.st_dev);
  EXPECT_EQ(after.st_ino, before.st_ino);
  ASSERT_THAT(write(held.get(), "x", 1), SyscallSucceedsWithValue(1));
  MaybeSave();
  ASSERT_THAT(fstat(held.get(), &after), SyscallSucceeds());
  EXPECT_EQ(after.st_size, 1);
  EXPECT_EQ(after.st_nlink, 0);
  EXPECT_EQ(after.st_dev, before.st_dev);
  EXPECT_EQ(after.st_ino, before.st_ino);
}

INSTANTIATE_TEST_SUITE_P(TmpfsAndBackingFilesystem, OverlayInodeUnlinked,
                         ::testing::Bool());

class OverlayInodeRestore : public ::testing::TestWithParam<FileLayer> {};

// Unchanged files keep their identities across restore even when no file
// description retains their overlay dentries.
TEST_P(OverlayInodeRestore, StableIdentityWithoutOpenDescriptors) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  TempPath base;
  std::string merged;
  Cleanup umount_base;
  Cleanup umount_merged;
  constexpr int kFileCount = 3002;
  std::vector<struct stat> before(kFileCount);
  FileDescriptor held[2];
  {
    const DisableSave ds;
    base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
                SyscallSucceeds());
    umount_base = Cleanup([&base] {
      EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds());
    });
    const std::string lower = JoinPath(base.path(), "lower");
    const std::string upper = JoinPath(base.path(), "upper");
    const std::string work = JoinPath(base.path(), "work");
    merged = JoinPath(base.path(), "merged");
    for (const std::string& dir : {lower, upper, work, merged}) {
      ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
    }
    for (int i = 0; i < kFileCount; ++i) {
      const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
          Open(JoinPath(GetParam() == FileLayer::kUpper ? upper : lower,
                        absl::StrCat(i)),
               O_CREAT | O_WRONLY, 0644));
    }
    const std::string opts = absl::StrCat(
        "lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
    ASSERT_THAT(mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()),
                SyscallSucceeds());
    umount_merged = Cleanup(
        [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });
    if (GetParam() == FileLayer::kCopiedUp) {
      for (int i = 0; i < kFileCount; ++i) {
        const FileDescriptor copied = ASSERT_NO_ERRNO_AND_VALUE(
            Open(JoinPath(merged, absl::StrCat(i)), O_WRONLY));
      }
    }
    for (int i = 0; i < 2; ++i) {
      held[i] = ASSERT_NO_ERRNO_AND_VALUE(
          Open(JoinPath(merged, absl::StrCat(i)), O_RDONLY));
    }
    for (int i = 0; i < kFileCount; ++i) {
      ASSERT_THAT(stat(JoinPath(merged, absl::StrCat(i)).c_str(), &before[i]),
                  SyscallSucceeds());
    }
  }

  MaybeSave();
  {
    const DisableSave ds;
    for (int i = 0; i < kFileCount; ++i) {
      SCOPED_TRACE(i);
      struct stat after;
      ASSERT_THAT(stat(JoinPath(merged, absl::StrCat(i)).c_str(), &after),
                  SyscallSucceeds());
      EXPECT_EQ(before[i].st_dev, after.st_dev);
      EXPECT_EQ(before[i].st_ino, after.st_ino);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(AllLayers, OverlayInodeRestore,
                         ::testing::Values(FileLayer::kLower, FileLayer::kUpper,
                                           FileLayer::kCopiedUp));

// Lower hard links share one inode. Copy-up of one name breaks the link:
// that name gets a new inode, and the other name keeps the original.
// With save/restore, the copy-up is an fchmod on a descriptor opened
// before the save, so no path lookup runs first.
TEST(OverlayInode, BrokenHardLink) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  TempPath base;
  std::string merged;
  Cleanup umount_base;
  Cleanup umount_merged;
  std::string merged_sub;
  std::string merged_file;
  std::string merged_link;
  FileDescriptor file_fd;
  FileDescriptor link_fd;
  struct stat file_stat;
  struct stat link_stat;
  {
    const DisableSave ds;
    base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(mount("", base.path().c_str(), "tmpfs", 0, ""),
                SyscallSucceeds());
    umount_base = Cleanup([&base] {
      EXPECT_THAT(umount(base.path().c_str()), SyscallSucceeds());
    });

    const std::string lower = JoinPath(base.path(), "lower");
    const std::string upper = JoinPath(base.path(), "upper");
    const std::string work = JoinPath(base.path(), "work");
    merged = JoinPath(base.path(), "merged");
    for (const std::string& dir : {lower, upper, work, merged}) {
      ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
    }
    const std::string sub = JoinPath(lower, "sub");
    ASSERT_THAT(mkdir(sub.c_str(), 0755), SyscallSucceeds());
    const std::string lower_file = JoinPath(sub, "file");
    const std::string lower_link = JoinPath(sub, "link");
    {
      const FileDescriptor created = ASSERT_NO_ERRNO_AND_VALUE(
          Open(lower_file, O_CREAT | O_WRONLY | O_TRUNC, 0644));
      ASSERT_THAT(write(created.get(), "a", 1), SyscallSucceedsWithValue(1));
    }
    ASSERT_THAT(link(lower_file.c_str(), lower_link.c_str()),
                SyscallSucceeds());

    const std::string opts = absl::StrCat(
        "lowerdir=", lower, ",upperdir=", upper, ",workdir=", work);
    ASSERT_THAT(mount("overlay", merged.c_str(), "overlay", 0, opts.c_str()),
                SyscallSucceeds());
    umount_merged = Cleanup(
        [&merged] { EXPECT_THAT(umount(merged.c_str()), SyscallSucceeds()); });

    merged_sub = JoinPath(merged, "sub");
    merged_file = JoinPath(merged_sub, "file");
    merged_link = JoinPath(merged_sub, "link");
    ASSERT_THAT(stat(merged_file.c_str(), &file_stat), SyscallSucceeds());
    ASSERT_THAT(stat(merged_link.c_str(), &link_stat), SyscallSucceeds());
    EXPECT_EQ(file_stat.st_dev, link_stat.st_dev);
    EXPECT_EQ(file_stat.st_ino, link_stat.st_ino);
    EXPECT_EQ(DirentIno(merged_sub, "file"), file_stat.st_ino);
    EXPECT_EQ(DirentIno(merged_sub, "link"), link_stat.st_ino);
    file_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(merged_file, O_RDONLY));
    link_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(merged_link, O_RDONLY));
  }

  MaybeSave();
  ASSERT_THAT(fchmod(file_fd.get(), 0600), SyscallSucceeds());
  struct stat file_after;
  struct stat link_after;
  ASSERT_THAT(fstat(file_fd.get(), &file_after), SyscallSucceeds());
  ASSERT_THAT(fstat(link_fd.get(), &link_after), SyscallSucceeds());
  EXPECT_EQ(file_stat.st_dev, file_after.st_dev);
  EXPECT_EQ(link_stat.st_dev, link_after.st_dev);
  EXPECT_EQ(link_stat.st_ino, link_after.st_ino);
  EXPECT_NE(file_after.st_ino, link_after.st_ino);
  EXPECT_EQ(DirentIno(merged_sub, "file"), file_after.st_ino);
  EXPECT_EQ(DirentIno(merged_sub, "link"), link_after.st_ino);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
