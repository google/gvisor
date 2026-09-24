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
#include <stdint.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Extended attribute names for POSIX ACLs.
constexpr char kAccessACL[] = "system.posix_acl_access";
constexpr char kDefaultACL[] = "system.posix_acl_default";

// POSIX ACL constants.
constexpr uint32_t kACLVersion = 2;
constexpr uint16_t kUserObj = 0x01;
constexpr uint16_t kUser = 0x02;
constexpr uint16_t kGroupObj = 0x04;
constexpr uint16_t kGroup = 0x08;
constexpr uint16_t kMask = 0x10;
constexpr uint16_t kOther = 0x20;
constexpr uint32_t kUndef = 0xffffffff;

// Permission bits.
constexpr uint16_t kR = 0x04;
constexpr uint16_t kW = 0x02;
constexpr uint16_t kX = 0x01;

constexpr uid_t kNobody = 65534;

// ACLEntry mirrors struct posix_acl_xattr_entry.
struct ACLEntry {
  uint16_t tag;
  uint16_t perm;
  uint32_t id;
};
static_assert(sizeof(ACLEntry) == 8, "unexpected ACLEntry size");

ACLEntry Ent(int tag, int perm, uint32_t id) {
  return ACLEntry{static_cast<uint16_t>(tag), static_cast<uint16_t>(perm), id};
}

// BuildACL builds the raw xattr representation for a POSIX ACL.
std::string BuildACL(const std::vector<ACLEntry>& entries) {
  uint32_t version = kACLVersion;
  std::string buf(reinterpret_cast<const char*>(&version), sizeof(version));
  for (const ACLEntry& e : entries) {
    buf.append(reinterpret_cast<const char*>(&e), sizeof(e));
  }
  return buf;
}

// ParseACL parses a raw ACL value into its entries.
std::vector<ACLEntry> ParseACL(const std::string& blob) {
  std::vector<ACLEntry> out;
  for (size_t off = sizeof(uint32_t); off + sizeof(ACLEntry) <= blob.size();
       off += sizeof(ACLEntry)) {
    ACLEntry e;
    memcpy(&e, blob.data() + off, sizeof(e));
    out.push_back(e);
  }
  return out;
}

// FindEntryPerm returns the permission of the first entry matching tag (and id
// for named user/group tags), or -1 if not found.
int FindEntryPerm(const std::string& blob, uint16_t tag, uint32_t id) {
  for (const ACLEntry& e : ParseACL(blob)) {
    if (e.tag != tag) continue;
    if ((tag == kUser || tag == kGroup) && e.id != id) continue;
    return e.perm;
  }
  return -1;
}

// GetXattrString reads an xattr into a string.
PosixErrorOr<std::string> GetXattrString(const std::string& path,
                                         const char* name) {
  char buf[512];
  int n = getxattr(path.c_str(), name, buf, sizeof(buf));
  if (n < 0) {
    return PosixError(errno, "getxattr");
  }
  return std::string(buf, n);
}

// ListContainsName reports whether a listxattr(2) result contains name.
bool ListContainsName(const char* list, int len, const char* name) {
  for (int i = 0; i < len; i += strlen(list + i) + 1) {
    if (strcmp(list + i, name) == 0) {
      return true;
    }
  }
  return false;
}

// Backend selects the filesystem the ACL tests run against.
//
// When support for POSIX ACLs is added to a new filesystem, it should be added
// here.
enum class Backend {
  kTmpfs,         // plain tmpfs
  kOverlayUpper,  // an overlay whose object is created in the upper layer
  kOverlayLower,  // an overlay whose object starts in the lower layer and is
                  // copied up on the first modifying operation
};

class PosixACLTest : public ::testing::TestWithParam<Backend> {
 protected:
  void SetUp() override {
    // Use /dev/shm to allow tmpfs tests to run without privilege.
    base_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/dev/shm"));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(base_.path())));

    const auto param = GetParam();
    switch (param) {
      case Backend::kTmpfs:
        dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_.path()));
        break;
      case Backend::kOverlayUpper:
      case Backend::kOverlayLower:
        MountOverlay(param);
        SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(dir_.path())));
    }

    file_ = JoinPath(dir_.path(), "posix_acl_test_file");
    subdir_ = JoinPath(dir_.path(), "subdir");
    sub_subdir_ = JoinPath(subdir_, "subsubdir");

    // For the lower-layer case the objects were already seeded in the lower
    // directory by MountOverlay(); the first modifying syscall in each test
    // will copy them up. Otherwise create them now: directly on tmpfs, or
    // through the merged mount (landing in the upper layer).
    if (GetParam() != Backend::kOverlayLower) {
      ASSERT_NO_ERRNO_AND_VALUE(Open(file_, O_CREAT | O_RDWR, 0644));
      ASSERT_THAT(chmod(file_.c_str(), 0644), SyscallSucceeds());
      ASSERT_THAT(mkdir(subdir_.c_str(), 0755), SyscallSucceeds());
      ASSERT_THAT(mkdir(sub_subdir_.c_str(), 0755), SyscallSucceeds());
    }

    uid_ = getuid();
    gid_ = getgid();
  }

  // MountOverlay mounts an overlay at dir_.
  void MountOverlay(const ParamType param) {
    // Mounting an overlay requires CAP_SYS_ADMIN
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

    // gVisor doesn't accept /dev/shm as an overlayfs layer. We need
    // CAP_SYS_ADMIN for this case anyways, so just mount a separate tmpfs.
    layers_ = JoinPath(base_.path(), "layers");
    ASSERT_THAT(mkdir(layers_.c_str(), 0755), SyscallSucceeds());
    ASSERT_THAT(mount("tmpfs", layers_.c_str(), "tmpfs", 0, "mode=0755"),
                SyscallSucceeds());
    tmpfs_mounted_ = true;

    const std::string lower = JoinPath(layers_, "lower");
    const std::string upper = JoinPath(layers_, "upper");
    const std::string work = JoinPath(layers_, "work");
    for (const std::string& d : {lower, upper, work}) {
      ASSERT_THAT(mkdir(d.c_str(), 0755), SyscallSucceeds());
    }

    // dir_ is the merged mount point.
    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_.path()));

    if (param == Backend::kOverlayLower) {
      const std::string lfile = JoinPath(lower, "posix_acl_test_file");
      ASSERT_NO_ERRNO_AND_VALUE(Open(lfile, O_CREAT | O_RDWR, 0644));
      ASSERT_THAT(chmod(lfile.c_str(), 0644), SyscallSucceeds());
      ASSERT_THAT(mkdir(JoinPath(lower, "subdir").c_str(), 0755),
                  SyscallSucceeds());
      ASSERT_THAT(mkdir(JoinPath(lower, "subdir/subsubdir").c_str(), 0755),
                  SyscallSucceeds());
    }

    const std::string opts =
        "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;
    ASSERT_THAT(
        mount("overlay", dir_.path().c_str(), "overlay", 0, opts.c_str()),
        SyscallSucceeds());
    overlay_mounted_ = true;
  }

  void TearDown() override {
    // Unmount inner-to-outer, before the TempPath destructors remove the (now
    // empty) mount points.
    if (overlay_mounted_) {
      EXPECT_THAT(umount2(dir_.path().c_str(), MNT_DETACH), SyscallSucceeds());
    }
    if (tmpfs_mounted_) {
      EXPECT_THAT(umount2(layers_.c_str(), MNT_DETACH), SyscallSucceeds());
    }
  }

  TempPath base_;
  TempPath dir_;
  std::string layers_;
  bool tmpfs_mounted_ = false;
  bool overlay_mounted_ = false;
  std::string file_;
  std::string subdir_;
  std::string sub_subdir_;
  uid_t uid_;
  gid_t gid_;
};

// Setting an access ACL and reading it back returns an identical blob.
TEST_P(PosixACLTest, SetGetAccessACL) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kGroup, kR | kW, gid_),
      Ent(kMask, kR | kW, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(file_, kAccessACL));
  EXPECT_EQ(got, acl);
}

// getxattr reports the size when passed a zero-length buffer.
TEST_P(PosixACLTest, GetAccessACLSize) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR | kW, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallSucceedsWithValue(acl.size()));
}

// getxattr on a file with no ACL returns ENODATA.
TEST_P(PosixACLTest, GetAccessACLNoData) {
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

// Setting an extended access ACL updates the file mode: the owner/other bits
// come from USER_OBJ/OTHER, and the group bits reflect the mask.
TEST_P(PosixACLTest, AccessACLUpdatesMode) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),    // owner rw-
      Ent(kUser, kR, uid_),              //
      Ent(kGroupObj, kR, kUndef),        // group_obj r--
      Ent(kMask, kR | kW | kX, kUndef),  // mask rwx (surfaces as group bits)
      Ent(kOther, kR, kUndef),           // other r--
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0674);
}

// A minimal ACL (only the three base entries, no mask/named entries) is
// equivalent to a mode: it is folded into the mode and not stored.
TEST_P(PosixACLTest, MinimalAccessACLFoldsToMode) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW | kX, kUndef),
      Ent(kGroupObj, kR | kX, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0754);

  // No extended ACL is stored.
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

// An extended access ACL appears in listxattr; removing it makes it disappear.
TEST_P(PosixACLTest, ListAndRemoveAccessACL) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  char list[512];
  int n = listxattr(file_.c_str(), list, sizeof(list));
  ASSERT_THAT(n, SyscallSucceeds());
  EXPECT_TRUE(ListContainsName(list, n, kAccessACL));

  ASSERT_THAT(removexattr(file_.c_str(), kAccessACL), SyscallSucceeds());
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  n = listxattr(file_.c_str(), list, sizeof(list));
  ASSERT_THAT(n, SyscallSucceeds());
  EXPECT_FALSE(ListContainsName(list, n, kAccessACL));
}

// A default ACL cannot be set on a non-directory.
TEST_P(PosixACLTest, DefaultACLOnFileFails) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kGroupObj, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  EXPECT_THAT(setxattr(file_.c_str(), kDefaultACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EACCES));
}

// A default ACL can be set on and read back from a directory, and appears in
// listxattr.
TEST_P(PosixACLTest, SetGetDefaultACLOnDir) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW | kX, kUndef),
      Ent(kUser, kR | kX, uid_),
      Ent(kGroupObj, kR | kX, kUndef),
      Ent(kMask, kR | kX, kUndef),
      Ent(kOther, kR | kX, kUndef),
  });
  ASSERT_THAT(setxattr(subdir_.c_str(), kDefaultACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(subdir_, kDefaultACL));
  EXPECT_EQ(got, acl);

  char list[512];
  int n = listxattr(subdir_.c_str(), list, sizeof(list));
  ASSERT_THAT(n, SyscallSucceeds());
  EXPECT_TRUE(ListContainsName(list, n, kDefaultACL));
}

// A file created in a directory with a default ACL inherits an access ACL
// derived from that default ACL. A subdirectory also inherits the default ACL.
TEST_P(PosixACLTest, DefaultACLInheritance) {
  const std::string dacl = BuildACL({
      Ent(kUserObj, kR | kW | kX, kUndef),
      Ent(kUser, kR | kX, uid_),
      Ent(kGroupObj, kR | kX, kUndef),
      Ent(kMask, kR | kW | kX, kUndef),
      Ent(kOther, kR | kX, kUndef),
  });
  ASSERT_THAT(
      setxattr(subdir_.c_str(), kDefaultACL, dacl.data(), dacl.size(), 0),
      SyscallSucceeds());

  // A regular child inherits an access ACL that names the user, but no default
  // ACL.
  const std::string child = JoinPath(subdir_, "child");
  {
    ASSERT_NO_ERRNO_AND_VALUE(Open(child, O_CREAT | O_RDWR, 0666));
  }

  const std::string cacl =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(child, kAccessACL));
  EXPECT_EQ(FindEntryPerm(cacl, kUser, uid_), kR | kX)
      << "child access ACL should inherit the named user from the default ACL";
  EXPECT_THAT(getxattr(child.c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // A child directory inherits the default ACL verbatim as its own default ACL.
  const std::string childdir = JoinPath(subdir_, "childdir");
  ASSERT_THAT(mkdir(childdir.c_str(), 0777), SyscallSucceeds());
  const std::string cdacl =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(childdir, kDefaultACL));
  EXPECT_EQ(cdacl, dacl);
}

// When a directory in lower with no default ACL, but whose parent has since
// been given a default ACL in upper, is copied up, it should *not* inherit
// the upper parent's default ACL.
//
// As a result, children created in the directory should not inherit the
// parent's default ACL.
TEST_P(PosixACLTest, CopyUpDirectoryDoesNotInheritDefaultACL) {
  // Only valid for overlayfs-lower.
  SKIP_IF(GetParam() != Backend::kOverlayLower);

  // First, copy-up the dir's parent with a default ACL.
  const std::string dacl = BuildACL({
      Ent(kUserObj, kR | kW | kX, kUndef),
      Ent(kUser, kR | kX, uid_),
      Ent(kGroupObj, kR | kX, kUndef),
      Ent(kMask, kR | kW | kX, kUndef),
      Ent(kOther, kR | kX, kUndef),
  });
  ASSERT_THAT(
      setxattr(subdir_.c_str(), kDefaultACL, dacl.data(), dacl.size(), 0),
      SyscallSucceeds());

  // Trigger copy-up of the directory by creating a file in it.
  const std::string child_file = JoinPath(sub_subdir_, "child_file");
  ASSERT_NO_ERRNO_AND_VALUE(Open(child_file, O_CREAT | O_RDWR, 0666));

  // The directory should not get an ACL in upper after copy-up.
  EXPECT_THAT(getxattr(sub_subdir_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(getxattr(sub_subdir_.c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // Existing file children should not get a spurious access ACL.
  EXPECT_THAT(getxattr(child_file.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // A new subdirectory should not get a spurious ACL (access or default).
  const std::string child_dir = JoinPath(sub_subdir_, "child_dir");
  ASSERT_THAT(mkdir(child_dir.c_str(), 0777), SyscallSucceeds());
  EXPECT_THAT(getxattr(child_dir.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(getxattr(child_dir.c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

// Removing a POSIX ACL on an overlay-lower file that has not been copied-up
// and has no POSIX ACL should not result in the file being copied up; instead,
// it should return ENODATA.
TEST_P(PosixACLTest, RemoveACLOnFileNotCopiedUp) {
  // Only valid for overlayfs-lower.
  SKIP_IF(GetParam() != Backend::kOverlayLower);

  KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
  if (version.major > 6 || (version.major == 6 && version.minor >= 2)) {
    // Setting an empty string "" xattr for a POSIX ACL only clears the ACL on
    // kernel >=6.2. Older kernels give EINVAL.
    EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, "", 0, 0),
                SyscallFailsWithErrno(ENODATA));
  }
  EXPECT_THAT(removexattr(file_.c_str(), kAccessACL),
              SyscallFailsWithErrno(ENODATA));

  // Removing a *default* ACL should succeed (but still skip copy-up)
  EXPECT_THAT(removexattr(file_.c_str(), kDefaultACL), SyscallSucceeds());
  EXPECT_THAT(removexattr(file_.c_str(), kAccessACL),
              SyscallFailsWithErrno(ENODATA));
}

// Regression test for overlayfs not setting the mode on copy-up.
//
// Lower has dir D (0755, no ACLs) containing char device N (0666, no ACL).
// Through the overlay, set a default ACL on D with a restrictive mask. Upper D
// now carries that default ACL.
//
// If N is copied-up for any reason, the default ACL should *not* affect its
// mode in the upper.
TEST_P(PosixACLTest, DeviceFileModeUnaffectedByPostCopyUpParentDefaultACL) {
  // Only valid for overlayfs-lower.
  SKIP_IF(GetParam() != Backend::kOverlayLower);

  // CAP_MKNOD necessary to make a device file
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_MKNOD)));

  const auto dirLower = JoinPath(layers_, "lower", "subdir");
  ASSERT_THAT(chmod(dirLower.c_str(), 0755), SyscallSucceeds());

  // Make a null S_IFCHR device file
  const auto pathLower = JoinPath(dirLower, "null");
  const dev_t dev = makedev(1, 3);
  ASSERT_THAT(mknod(pathLower.c_str(), S_IFCHR | 0666, dev), SyscallSucceeds());
  ASSERT_THAT(chmod(pathLower.c_str(), 0666),
              SyscallSucceeds());  // adjust for possible umask

  // Sanity check that the resulting device file mode was indeed 0666
  const auto path = JoinPath(subdir_, "null");
  struct stat st = {};
  ASSERT_THAT(stat(path.c_str(), &st), SyscallSucceeds());
  ASSERT_EQ(st.st_mode & 0777, 0666);

  // Set a default ACL with a restrictive mask on dir, through the overlay
  // (triggering copy-up)
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR | kW, uid_),
      Ent(kGroupObj, 0, kUndef),
      Ent(kMask, 0, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(subdir_.c_str(), kDefaultACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Trigger a copy-up of the device file
  ASSERT_THAT(chown(path.c_str(), kNobody, kNobody), SyscallSucceeds());

  // The device file's mode should be unchanged
  ASSERT_THAT(stat(path.c_str(), &st), SyscallSucceeds());
  ASSERT_EQ(st.st_mode & 0777, 0666);
}

// chmod on a file with an extended ACL updates USER_OBJ, the mask, and OTHER
// (not the GROUP_OBJ entry).
TEST_P(PosixACLTest, ChmodUpdate) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR | kW, uid_),
      Ent(kGroupObj, kR, kUndef),  // group_obj r--
      Ent(kMask, kR, kUndef),      // mask r--
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Update u:r, g:rw, o:0.
  ASSERT_THAT(chmod(file_.c_str(), 0460), SyscallSucceeds());

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(file_, kAccessACL));
  // USER_OBJ, MASK, and OTHER should have been updated.
  EXPECT_EQ(FindEntryPerm(got, kUserObj, kUndef), kR);
  EXPECT_EQ(FindEntryPerm(got, kMask, kUndef), kR | kW);
  EXPECT_EQ(FindEntryPerm(got, kOther, kUndef), 0);
  // GROUP_OBJ should have b leave GROUP_OBJ untouched.
  EXPECT_EQ(FindEntryPerm(got, kGroupObj, kUndef), kR);

  // The mode should be 460 (as we set).
  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0460);
}

// A named-user ACL entry grants access that the mode bits alone would deny, and
// the mask caps that access.
TEST_P(PosixACLTest, NamedUserEnforcement) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // Without an ACL granting access, "nobody" cannot read a 0600 file.
  ASSERT_THAT(chmod(file_.c_str(), 0600), SyscallSucceeds());
  {
    ScopedThread t([&] {
      EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());
      EXPECT_THAT(open(file_.c_str(), O_RDONLY), SyscallFailsWithErrno(EACCES));
    });
  }

  // Grant "nobody" read via a named-user entry; the mask allows only read.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR | kW | kX, kNobody),  // capped by the mask
      Ent(kGroupObj, 0, kUndef),
      Ent(kMask, kR, kUndef),  // mask r-- : nobody effectively gets r-- only
      Ent(kOther, 0, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  ScopedThread([&] {
    EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());
    // Read is granted by the ACL.
    int rfd = open(file_.c_str(), O_RDONLY);
    EXPECT_THAT(rfd, SyscallSucceeds());
    if (rfd >= 0) close(rfd);
    // Write is denied because the mask limits nobody to read.
    int wfd = open(file_.c_str(), O_WRONLY);
    EXPECT_THAT(wfd, SyscallFailsWithErrno(EACCES));
    if (wfd >= 0) close(wfd);
  });
}

// A named-group ACL entry grants access to a process in that group that the
// mode bits alone would deny, capped by the mask.
TEST_P(PosixACLTest, NamedGroupEnforcement) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));

  // Grant group "nobody" read+write, but the mask caps the group class to read.
  // Owner keeps rw; group_obj and other get nothing.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kGroupObj, 0, kUndef),
      Ent(kGroup, kR | kW, kNobody),  // capped by the mask
      Ent(kMask, kR, kUndef),         // mask r-- : group class limited to read
      Ent(kOther, 0, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  ScopedThread([&] {
    // Become a member of only the named group and a non-owner user.
    EXPECT_THAT(syscall(SYS_setgroups, 0, nullptr), SyscallSucceeds());
    EXPECT_THAT(syscall(SYS_setgid, kNobody), SyscallSucceeds());
    EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());
    // Read is granted via the named group.
    int rfd = open(file_.c_str(), O_RDONLY);
    EXPECT_THAT(rfd, SyscallSucceeds());
    if (rfd >= 0) close(rfd);
    // Write is denied due to the mask.
    int wfd = open(file_.c_str(), O_WRONLY);
    EXPECT_THAT(wfd, SyscallFailsWithErrno(EACCES));
    if (wfd >= 0) close(wfd);
  });
}

// A restrictive USER_OBJ locks the user out of their own file, even
// if group/other would otherwise grant the access.
TEST_P(PosixACLTest, UserObjLocksSelfOutEnforcement) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));

  // Drop special capabilities if present
  AutoCapability dacOverride(CAP_DAC_OVERRIDE, false);
  AutoCapability dacReadSearch(CAP_DAC_READ_SEARCH, false);

  // Read succeeds by default.
  int rfd = open(file_.c_str(), O_RDONLY);
  EXPECT_THAT(rfd, SyscallSucceeds());

  // New ACL: everybody has read-only access, except USER_OBJ which has none.
  const std::string acl = BuildACL({
      Ent(kUserObj, 0, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Read now fails.
  rfd = open(file_.c_str(), O_RDONLY);
  EXPECT_THAT(rfd, SyscallFailsWithErrno(EACCES));
}

// A restrictive named USER locks the user out of their own file, even
// if group/other would otherwise grant the access.
TEST_P(PosixACLTest, NamedUserLocksSelfOutEnforcement) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));

  // Drop special capabilities if present
  AutoCapability dacOverride(CAP_DAC_OVERRIDE, false);
  AutoCapability dacReadSearch(CAP_DAC_READ_SEARCH, false);

  // Read succeeds by default.
  int rfd = open(file_.c_str(), O_RDONLY);
  EXPECT_THAT(rfd, SyscallSucceeds());

  // Make the file owned by uid kNobody.
  ASSERT_THAT(chown(file_.c_str(), kNobody, gid_), SyscallSucceeds());

  // New ACL: everybody has read-only access, except for USER uid_.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR, kUndef),
      Ent(kUser, 0, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Read now fails.
  rfd = open(file_.c_str(), O_RDONLY);
  EXPECT_THAT(rfd, SyscallFailsWithErrno(EACCES));
}

// Only the file owner (or a suitably privileged process) may set an ACL, even
// with write permission on the file.
TEST_P(PosixACLTest, SetACLRequiresOwnership) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // World-writable file owned by the (root) test process.
  ASSERT_THAT(chmod(file_.c_str(), 0666), SyscallSucceeds());
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, kNobody),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  ScopedThread([&] {
    EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());
    EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
                SyscallFailsWithErrno(EPERM));
  });
}

// An exception to the above case: default ACLs on non-directories can be
// "cleared" by anyone.
TEST_P(PosixACLTest, ClearDefaultACLNonOwner) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // File owned by the test process with no permissions granted to
  // anyone else.
  ASSERT_THAT(chmod(file_.c_str(), 0600), SyscallSucceeds());

  ScopedThread([&] {
    EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());
    EXPECT_THAT(removexattr(file_.c_str(), kDefaultACL), SyscallSucceeds());
  });
}

// POSIX access ACLs should work properly with symlinks.
TEST_P(PosixACLTest, SetAccessACLSymlink) {
  // Create a symlink to a file
  auto sym = JoinPath(dir_.path(), "posix_acl_test_symlink");
  ASSERT_THAT(symlink(file_.c_str(), sym.c_str()), SyscallSucceeds());
  auto cleanup = Cleanup([&sym] { unlink(sym.c_str()); });

  // Setting an ACL *through* the symlink should succeed.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  EXPECT_THAT(setxattr(sym.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Fetching an ACL *through* the symlink should succeed.
  EXPECT_THAT(getxattr(sym.c_str(), kAccessACL, nullptr, 0), SyscallSucceeds());

  // Removing an ACL *through* the symlink should succeed.
  EXPECT_THAT(removexattr(sym.c_str(), kAccessACL), SyscallSucceeds());

  // Setting an ACL *on* the symlink itself should fail.
  EXPECT_THAT(lsetxattr(sym.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EOPNOTSUPP));

  // Fetching the ACL *of* the symlink itself should also fail.
  EXPECT_THAT(lgetxattr(sym.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(EOPNOTSUPP));

  // Removing an ACL *of* the symlink itself should also fail.
  EXPECT_THAT(syscall(SYS_lremovexattr, sym.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

// POSIX default ACLs should work properly with symlinks.
TEST_P(PosixACLTest, SetDefaultACLSymlink) {
  // Create a symlink to a directory
  auto sym = JoinPath(dir_.path(), "posix_acl_test_symlink");
  ASSERT_THAT(symlink(dir_.path().c_str(), sym.c_str()), SyscallSucceeds());
  auto cleanup = Cleanup([&sym] { unlink(sym.c_str()); });

  // Setting an ACL *through* the symlink should succeed.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  EXPECT_THAT(setxattr(sym.c_str(), kDefaultACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Fetching an ACL *through* the symlink should succeed.
  EXPECT_THAT(getxattr(sym.c_str(), kDefaultACL, nullptr, 0),
              SyscallSucceeds());

  // Removing an ACL *through* the symlink should succeed.
  EXPECT_THAT(removexattr(sym.c_str(), kDefaultACL), SyscallSucceeds());

  // Setting an ACL *on* the symlink itself should fail.
  EXPECT_THAT(lsetxattr(sym.c_str(), kDefaultACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EOPNOTSUPP));

  // Fetching the ACL *of* the symlink itself should also fail.
  EXPECT_THAT(lgetxattr(sym.c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(EOPNOTSUPP));

  // Removing an ACL *of* the symlink itself should also fail.
  EXPECT_THAT(syscall(SYS_lremovexattr, sym.c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

static bool IsTimespecLater(struct timespec a, struct timespec b) {
  if (a.tv_sec > b.tv_sec) {
    return true;
  }
  if (a.tv_sec == b.tv_sec && a.tv_nsec > b.tv_nsec) {
    return true;
  }
  return false;
}

TEST_P(PosixACLTest, SetACLUpdatesCTime) {
  // Fetch the original ctime
  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  struct timespec old_ctime = st.st_ctim;

  // Set an ACL on the file.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  absl::SleepFor(absl::Milliseconds(10));
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Fetch the new ctime
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(IsTimespecLater(st.st_ctim, old_ctime));
}

TEST_P(PosixACLTest, RemoveACLUpdatesCTime) {
  // Set an ACL on the file.
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Fetch the original ctime
  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  struct timespec old_ctime = st.st_ctim;

  // Remove the ACL
  absl::SleepFor(absl::Milliseconds(10));
  ASSERT_THAT(removexattr(file_.c_str(), kAccessACL), SyscallSucceeds());

  // Fetch the new ctime
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(IsTimespecLater(st.st_ctim, old_ctime));
}

TEST_P(PosixACLTest, SetACLClearsSGID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FSETID)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_CHOWN)));

  // Set the setgid bit
  ASSERT_THAT(chmod(file_.c_str(), S_ISGID | 0750), SyscallSucceeds());
  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(st.st_mode & S_ISGID);

  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Setting a POSIX ACL shouldn't clear the setgid bit if we have privilege
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(st.st_mode & S_ISGID);

  // If we drop privilege, setting a POSIX ACL *still* shouldn't clear the
  // setgid bit since we're the owning group
  {
    AutoCapability fsetid(CAP_FSETID, false);
    ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
                SyscallSucceeds());
    ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
    ASSERT_TRUE(st.st_mode & S_ISGID);
  }

  ASSERT_THAT(chown(file_.c_str(), kNobody, kNobody), SyscallSucceeds());
  ASSERT_THAT(chmod(file_.c_str(), S_ISGID | 0750), SyscallSucceeds());
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(st.st_mode & S_ISGID);

  // If we change the owning user/group, setting a POSIX ACL should *now* clear
  // the setgid bit
  AutoCapability fsetid(CAP_FSETID, false);
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_FALSE(st.st_mode & S_ISGID);
}

TEST_P(PosixACLTest, RemoveACLClearsSGID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FSETID)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_CHOWN)));

  // Set the setgid bit
  ASSERT_THAT(chmod(file_.c_str(), S_ISGID | 0750), SyscallSucceeds());
  struct stat st = {};
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(st.st_mode & S_ISGID);

  // Clearing a POSIX ACL shouldn't clear the setgid bit if we have privilege
  ASSERT_THAT(removexattr(file_.c_str(), kAccessACL), SyscallSucceeds());
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(st.st_mode & S_ISGID);

  // If we drop privilege, clearing a POSIX ACL *still* shouldn't clear the
  // setgid bit since we're the owning group
  {
    AutoCapability fsetid(CAP_FSETID, false);
    ASSERT_THAT(removexattr(file_.c_str(), kAccessACL), SyscallSucceeds());
    ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
    ASSERT_TRUE(st.st_mode & S_ISGID);
  }

  ASSERT_THAT(chown(file_.c_str(), kNobody, kNobody), SyscallSucceeds());
  ASSERT_THAT(chmod(file_.c_str(), S_ISGID | 0750), SyscallSucceeds());
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_TRUE(st.st_mode & S_ISGID);

  // If we change the owning user/group, clearing a POSIX ACL should *now* clear
  // the setgid bit
  AutoCapability fsetid(CAP_FSETID, false);
  ASSERT_THAT(removexattr(file_.c_str(), kAccessACL), SyscallSucceeds());
  ASSERT_THAT(stat(file_.c_str(), &st), SyscallSucceeds());
  ASSERT_FALSE(st.st_mode & S_ISGID);
}

TEST_P(PosixACLTest, SetACLEmpty) {
  if (!IsRunningOnGvisor()) {
    // Setting an empty string "" xattr for a POSIX ACL only clears the ACL on
    // kernel >=6.2. Older kernels give EINVAL.
    KernelVersion version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major < 6 || (version.major == 6 && version.minor < 2));
  }

  // Set an ACL on the file
  std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Setting a zero-length xattr as the ACL should be equivalent to calling
  // removexattr().
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, "", 0, 0), SyscallSucceeds());
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // Same for default ACLs.
  acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(
      setxattr(dir_.path().c_str(), kDefaultACL, acl.data(), acl.size(), 0),
      SyscallSucceeds());
  ASSERT_THAT(setxattr(dir_.path().c_str(), kDefaultACL, "", 0, 0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(dir_.path().c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // Clearing default ACL on a file with empty setxattr() should work.
  EXPECT_THAT(setxattr(file_.c_str(), kDefaultACL, "", 0, 0),
              SyscallSucceeds());
}

TEST_P(PosixACLTest, SetACLEmptyHeaderOnly) {
  std::string emptyACL = BuildACL({});

  // Set an ACL on the file
  std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Setting a zero-length xattr as the ACL should be equivalent to calling
  // removexattr().
  ASSERT_THAT(
      setxattr(file_.c_str(), kAccessACL, emptyACL.data(), emptyACL.size(), 0),
      SyscallSucceeds());
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // Same for default ACLs.
  acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(
      setxattr(dir_.path().c_str(), kDefaultACL, acl.data(), acl.size(), 0),
      SyscallSucceeds());
  ASSERT_THAT(setxattr(dir_.path().c_str(), kDefaultACL, emptyACL.data(),
                       emptyACL.size(), 0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(dir_.path().c_str(), kDefaultACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));

  // Clearing default ACL on a file with empty setxattr() should work.
  EXPECT_THAT(
      setxattr(file_.c_str(), kDefaultACL, emptyACL.data(), emptyACL.size(), 0),
      SyscallSucceeds());
}

TEST_P(PosixACLTest, SetACLIncompleteHeader) {
  // Set an ACL on the file
  char xattr[1] = {};
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, xattr, 1, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(PosixACLTest, SetACLWrongVersion) {
  std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });
  uint32_t version = 50000;
  memcpy(acl.data(), &version, sizeof(version));

  // Should fail with EOPNOTSUPP due to the incorrect version
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

TEST_P(PosixACLTest, SetACLNonWholeNumberEntries) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to the odd size
  EXPECT_THAT(
      setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size() - 1, 0),
      SyscallFailsWithErrno(EINVAL));
}

TEST_P(PosixACLTest, SetACLInvalidPermissionBits) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, 10, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to the USER.Perm = 10
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(PosixACLTest, SetACLMultipleObj) {
  std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to multiple USER_OBJ
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));

  acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to multiple GROUP_OBJ
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));

  acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to multiple OTHER
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));

  acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to multiple MASK
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(PosixACLTest, SetACLNonUniqueID) {
  // acl(5) documents this as causing an ACL to be invalid, however
  // Linux does not enforce this. So we won't either.

  std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kUser, kR | kW, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kGroupObj, kR, kUndef),
      Ent(kGroup, kR, gid_),
      Ent(kGroup, kR | kW, gid_),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());
}

TEST_P(PosixACLTest, SetACLNoObj) {
  const std::string acl = BuildACL({
      Ent(kUser, kR, uid_),
      Ent(kUser, kR, uid_),
      Ent(kMask, kR, kUndef),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to no USER_OBJ or GROUP_OBJ
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(PosixACLTest, SetACLNoMask) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kGroup, kR, gid_),
      Ent(kOther, kR, kUndef),
  });

  // Should fail with EINVAL due to no mask despite presence of named user
  EXPECT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallFailsWithErrno(EINVAL));
}

// Test reading a POSIX ACL from a lower overlayfs mount point through a stacked
// overlay.
TEST_P(PosixACLTest, GetACLThroughStackedOverlay) {
  // TODO(gvisor.dev/issues/14066): fix nested-overlayfs locks
  if (IsRunningOnGvisor()) {
    GTEST_SKIP() << "Skipped due to #14066";
  }

  SKIP_IF(GetParam() != Backend::kOverlayLower);

  // Need CAP_SYS_ADMIN to mount overlayfs.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR | kW, uid_),
      Ent(kGroupObj, 0, kUndef),
      Ent(kMask, 0, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  const auto upper2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(layers_));
  const auto work2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(layers_));
  const auto stacked_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_.path()));
  const std::string opts = "lowerdir=" + dir_.path() +
                           ",upperdir=" + upper2.path() +
                           ",workdir=" + work2.path();
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("overlay", stacked_dir.path(), "overlay", 0, opts, 0));

  const auto stacked_file = JoinPath(stacked_dir.path(), "posix_acl_test_file");
  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(stacked_file, kAccessACL));
  EXPECT_EQ(got, acl);
}

// Test setting a POSIX ACL on a file accessed through a stacked overlay.
TEST_P(PosixACLTest, SetACLThroughStackedOverlay) {
  // TODO(gvisor.dev/issues/14066): fix nested-overlayfs locks
  if (IsRunningOnGvisor()) {
    GTEST_SKIP() << "Skipped due to #14066";
  }

  SKIP_IF(GetParam() != Backend::kOverlayLower);

  // Need CAP_SYS_ADMIN to mount overlayfs.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kGroup, kR | kW, gid_),
      Ent(kMask, kR | kW, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  const auto upper2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(layers_));
  const auto work2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(layers_));
  const auto stacked_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base_.path()));
  const std::string opts = "lowerdir=" + dir_.path() +
                           ",upperdir=" + upper2.path() +
                           ",workdir=" + work2.path();
  const auto mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("overlay", stacked_dir.path(), "overlay", 0, opts, 0));

  // Trigger a copy-up (mode 664 matches u/mask/o from the ACL, so this chmod
  // should not affect the ACL).
  const auto stacked_file = JoinPath(stacked_dir.path(), "posix_acl_test_file");
  ASSERT_THAT(chmod(stacked_file.c_str(), 0664), SyscallSucceeds());

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(stacked_file, kAccessACL));
  EXPECT_EQ(got, acl);
}

INSTANTIATE_TEST_SUITE_P(
    All, PosixACLTest,
    ::testing::Values(Backend::kTmpfs, Backend::kOverlayUpper,
                      Backend::kOverlayLower),
    [](const ::testing::TestParamInfo<Backend>& info) -> std::string {
      switch (info.param) {
        case Backend::kTmpfs:
          return "Tmpfs";
        case Backend::kOverlayUpper:
          return "OverlayUpper";
        case Backend::kOverlayLower:
          return "OverlayLower";
      }
      return "Unknown";
    });

}  // namespace

}  // namespace testing
}  // namespace gvisor
