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
#include <linux/capability.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
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

class PosixACLTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Use /dev/shm to allow the native tests to run without privilege
    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/dev/shm"));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(dir_.path())));

    file_ = JoinPath(dir_.path(), "posix_acl_test_file");
    ASSERT_NO_ERRNO_AND_VALUE(Open(file_, O_CREAT | O_RDWR, 0644));
    ASSERT_THAT(chmod(file_.c_str(), 0644), SyscallSucceeds());

    subdir_ = JoinPath(dir_.path(), "subdir");
    ASSERT_THAT(mkdir(subdir_.c_str(), 0755), SyscallSucceeds());

    uid_ = getuid();
    gid_ = getgid();
  }

  TempPath dir_;
  std::string file_;
  std::string subdir_;
  uid_t uid_;
  gid_t gid_;
};

// Setting an access ACL and reading it back returns an identical blob.
TEST_F(PosixACLTest, SetGetAccessACL) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR, uid_),
      Ent(kGroupObj, kR, kUndef),
      Ent(kMask, kR | kW, kUndef),
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(file_, kAccessACL));
  EXPECT_EQ(got, acl);
}

// Setting an access ACL with a named-group entry round-trips, and the stored
// entry is keyed by group ID.
TEST_F(PosixACLTest, SetGetNamedGroupACL) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
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
  EXPECT_EQ(FindEntryPerm(got, kGroup, gid_), kR | kW);
}

// getxattr reports the size when passed a zero-length buffer.
TEST_F(PosixACLTest, GetAccessACLSize) {
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
TEST_F(PosixACLTest, GetAccessACLNoData) {
  EXPECT_THAT(getxattr(file_.c_str(), kAccessACL, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

// Setting an extended access ACL updates the file mode: the owner/other bits
// come from USER_OBJ/OTHER, and the group bits reflect the mask.
TEST_F(PosixACLTest, AccessACLUpdatesMode) {
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
TEST_F(PosixACLTest, MinimalAccessACLFoldsToMode) {
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
TEST_F(PosixACLTest, ListAndRemoveAccessACL) {
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
TEST_F(PosixACLTest, DefaultACLOnFileFails) {
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
TEST_F(PosixACLTest, SetGetDefaultACLOnDir) {
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
TEST_F(PosixACLTest, DefaultACLInheritance) {
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

// chmod on a file with an extended ACL updates the mask (the group bits), not
// the GROUP_OBJ entry.
TEST_F(PosixACLTest, ChmodUpdatesMask) {
  const std::string acl = BuildACL({
      Ent(kUserObj, kR | kW, kUndef),
      Ent(kUser, kR | kW, uid_),
      Ent(kGroupObj, kR, kUndef),  // group_obj r--
      Ent(kMask, kR, kUndef),      // mask r--
      Ent(kOther, kR, kUndef),
  });
  ASSERT_THAT(setxattr(file_.c_str(), kAccessACL, acl.data(), acl.size(), 0),
              SyscallSucceeds());

  // Give the group class read+write. This must move the mask to rw-, leaving
  // GROUP_OBJ untouched.
  ASSERT_THAT(chmod(file_.c_str(), 0664), SyscallSucceeds());

  const std::string got =
      ASSERT_NO_ERRNO_AND_VALUE(GetXattrString(file_, kAccessACL));
  EXPECT_EQ(FindEntryPerm(got, kMask, kUndef), kR | kW);
  EXPECT_EQ(FindEntryPerm(got, kGroupObj, kUndef), kR);
}

// A named-user ACL entry grants access that the mode bits alone would deny, and
// the mask caps that access.
TEST_F(PosixACLTest, NamedUserEnforcement) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // Without an ACL granting access, "nobody" cannot read a 0600 file.
  ASSERT_THAT(chmod(file_.c_str(), 0600), SyscallSucceeds());
  ScopedThread([&] {
    EXPECT_THAT(syscall(SYS_setuid, kNobody), SyscallSucceeds());
    EXPECT_THAT(open(file_.c_str(), O_RDONLY), SyscallFailsWithErrno(EACCES));
  });

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
TEST_F(PosixACLTest, NamedGroupEnforcement) {
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

// Only the file owner (or a suitably privileged process) may set an ACL, even
// with write permission on the file.
TEST_F(PosixACLTest, SetACLRequiresOwnership) {
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

}  // namespace

}  // namespace testing
}  // namespace gvisor
