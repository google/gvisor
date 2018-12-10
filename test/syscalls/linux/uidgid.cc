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
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "test/util/capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

DEFINE_int32(scratch_uid1, 65534, "first scratch UID");
DEFINE_int32(scratch_uid2, 65533, "second scratch UID");
DEFINE_int32(scratch_gid1, 65534, "first scratch GID");
DEFINE_int32(scratch_gid2, 65533, "second scratch GID");

using ::testing::UnorderedElementsAreArray;

namespace gvisor {
namespace testing {

namespace {

TEST(UidGidTest, Getuid) {
  uid_t ruid, euid, suid;
  EXPECT_THAT(getresuid(&ruid, &euid, &suid), SyscallSucceeds());
  EXPECT_THAT(getuid(), SyscallSucceedsWithValue(ruid));
  EXPECT_THAT(geteuid(), SyscallSucceedsWithValue(euid));
}

TEST(UidGidTest, Getgid) {
  gid_t rgid, egid, sgid;
  EXPECT_THAT(getresgid(&rgid, &egid, &sgid), SyscallSucceeds());
  EXPECT_THAT(getgid(), SyscallSucceedsWithValue(rgid));
  EXPECT_THAT(getegid(), SyscallSucceedsWithValue(egid));
}

TEST(UidGidTest, Getgroups) {
  // "If size is zero, list is not modified, but the total number of
  // supplementary group IDs for the process is returned." - getgroups(2)
  int nr_groups;
  ASSERT_THAT(nr_groups = getgroups(0, nullptr), SyscallSucceeds());
  std::vector<gid_t> list(nr_groups);
  EXPECT_THAT(getgroups(list.size(), list.data()), SyscallSucceeds());

  // "EINVAL: size is less than the number of supplementary group IDs, but is
  // not zero."
  EXPECT_THAT(getgroups(-1, nullptr), SyscallFailsWithErrno(EINVAL));

  // Testing for EFAULT requires actually having groups, which isn't guaranteed
  // here; see the setgroups test below.
}

// If the caller's real/effective/saved user/group IDs are all 0, IsRoot returns
// true. Otherwise IsRoot logs an explanatory message and returns false.
PosixErrorOr<bool> IsRoot() {
  uid_t ruid, euid, suid;
  int rc = getresuid(&ruid, &euid, &suid);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "getresuid");
  }
  if (ruid != 0 || euid != 0 || suid != 0) {
    return false;
  }
  gid_t rgid, egid, sgid;
  rc = getresgid(&rgid, &egid, &sgid);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "getresgid");
  }
  if (rgid != 0 || egid != 0 || sgid != 0) {
    return false;
  }
  return true;
}

// Checks that the calling process' real/effective/saved user IDs are
// ruid/euid/suid respectively.
PosixError CheckUIDs(uid_t ruid, uid_t euid, uid_t suid) {
  uid_t actual_ruid, actual_euid, actual_suid;
  int rc = getresuid(&actual_ruid, &actual_euid, &actual_suid);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "getresuid");
  }
  if (ruid != actual_ruid || euid != actual_euid || suid != actual_suid) {
    return PosixError(
        EPERM, absl::StrCat(
                   "incorrect user IDs: got (",
                   absl::StrJoin({actual_ruid, actual_euid, actual_suid}, ", "),
                   ", wanted (", absl::StrJoin({ruid, euid, suid}, ", "), ")"));
  }
  return NoError();
}

PosixError CheckGIDs(gid_t rgid, gid_t egid, gid_t sgid) {
  gid_t actual_rgid, actual_egid, actual_sgid;
  int rc = getresgid(&actual_rgid, &actual_egid, &actual_sgid);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "getresgid");
  }
  if (rgid != actual_rgid || egid != actual_egid || sgid != actual_sgid) {
    return PosixError(
        EPERM, absl::StrCat(
                   "incorrect group IDs: got (",
                   absl::StrJoin({actual_rgid, actual_egid, actual_sgid}, ", "),
                   ", wanted (", absl::StrJoin({rgid, egid, sgid}, ", "), ")"));
  }
  return NoError();
}

// N.B. These tests may break horribly unless run via a gVisor test runner,
// because changing UID in one test may forfeit permissions required by other
// tests. (The test runner runs each test in a separate process.)

TEST(UidGidRootTest, Setuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting this
  // test. Otherwise, the files are created by root (UID before the test), but
  // cannot be opened by the `uid` set below after the test. After calling
  // setuid(non-zero-UID), there is no way to get root privileges back.
  ScopedThread([&] {
    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. POSIX threads, however, require that all
    // threads have the same UIDs, so using the setuid wrapper sets all threads'
    // real UID.
    EXPECT_THAT(syscall(SYS_setuid, -1), SyscallFailsWithErrno(EINVAL));

    const uid_t uid = FLAGS_scratch_uid1;
    EXPECT_THAT(syscall(SYS_setuid, uid), SyscallSucceeds());
    // "If the effective UID of the caller is root (more precisely: if the
    // caller has the CAP_SETUID capability), the real UID and saved set-user-ID
    // are also set." - setuid(2)
    EXPECT_NO_ERRNO(CheckUIDs(uid, uid, uid));
  });
}

TEST(UidGidRootTest, Setgid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  EXPECT_THAT(setgid(-1), SyscallFailsWithErrno(EINVAL));

  const gid_t gid = FLAGS_scratch_gid1;
  ASSERT_THAT(setgid(gid), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(gid, gid, gid));
}

TEST(UidGidRootTest, SetgidNotFromThreadGroupLeader) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  const gid_t gid = FLAGS_scratch_gid1;
  // NOTE: Do setgid in a separate thread so that we can test if
  // info.si_pid is set correctly.
  ScopedThread([gid] { ASSERT_THAT(setgid(gid), SyscallSucceeds()); });
  EXPECT_NO_ERRNO(CheckGIDs(gid, gid, gid));
}

TEST(UidGidRootTest, Setreuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // "Supplying a value of -1 for either the real or effective user ID forces
  // the system to leave that ID unchanged." - setreuid(2)
  EXPECT_THAT(setreuid(-1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckUIDs(0, 0, 0));

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting this
  // test. Otherwise, the files are created by root (UID before the test), but
  // cannot be opened by the `uid` set below after the test. After calling
  // setuid(non-zero-UID), there is no way to get root privileges back.
  ScopedThread([&] {
    const uid_t ruid = FLAGS_scratch_uid1;
    const uid_t euid = FLAGS_scratch_uid2;

    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. posix threads, however, require that all
    // threads have the same UIDs, so using the setuid wrapper sets all threads'
    // real UID.
    EXPECT_THAT(syscall(SYS_setreuid, ruid, euid), SyscallSucceeds());

    // "If the real user ID is set or the effective user ID is set to a value
    // not equal to the previous real user ID, the saved set-user-ID will be set
    // to the new effective user ID." - setreuid(2)
    EXPECT_NO_ERRNO(CheckUIDs(ruid, euid, euid));
  });
}

TEST(UidGidRootTest, Setregid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  EXPECT_THAT(setregid(-1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(0, 0, 0));

  const gid_t rgid = FLAGS_scratch_gid1;
  const gid_t egid = FLAGS_scratch_gid2;
  ASSERT_THAT(setregid(rgid, egid), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(rgid, egid, egid));
}

TEST(UidGidRootTest, Setresuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // "If one of the arguments equals -1, the corresponding value is not
  // changed." - setresuid(2)
  EXPECT_THAT(setresuid(-1, -1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckUIDs(0, 0, 0));

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting this
  // test. Otherwise, the files are created by root (UID before the test), but
  // cannot be opened by the `uid` set below after the test. After calling
  // setuid(non-zero-UID), there is no way to get root privileges back.
  ScopedThread([&] {
    const uid_t ruid = 12345;
    const uid_t euid = 23456;
    const uid_t suid = 34567;

    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. posix threads, however, require that all
    // threads have the same UIDs, so using the setuid wrapper sets all threads'
    // real UID.
    EXPECT_THAT(syscall(SYS_setresuid, ruid, euid, suid), SyscallSucceeds());
    EXPECT_NO_ERRNO(CheckUIDs(ruid, euid, suid));
  });
}

TEST(UidGidRootTest, Setresgid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  EXPECT_THAT(setresgid(-1, -1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(0, 0, 0));

  const gid_t rgid = 12345;
  const gid_t egid = 23456;
  const gid_t sgid = 34567;
  ASSERT_THAT(setresgid(rgid, egid, sgid), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(rgid, egid, sgid));
}

TEST(UidGidRootTest, Setgroups) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  std::vector<gid_t> list = {123, 500};
  ASSERT_THAT(setgroups(list.size(), list.data()), SyscallSucceeds());
  std::vector<gid_t> list2(list.size());
  ASSERT_THAT(getgroups(list2.size(), list2.data()), SyscallSucceeds());
  EXPECT_THAT(list, UnorderedElementsAreArray(list2));

  // "EFAULT: list has an invalid address."
  EXPECT_THAT(getgroups(100, reinterpret_cast<gid_t*>(-1)),
              SyscallFailsWithErrno(EFAULT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
