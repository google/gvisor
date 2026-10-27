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
#include <grp.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/uid_util.h"

ABSL_FLAG(int32_t, scratch_uid1, 65534, "first scratch UID");
ABSL_FLAG(int32_t, scratch_uid2, 65533, "second scratch UID");
ABSL_FLAG(int32_t, scratch_gid1, 65534, "first scratch GID");
ABSL_FLAG(int32_t, scratch_gid2, 65533, "second scratch GID");

// Force use of syscall instead of glibc set*id() wrappers because we want to
// apply to the current task only. libc sets all threads in a process because
// "POSIX requires that all threads in a process share the same credentials."
#define setuid USE_SYSCALL_INSTEAD
#define setgid USE_SYSCALL_INSTEAD
#define setreuid USE_SYSCALL_INSTEAD
#define setregid USE_SYSCALL_INSTEAD
#define setresuid USE_SYSCALL_INSTEAD
#define setresgid USE_SYSCALL_INSTEAD

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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow="
  EXPECT_THAT(getgroups(-1, nullptr), SyscallFailsWithErrno(EINVAL));
#pragma GCC diagnostic pop

  // Testing for EFAULT requires actually having groups, which isn't guaranteed
  // here; see the setgroups test below.
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

    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    EXPECT_THAT(syscall(SYS_setuid, uid), SyscallSucceeds());
    // "If the effective UID of the caller is root (more precisely: if the
    // caller has the CAP_SETUID capability), the real UID and saved set-user-ID
    // are also set." - setuid(2)
    EXPECT_NO_ERRNO(CheckUIDs(uid, uid, uid));
  });
}

TEST(UidGidRootTest, Setgid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  EXPECT_THAT(syscall(SYS_setgid, -1), SyscallFailsWithErrno(EINVAL));

  ScopedThread([&] {
    const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
    EXPECT_THAT(syscall(SYS_setgid, gid), SyscallSucceeds());
    EXPECT_NO_ERRNO(CheckGIDs(gid, gid, gid));
  });
}

TEST(UidGidRootTest, SetgidNotFromThreadGroupLeader) {
#pragma push_macro("allow_setgid")
#undef setgid

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  int old_gid = getgid();
  auto clean = Cleanup([old_gid] { setgid(old_gid); });

  const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
  // NOTE(b/64676707): Do setgid in a separate thread so that we can test if
  // info.si_pid is set correctly.
  ScopedThread thread =
      ScopedThread([gid] { ASSERT_THAT(setgid(gid), SyscallSucceeds()); });
  thread.Join();
  EXPECT_NO_ERRNO(CheckGIDs(gid, gid, gid));

#pragma pop_macro("allow_setgid")
}

TEST(UidGidRootTest, Setreuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // "Supplying a value of -1 for either the real or effective user ID forces
  // the system to leave that ID unchanged." - setreuid(2)
  EXPECT_THAT(syscall(SYS_setreuid, -1, -1), SyscallSucceeds());

  EXPECT_NO_ERRNO(CheckUIDs(0, 0, 0));

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting
  // this test. Otherwise, the files are created by root (UID before the
  // test), but cannot be opened by the `uid` set below after the test. After
  // calling setuid(non-zero-UID), there is no way to get root privileges
  // back.
  ScopedThread([&] {
    const uid_t ruid = absl::GetFlag(FLAGS_scratch_uid1);
    const uid_t euid = absl::GetFlag(FLAGS_scratch_uid2);

    EXPECT_THAT(syscall(SYS_setreuid, ruid, euid), SyscallSucceeds());

    // "If the real user ID is set or the effective user ID is set to a value
    // not equal to the previous real user ID, the saved set-user-ID will be
    // set to the new effective user ID." - setreuid(2)
    EXPECT_NO_ERRNO(CheckUIDs(ruid, euid, euid));
  });
}

TEST(UidGidRootTest, Setregid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  EXPECT_THAT(syscall(SYS_setregid, -1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(0, 0, 0));

  ScopedThread([&] {
    const gid_t rgid = absl::GetFlag(FLAGS_scratch_gid1);
    const gid_t egid = absl::GetFlag(FLAGS_scratch_gid2);
    ASSERT_THAT(syscall(SYS_setregid, rgid, egid), SyscallSucceeds());
    EXPECT_NO_ERRNO(CheckGIDs(rgid, egid, egid));
  });
}

TEST(UidGidRootTest, Setresuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // "If one of the arguments equals -1, the corresponding value is not
  // changed." - setresuid(2)
  EXPECT_THAT(syscall(SYS_setresuid, -1, -1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckUIDs(0, 0, 0));

  // Do setuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting
  // this test. Otherwise, the files are created by root (UID before the
  // test), but cannot be opened by the `uid` set below after the test. After
  // calling setuid(non-zero-UID), there is no way to get root privileges
  // back.
  ScopedThread([&] {
    const uid_t ruid = 12345;
    const uid_t euid = 23456;
    const uid_t suid = 34567;

    // Use syscall instead of glibc setuid wrapper because we want this setuid
    // call to only apply to this task. posix threads, however, require that
    // all threads have the same UIDs, so using the setuid wrapper sets all
    // threads' real UID.
    EXPECT_THAT(syscall(SYS_setresuid, ruid, euid, suid), SyscallSucceeds());
    EXPECT_NO_ERRNO(CheckUIDs(ruid, euid, suid));
  });
}

TEST(UidGidRootTest, Setresgid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  EXPECT_THAT(syscall(SYS_setresgid, -1, -1, -1), SyscallSucceeds());
  EXPECT_NO_ERRNO(CheckGIDs(0, 0, 0));

  ScopedThread([&] {
    const gid_t rgid = 12345;
    const gid_t egid = 23456;
    const gid_t sgid = 34567;
    ASSERT_THAT(syscall(SYS_setresgid, rgid, egid, sgid), SyscallSucceeds());
    EXPECT_NO_ERRNO(CheckGIDs(rgid, egid, sgid));
  });
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

TEST(UidGidRootTest, Setuid_prlimit) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // Do seteuid in a separate thread so that after finishing this test, the
  // process can still open files the test harness created before starting
  // this test. Otherwise, the files are created by root (UID before the
  // test), but cannot be opened by the `uid` set below after the test.
  ScopedThread([&] {
    // Use syscall instead of glibc setuid wrapper because we want this
    // seteuid call to only apply to this task. POSIX threads, however,
    // require that all threads have the same UIDs, so using the seteuid
    // wrapper sets all threads' UID.
    EXPECT_THAT(syscall(SYS_setreuid, -1, 65534), SyscallSucceeds());

    // Despite the UID change, we should be able to get our own limits.
    struct rlimit rl = {};
    EXPECT_THAT(prlimit(0, RLIMIT_NOFILE, NULL, &rl), SyscallSucceeds());
  });
}

#ifndef SECBIT_NO_SETUID_FIXUP
#define SECBIT_NO_SETUID_FIXUP (1 << 2)
#endif

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif

constexpr uid_t kNoUID = -1;
constexpr gid_t kNoGID = -1;

// setfsuid(2) and setfsgid(2) only apply to the calling task, and always
// return the previous filesystem ID.
uid_t Setfsuid(uid_t uid) { return syscall(SYS_setfsuid, uid); }
gid_t Setfsgid(gid_t gid) { return syscall(SYS_setfsgid, gid); }

// Returns the filesystem ID, the fourth field of the "Uid:" or "Gid:" line of
// /proc/thread-self/status.
PosixErrorOr<uint32_t> StatusFilesystemID(absl::string_view key) {
  ASSIGN_OR_RETURN_ERRNO(std::string status,
                         GetContents("/proc/thread-self/status"));
  for (absl::string_view line : absl::StrSplit(status, '\n')) {
    if (!absl::StartsWith(line, key)) {
      continue;
    }
    std::vector<absl::string_view> ids =
        absl::StrSplit(line.substr(key.size()), '\t', absl::SkipEmpty());
    uint32_t id;
    if (ids.size() != 4 || !absl::SimpleAtoi(ids[3], &id)) {
      return PosixError(EINVAL, absl::StrCat("bad status line: ", line));
    }
    return id;
  }
  return PosixError(ENOENT, absl::StrCat("no ", key, " line in status"));
}

PosixErrorOr<bool> Faccessat2Supported() {
  if (IsRunningOnGvisor()) {
    return true;
  }
  if (syscall(SYS_faccessat2, -1, "/", F_OK, 0) == 0) {
    return true;
  }
  if (errno == ENOSYS) {
    return false;
  }
  return PosixError(errno, "unexpected errno from faccessat2(/)");
}

// setfsuid(-1) and setfsgid(-1) change nothing and return the filesystem IDs,
// which follow the effective IDs by default.
TEST(UidGidTest, SetfsuidQuery) {
  EXPECT_EQ(Setfsuid(kNoUID), geteuid());
  EXPECT_EQ(Setfsgid(kNoGID), getegid());
  EXPECT_THAT(StatusFilesystemID("Uid:"), IsPosixErrorOkAndHolds(geteuid()));
  EXPECT_THAT(StatusFilesystemID("Gid:"), IsPosixErrorOkAndHolds(getegid()));
}

// With CAP_SETUID, any UID can be set, and the real, effective and saved UIDs
// are left alone.
TEST(UidGidRootTest, Setfsuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    EXPECT_EQ(Setfsuid(uid), 0);
    EXPECT_EQ(Setfsuid(kNoUID), uid);
    EXPECT_NO_ERRNO(CheckUIDs(0, 0, 0));
    EXPECT_THAT(StatusFilesystemID("Uid:"), IsPosixErrorOkAndHolds(uid));
    EXPECT_EQ(Setfsuid(0), uid);
    EXPECT_EQ(Setfsuid(kNoUID), 0);
  });
}

// With CAP_SETGID, any GID can be set, and the real, effective and saved GIDs
// are left alone.
TEST(UidGidRootTest, Setfsgid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
    EXPECT_EQ(Setfsgid(gid), 0);
    EXPECT_EQ(Setfsgid(kNoGID), gid);
    EXPECT_NO_ERRNO(CheckGIDs(0, 0, 0));
    EXPECT_THAT(StatusFilesystemID("Gid:"), IsPosixErrorOkAndHolds(gid));
    EXPECT_EQ(Setfsgid(0), gid);
    EXPECT_EQ(Setfsgid(kNoGID), 0);
  });
}

// Without CAP_SETUID, only the real, effective or saved UID can be set; other
// UIDs are ignored and the previous filesystem UID is still returned.
TEST(UidGidRootTest, SetfsuidUnprivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    const uid_t ruid = 12345;
    const uid_t euid = 23456;
    const uid_t suid = 34567;
    ASSERT_THAT(syscall(SYS_setresuid, ruid, euid, suid), SyscallSucceeds());
    ASSERT_THAT(HaveCapability(CAP_SETUID), IsPosixErrorOkAndHolds(false));

    EXPECT_EQ(Setfsuid(45678), euid);
    EXPECT_EQ(Setfsuid(kNoUID), euid);
    EXPECT_EQ(Setfsuid(ruid), euid);
    EXPECT_EQ(Setfsuid(suid), ruid);
    EXPECT_EQ(Setfsuid(euid), suid);
    EXPECT_EQ(Setfsuid(kNoUID), euid);
  });
}

// Without CAP_SETGID, only the real, effective or saved GID can be set; other
// GIDs are ignored and the previous filesystem GID is still returned.
TEST(UidGidRootTest, SetfsgidUnprivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    const gid_t rgid = 12345;
    const gid_t egid = 23456;
    const gid_t sgid = 34567;
    ASSERT_THAT(syscall(SYS_setresgid, rgid, egid, sgid), SyscallSucceeds());
    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    ASSERT_THAT(syscall(SYS_setresuid, uid, uid, uid), SyscallSucceeds());
    ASSERT_THAT(HaveCapability(CAP_SETGID), IsPosixErrorOkAndHolds(false));

    EXPECT_EQ(Setfsgid(45678), egid);
    EXPECT_EQ(Setfsgid(kNoGID), egid);
    EXPECT_EQ(Setfsgid(rgid), egid);
    EXPECT_EQ(Setfsgid(sgid), rgid);
    EXPECT_EQ(Setfsgid(kNoGID), sgid);
  });
}

// Moving the filesystem UID away from root clears the filesystem capabilities
// from the effective set; moving it back restores them from the permitted set.
// setfsgid(2) leaves capabilities alone.
TEST(UidGidRootTest, SetfsuidFilesystemCapabilities) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_DAC_OVERRIDE)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FOWNER)));

  ScopedThread([&] {
    const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
    ASSERT_EQ(Setfsgid(gid), 0);
    EXPECT_THAT(HaveCapability(CAP_DAC_OVERRIDE), IsPosixErrorOkAndHolds(true));

    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    ASSERT_EQ(Setfsuid(uid), 0);
    MaybeSave();
    EXPECT_EQ(Setfsuid(kNoUID), uid);
    EXPECT_EQ(Setfsgid(kNoGID), gid);
    EXPECT_THAT(StatusFilesystemID("Uid:"), IsPosixErrorOkAndHolds(uid));
    EXPECT_THAT(HaveCapability(CAP_DAC_OVERRIDE),
                IsPosixErrorOkAndHolds(false));
    EXPECT_THAT(HaveCapability(CAP_FOWNER), IsPosixErrorOkAndHolds(false));
    EXPECT_THAT(HaveCapability(CAP_SETUID), IsPosixErrorOkAndHolds(true));

    ASSERT_EQ(Setfsuid(0), uid);
    EXPECT_THAT(HaveCapability(CAP_DAC_OVERRIDE), IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(HaveCapability(CAP_FOWNER), IsPosixErrorOkAndHolds(true));
  });
}

// SECBIT_NO_SETUID_FIXUP keeps the effective set across setfsuid(2).
TEST(UidGidRootTest, SetfsuidNoSetuidFixup) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETPCAP)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_DAC_OVERRIDE)));

  ScopedThread([&] {
    ASSERT_THAT(prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP, 0, 0, 0),
                SyscallSucceeds());
    ASSERT_EQ(Setfsuid(absl::GetFlag(FLAGS_scratch_uid1)), 0);
    EXPECT_THAT(HaveCapability(CAP_DAC_OVERRIDE), IsPosixErrorOkAndHolds(true));
  });
}

// setuid(2), setreuid(2) and setresuid(2) reset the filesystem UID to the
// effective UID, even when the effective UID does not change.
TEST(UidGidRootTest, SetuidResetsFsuid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    ASSERT_EQ(Setfsuid(uid), 0);
    ASSERT_THAT(syscall(SYS_setreuid, -1, -1), SyscallSucceeds());
    EXPECT_EQ(Setfsuid(kNoUID), 0);

    ASSERT_EQ(Setfsuid(uid), 0);
    ASSERT_THAT(syscall(SYS_setuid, 0), SyscallSucceeds());
    EXPECT_EQ(Setfsuid(kNoUID), 0);

    ASSERT_EQ(Setfsuid(uid), 0);
    ASSERT_THAT(syscall(SYS_setresuid, 0, 0, 0), SyscallSucceeds());
    EXPECT_EQ(Setfsuid(kNoUID), 0);
  });
}

// setgid(2), setregid(2) and setresgid(2) reset the filesystem GID to the
// effective GID, even when the effective GID does not change.
TEST(UidGidRootTest, SetgidResetsFsgid) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
    ASSERT_EQ(Setfsgid(gid), 0);
    ASSERT_THAT(syscall(SYS_setregid, -1, -1), SyscallSucceeds());
    EXPECT_EQ(Setfsgid(kNoGID), 0);

    ASSERT_EQ(Setfsgid(gid), 0);
    ASSERT_THAT(syscall(SYS_setgid, 0), SyscallSucceeds());
    EXPECT_EQ(Setfsgid(kNoGID), 0);

    ASSERT_EQ(Setfsgid(gid), 0);
    ASSERT_THAT(syscall(SYS_setresgid, 0, 0, 0), SyscallSucceeds());
    EXPECT_EQ(Setfsgid(kNoGID), 0);
  });
}

// Since Linux 6.3, setresuid(-1, -1, -1) and setresgid(-1, -1, -1) are no-ops
// that keep the filesystem IDs.
TEST(UidGidRootTest, SetresuidNoopKeepsFilesystemIDs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));
  if (!IsRunningOnGvisor()) {
    auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major < 6 || (version.major == 6 && version.minor < 3));
  }

  ScopedThread([&] {
    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    ASSERT_EQ(Setfsuid(uid), 0);
    ASSERT_THAT(syscall(SYS_setresuid, -1, -1, -1), SyscallSucceeds());
    EXPECT_EQ(Setfsuid(kNoUID), uid);

    const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
    ASSERT_EQ(Setfsgid(gid), 0);
    ASSERT_THAT(syscall(SYS_setresgid, -1, -1, -1), SyscallSucceeds());
    EXPECT_EQ(Setfsgid(kNoGID), gid);
  });
}

// File permission checks and access(2) with AT_EACCESS use the filesystem UID,
// while plain access(2) uses the real UID.
TEST(UidGidRootTest, SetfsuidFilePermissions) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(Faccessat2Supported()));

  const uid_t owner = absl::GetFlag(FLAGS_scratch_uid1);
  const uid_t other = absl::GetFlag(FLAGS_scratch_uid2);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(dir.path(), "", 0400));
  ASSERT_THAT(chown(file.path().c_str(), owner, -1), SyscallSucceeds());
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_PATH | O_DIRECTORY));
  const std::string name(Basename(file.path()));

  ScopedThread([&] {
    ASSERT_EQ(Setfsuid(other), 0);
    EXPECT_THAT(openat(dirfd.get(), name.c_str(), O_RDONLY),
                SyscallFailsWithErrno(EACCES));
    EXPECT_THAT(
        syscall(SYS_faccessat2, dirfd.get(), name.c_str(), R_OK, AT_EACCESS),
        SyscallFailsWithErrno(EACCES));
    EXPECT_THAT(syscall(SYS_faccessat, dirfd.get(), name.c_str(), R_OK),
                SyscallSucceeds());

    ASSERT_EQ(Setfsuid(owner), other);
    EXPECT_NO_ERRNO(OpenAt(dirfd.get(), name, O_RDONLY));
    EXPECT_THAT(
        syscall(SYS_faccessat2, dirfd.get(), name.c_str(), R_OK, AT_EACCESS),
        SyscallSucceeds());
  });
}

// New files and pipes are owned by the filesystem UID and GID.
TEST(UidGidRootTest, SetfsuidNewFileOwner) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_THAT(chmod(dir.path().c_str(), 0777), SyscallSucceeds());
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_PATH | O_DIRECTORY));

  ScopedThread([&] {
    const uid_t uid = absl::GetFlag(FLAGS_scratch_uid1);
    const gid_t gid = absl::GetFlag(FLAGS_scratch_gid1);
    ASSERT_EQ(Setfsgid(gid), 0);
    ASSERT_EQ(Setfsuid(uid), 0);
    MaybeSave();

    const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
        OpenAt(dirfd.get(), "file", O_CREAT | O_EXCL | O_RDWR, 0600));
    struct stat st;
    ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
    EXPECT_EQ(st.st_uid, uid);
    EXPECT_EQ(st.st_gid, gid);

    int pipefds[2];
    ASSERT_THAT(pipe(pipefds), SyscallSucceeds());
    const FileDescriptor rfd(pipefds[0]);
    const FileDescriptor wfd(pipefds[1]);
    ASSERT_THAT(fstat(rfd.get(), &st), SyscallSucceeds());
    EXPECT_EQ(st.st_uid, uid);
    EXPECT_EQ(st.st_gid, gid);

    ASSERT_THAT(unlinkat(dirfd.get(), "file", 0), SyscallSucceeds());
  });
}

// /proc/[pid] entries are owned by the task's effective IDs (root here, which
// is also the owner of a non-dumpable task's entries), not its filesystem IDs.
TEST(UidGidRootTest, SetfsuidProcEntriesOwner) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  // A new process, so that its /proc/[pid] entries are created after the
  // filesystem IDs change.
  const auto rest = [] {
    TEST_CHECK(Setfsgid(absl::GetFlag(FLAGS_scratch_gid1)) == 0);
    TEST_CHECK(Setfsuid(absl::GetFlag(FLAGS_scratch_uid1)) == 0);
    for (const char* path :
         {"/proc/self/fd", "/proc/self/fdinfo", "/proc/self/exe",
          "/proc/self/cwd", "/proc/self/root", "/proc/self/comm"}) {
      struct stat st;
      TEST_PCHECK(lstat(path, &st) == 0);
      TEST_CHECK(st.st_uid == 0);
      TEST_CHECK(st.st_gid == 0);
    }
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

// Changing the filesystem UID or GID resets the parent death signal, and does
// so only when the ID actually changes.
TEST(UidGidRootTest, SetfsuidResetsParentDeathSignal) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsRoot()));

  ScopedThread([&] {
    int sig;
    ASSERT_THAT(prctl(PR_SET_PDEATHSIG, SIGUSR1), SyscallSucceeds());
    ASSERT_EQ(Setfsuid(0), 0);
    ASSERT_THAT(prctl(PR_GET_PDEATHSIG, &sig), SyscallSucceeds());
    EXPECT_EQ(sig, SIGUSR1);

    ASSERT_EQ(Setfsuid(absl::GetFlag(FLAGS_scratch_uid1)), 0);
    ASSERT_THAT(prctl(PR_GET_PDEATHSIG, &sig), SyscallSucceeds());
    EXPECT_EQ(sig, 0);

    ASSERT_THAT(prctl(PR_SET_PDEATHSIG, SIGUSR1), SyscallSucceeds());
    ASSERT_EQ(Setfsgid(absl::GetFlag(FLAGS_scratch_gid1)), 0);
    ASSERT_THAT(prctl(PR_GET_PDEATHSIG, &sig), SyscallSucceeds());
    EXPECT_EQ(sig, 0);
  });
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
