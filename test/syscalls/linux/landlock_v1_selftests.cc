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

// Landlock ABI v1 conformance tests ported from the Linux kernel's own
// Landlock selftests, tools/testing/selftests/landlock, as of Linux v7.0.
//
// Every test below names the upstream selftest it corresponds to, as
// "<selftest file> <fixture>.<test>" (plus the FIXTURE_VARIANT where the
// upstream test is variant-driven). One upstream test often becomes several
// gtest cases here: the kselftest harness bundles many independent checks into
// one TEST_F_FORK body, while the gVisor suite keeps one behaviour per case so
// a failure names what broke.
//
// Tests that gVisor wrote itself -- error-ordering checks derived from reading
// the Linux VFS, and coverage of gVisor-specific paths such as host-donated
// file descriptors, mqueue, fsconfig and symlink races -- live in
// landlock_v1.cc instead.
//
// The v1-relevant upstream selftests that are NOT ported, and why, are listed
// in a comment at the end of this file.

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

// Creates an empty regular file at path.
void CreateFile(const std::string& path) {
  int fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
}

// --------------------------------------------------------------------------
// Tests ported from tools/testing/selftests/landlock/base_test.c.
// --------------------------------------------------------------------------

// Linux selftest: base_test.c abi_version
//
// The kernel test pins the reported version to the exact value that kernel
// implements; gVisor only requires v1 or later.
TEST(LandlockV1Test, AbiVersionIsSupported) {
  int version = LandlockAbiVersion();
  SKIP_IF(version < 0 && errno == ENOSYS);
  ASSERT_GE(version, 1) << "unexpected Landlock ABI version";
}

// Linux selftest: base_test.c inconsistent_attr
//
// Size handling of the attr follows copy_min_struct_from_user(): a struct
// shorter than 8 bytes cannot even hold handled_access_fs, one of exactly 8
// bytes is accepted with the missing fields read as zero, one longer than a
// page is refused outright, and unknown trailing bytes are only tolerated if
// zero.
TEST(LandlockV1Test, CreateRulesetSizeHandling) {
  SKIP_IF(LandlockAbiVersion() < 1);
  uint64_t fs_only = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(
                  reinterpret_cast<landlock_ruleset_attr*>(&fs_only), 7, 0),
              SyscallFailsWithErrno(EINVAL));
  int fd = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(&fs_only), sizeof(fs_only), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
  const int64_t page_size = sysconf(_SC_PAGESIZE);
  std::vector<char> big(page_size + 8, 0);
  memcpy(big.data(), &fs_only, sizeof(fs_only));
  EXPECT_THAT(
      landlock_create_ruleset(
          reinterpret_cast<landlock_ruleset_attr*>(big.data()), big.size(), 0),
      SyscallFailsWithErrno(E2BIG));
  // A struct longer than the implementation knows, with a nonzero byte in the
  // tail. Kernels that know more of the tail as real fields report the
  // garbage as EINVAL instead; ENOMSG or success would be wrong everywhere.
  std::vector<char> tail(sizeof(landlock_ruleset_attr) + 8, 0);
  memcpy(tail.data(), &fs_only, sizeof(fs_only));
  tail[tail.size() - 1] = 1;
  int rc = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(tail.data()), tail.size(), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
  // To ABI 1 the struct ends at handled_access_fs; a nonzero byte anywhere
  // past offset 8 is tail garbage, E2BIG, even at offsets a later ABI turned
  // into handled_access_net or scoped. Such kernels report EINVAL for their
  // known fields' unknown bits instead.
  landlock_ruleset_attr full = {};
  full.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  full.scoped = (1ULL << 63);
  rc = landlock_create_ruleset(&full, sizeof(full), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

// Linux selftest: base_test.c inconsistent_attr
TEST(LandlockV1Test, CreateRulesetNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(landlock_create_ruleset(nullptr, 7, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(
      landlock_create_ruleset(nullptr, sizeof(landlock_ruleset_attr), 0),
      SyscallFailsWithErrno(EFAULT));
}

// Linux selftests:
//   base_test.c inconsistent_attr
//   fs_test.c layout1.empty_or_same_ruleset
TEST(LandlockV1Test, CreateRulesetEmptyHandledAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(ENOMSG));
}

// Linux selftest: base_test.c errata
//
// LANDLOCK_CREATE_RULESET_ERRATA reports a bitmask of the errata an
// implementation has fixed. Any non-negative value is a valid answer; zero
// means "none reported". Implementations that predate the flag reject it.
TEST(LandlockV1Test, CreateRulesetErrataReturnsBitmask) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int rc = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (rc < 0) {
    EXPECT_EQ(errno, EINVAL) << "unexpected errno " << errno;
  } else {
    EXPECT_GE(rc, 0);
  }
}

// Linux selftest: base_test.c errata
//
// The errata query takes no ruleset, so passing one is an error.
TEST(LandlockV1Test, CreateRulesetErrataRejectsAttr) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_REG;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(landlock_create_ruleset(nullptr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

// Linux selftest: base_test.c errata
//
// The query flags are mutually exclusive.
TEST(LandlockV1Test, CreateRulesetVersionAndErrataRejected) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0,
                                      LANDLOCK_CREATE_RULESET_VERSION |
                                          LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

// Linux selftest: base_test.c create_ruleset_checks_ordering
TEST(LandlockV1Test, CreateRulesetRejectsUnknownFlags) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), /*flags=*/0xffff),
              SyscallFailsWithErrno(EINVAL));
}

// Linux selftest: base_test.c add_rule_checks_ordering
TEST(LandlockV1Test, AddRuleRejectsUnknownRuleType) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(fd, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EINVAL));
  close(fd);
}

// Linux selftests:
//   base_test.c add_rule_checks_ordering
//   fs_test.c layout1.inval
//
// The ruleset fd is resolved before the rule type is looked at, as
// sys_landlock_add_rule() resolves the fd before the switch on rule_type, so a
// call that gets both wrong is told about the fd.
TEST(LandlockV1Test, AddRuleBadFdWithBadRuleTypeReportsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(-1, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADF));

  // A valid fd that is not a ruleset is still reported before the rule type.
  int file_fd = open("/", O_RDONLY | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(file_fd, static_cast<landlock_rule_type>(0xffff),
                        &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(file_fd);
}

// Linux selftest: base_test.c add_rule_checks_ordering
//
// Once the fd, rule type, and flags have passed, the rule attribute is copied
// in: a null pointer is the copy's EFAULT, not EINVAL.
TEST(LandlockV1Test, AddRuleNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, nullptr, 0),
      SyscallFailsWithErrno(EFAULT));
  close(ruleset_fd);
}

// Linux selftest: base_test.c add_rule_checks_ordering
//
// Nonzero flags are EINVAL. Bit 0 is LANDLOCK_ADD_RULE_QUIET on later ABIs
// and succeeds there, so the probe uses bit 1, unknown everywhere.
TEST(LandlockV1Test, AddRuleUnknownFlagsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 2),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

// Linux selftests:
//   base_test.c restrict_self_checks_ordering
//   fs_test.c layout0.unpriv
TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsFails) {
  SKIP_IF(LandlockAbiVersion() < 1);
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 0) < 0 && errno == EPERM ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

// Linux selftest: base_test.c restrict_self_checks_ordering
//
// The no_new_privs check comes before any check on what the caller passed, so a
// thread that may not sandbox itself is told that and not that its arguments
// are bad. See Linux commit eba39ca4b155 ("landlock: Change
// landlock_restrict_self(2) check ordering").
TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsReportsEpermNotEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Both the flags and the descriptor are invalid, and neither is what the
    // call fails on.
    _exit(landlock_restrict_self(-1, ~0u) < 0 && errno == EPERM ? kDenied
                                                                : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: base_test.c restrict_self_checks_ordering
//
// Once no_new_privs is satisfied, unknown flags are EINVAL. Later ABIs accept
// their LOG_* and TSYNC bits in the low positions, so the probe uses bit 31,
// unknown everywhere. This is the "reject later-ABI flags" behavior the v1
// claim depends on, distinct from the EPERM-ordering test above.
TEST(LandlockV1Test, RestrictSelfUnknownFlagsWithNoNewPrivsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 1u << 31) < 0 && errno == EINVAL ? kDenied
                                                                      : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: base_test.c restrict_self_checks_ordering
//
// Covers the closed-fd EBADF leg only; see restrict_self_fd in the gap list
// at the end of this file for the EBADFD leg.
TEST(LandlockV1Test, RestrictSelfRejectsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(-1, 0) < 0 && errno == EBADF ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

// Linux selftest: fs_test.c layout0.unpriv
//
// CAP_SYS_ADMIN in the caller's user namespace substitutes for no_new_privs.
TEST(LandlockV1Test, RestrictSelfWithCapSysAdminWithoutNoNewPrivs) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    // Deliberately no prctl(PR_SET_NO_NEW_PRIVS).
    if (landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    // The domain is enforced, proving the call did more than return 0.
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: base_test.c ruleset_fd_io
//
// The ruleset fd supports none of the ordinary file operations.
TEST(LandlockV1Test, RulesetFdRejectsIO) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  char c;
  EXPECT_THAT(read(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(write(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(lseek(fd, 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  close(fd);
}

// --------------------------------------------------------------------------
// Tests ported from tools/testing/selftests/landlock/fs_test.c.
// --------------------------------------------------------------------------

// Linux selftest: fs_test.c layout0.ruleset_with_unknown_access
TEST(LandlockV1Test, CreateRulesetHandlingAllV1RightsSucceeds) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
}

// Linux selftest: fs_test.c layout0.ruleset_with_unknown_access
TEST(LandlockV1Test, CreateRulesetRejectsUnknownAccessBits) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = (1ULL << 63);
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(EINVAL));
}

// Linux selftest: fs_test.c layout1.inval
//
// An empty allowed_access is reported before the parent fd is even looked at,
// as add_rule_path_beneath() orders them.
TEST(LandlockV1Test, AddRuleEmptyAllowedAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.parent_fd = -1;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(ENOMSG));
  close(fd);
}

// Linux selftests:
//   fs_test.c layout0.rule_with_unknown_access
//   fs_test.c layout1.rule_with_unhandled_access
TEST(LandlockV1Test, AddPathBeneathRejectsUnhandledAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

// Linux selftest: fs_test.c layout1.file_and_dir_access_rights
//
// A rule on a non-directory may only carry rights a file can satisfy;
// granting a directory-only right like READ_DIR on a regular file is EINVAL,
// per landlock_append_fs_rule()'s ACCESS_FILE masking.
TEST(LandlockV1Test, AddRuleDirOnlyRightsOnNonDirectoryReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  // A file-compatible right on the same file is accepted.
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallSucceeds());
  close(parent_fd);
  close(fd);
}

// Linux selftest: fs_test.c layout1.file_and_dir_access_rights
//
// A rule added on a regular file may hold only the rights that can apply to a
// file — EXECUTE, WRITE_FILE and READ_FILE; every directory-only right is
// refused with EINVAL, bit by bit, as the fs selftests check.
TEST(LandlockV1Test, FileRuleAcceptsOnlyFileCompatibleRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int file_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  constexpr uint64_t kFileCompatible = LANDLOCK_ACCESS_FS_EXECUTE |
                                       LANDLOCK_ACCESS_FS_WRITE_FILE |
                                       LANDLOCK_ACCESS_FS_READ_FILE;
  for (int bit = 0; bit < 13; bit++) {
    const uint64_t access = 1ULL << bit;
    landlock_path_beneath_attr path_beneath = {};
    path_beneath.allowed_access = access;
    path_beneath.parent_fd = file_fd;
    if (access & kFileCompatible) {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallSucceeds())
          << "access bit " << bit;
    } else {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallFailsWithErrno(EINVAL))
          << "access bit " << bit;
    }
  }
  close(ruleset_fd);
  close(file_fd);
}

// Linux selftest: fs_test.c layout0.proc_nsfs
//
// A rule can only name a file that lives on a mount the application can reach
// through the mount tree. Files on the kernel's own mounts — the tmpfs behind
// memfd_create(2), nsfs, pipefs, sockfs — are rejected, since a rule naming one
// could never match anything.
//
// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd()
TEST(LandlockV1Test, AddPathBeneathRejectsInternalMountFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  auto close_ruleset = Cleanup([fd] { close(fd); });

  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

  int memfd = syscall(SYS_memfd_create, "landlock_v1_test", 0);
  ASSERT_THAT(memfd, SyscallSucceeds());
  path_beneath.parent_fd = memfd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(memfd);

  int ns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (ns_fd >= 0) {
    path_beneath.parent_fd = ns_fd;
    EXPECT_THAT(
        landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
        SyscallFailsWithErrno(EBADFD));
    close(ns_fd);
  }

  int sv[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), SyscallSucceeds());
  path_beneath.parent_fd = sv[0];
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(sv[0]);
  close(sv[1]);
}

// Linux selftest: fs_test.c layout0.proc_nsfs
TEST(LandlockV1Test, NamespaceFileIsOpenableUnderDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/ns/net"));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout0.max_layers
//
// A domain takes at most LANDLOCK_MAX_NUM_LAYERS (16) stacked rulesets; the
// seventeenth is refused with E2BIG and leaves the sixteen intact.
TEST(LandlockV1Test, MaxSixteenStackedLayers) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    for (int i = 0; i < 16; i++) {
      int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
      if (landlock_restrict_self(fd, 0) != 0) {
        _exit(kSetup);
      }
      close(fd);
    }
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
    int rc = landlock_restrict_self(fd, 0);
    close(fd);
    _exit(rc < 0 && errno == E2BIG ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.effective_access
TEST(LandlockV1Test, ReadInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.effective_access
TEST(LandlockV1Test, ReadOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.effective_access
TEST(LandlockV1Test, WriteFileInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_WRITE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.effective_access
TEST(LandlockV1Test, WriteFileOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_WRITE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.effective_access
TEST(LandlockV1Test, ReadDirOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_DIR, allowed,
                  LANDLOCK_ACCESS_FS_READ_DIR);
    int fd = open(target.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.effective_access
//
// O_PATH opens no file content, so hook_file_open() requests nothing and even
// a deny-everything domain permits it.
TEST(LandlockV1Test, OPathOpenNeedsNoRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    int fd = open(target.c_str(), O_PATH | O_CLOEXEC);
    _exit(fd >= 0 ? kAllowed : (errno == EACCES ? kDenied : kOther));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.unhandled_access
//
// The rights an open needs come from its access mode alone, and only the
// handled ones can deny.
TEST(LandlockV1Test, UnhandledOpenModesRemainAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string allowed;
  allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    // WRITE_FILE is not handled, so a write-only open is unrestricted.
    int wo = open(target.c_str(), O_WRONLY);
    if (wo < 0) {
      _exit(ClassifyFs(wo));
    }
    close(wo);
    // A read-write open still requires the handled READ_FILE right.
    _exit(ClassifyFs(open(target.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.ruleset_overlap
//
// Rules for the same file in different layers intersect: every layer must
// grant a right on its own, so a second layer granting only WRITE on a file
// the first layer granted only READ leaves both denied.
TEST(LandlockV1Test, SameFileRulesInTwoLayersIntersect) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    constexpr uint64_t kHandled =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    ApplyFsPolicy(kHandled, target, LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(target) != kAllowed) {
      _exit(kSetup);
    }
    ApplyFsPolicy(kHandled, target, LANDLOCK_ACCESS_FS_WRITE_FILE);
    // READ is now denied by the second layer, WRITE by the first.
    if (TryReadOpen(target) != kDenied) {
      _exit(kOther);
    }
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
      _exit(kOther);
    }
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.layer_rule_unions
//
// landlock_unmask_layers() collects rights from every rule met on the walk
// toward the root: within one layer rules union, unlike between layers.
TEST(LandlockV1Test, RulesInOneLayerUnionAcrossAncestry) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent_dir.path()));
  TempPath child_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(child_dir.path()));
  TempPath parent_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(parent_dir.path()));
  static std::string parent;
  parent = parent_dir.path();
  static std::string child;
  child = child_dir.path();
  static std::string in_child;
  in_child = child_file.path();
  static std::string in_parent;
  in_parent = parent_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, parent, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, child, LANDLOCK_ACCESS_FS_WRITE_FILE);
    EnforceOrDie(fd);
    // Within one layer, rules encountered along the ancestry walk are
    // unioned: READ_FILE from the parent rule plus WRITE_FILE from the
    // child rule satisfy a read-write open below the child.
    int rw = open(in_child.c_str(), O_RDWR);
    if (rw < 0) {
      _exit(ClassifyFs(rw));
    }
    close(rw);
    // Directly below the parent, only READ_FILE has been granted.
    int denied = open(in_parent.c_str(), O_RDWR);
    if (denied >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    _exit(TryReadOpen(in_parent));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.inherit_subset
//   fs_test.c layout1.inherit_superset
//
// Covers the two-layer intersection the kernel tests spell out over a deeper
// hierarchy and a larger access mask.
TEST(LandlockV1Test, LayeredRulesetsOnlyIntersect) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    EnforceOrDie(fd);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.empty_or_same_ruleset
//
// landlock_restrict_self(2) does not consume the ruleset fd.
TEST(LandlockV1Test, SameRulesetEnforcedTwiceStillDenies) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string allowed;
  allowed = allowed_dir.path();
  static std::string in_allowed;
  in_allowed = inside.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    // The same ruleset fd may be enforced repeatedly, stacking identical
    // layers.
    if (landlock_restrict_self(fd, 0) != 0 ||
        landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    if (TryReadOpen(in_allowed) != kAllowed) {
      _exit(kOther);
    }
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rule_on_mountpoint
TEST(LandlockV1Test, RuleReachesFileThroughBindMount) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath mount_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string dir = covered_dir.path();
  const std::string mount_point = mount_dir.path();
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));
  const std::string via_mount = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    // The mount has to be in place before the domain is enforced, since a
    // domain forbids changing the mount tree at all.
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(dir.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, dir,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(via_mount));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rule_over_mountpoint
//
// A rule on a directory covers bind mounts attached beneath it: the ancestry
// walk climbs from the mounted tree up through the mount point.
TEST(LandlockV1Test, RuleAboveBindMountPointReachesMountContents) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string src = JoinPath(root.path(), "src");
  const std::string covering = JoinPath(root.path(), "covering");
  const std::string mount_point = JoinPath(covering, "mp");
  ASSERT_THAT(mkdir(src.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(covering.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_point.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(src, "f")));
  const std::string via_mount = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(src.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    // The rule is on an ancestor of the mount point, not on the bind
    // source: the ancestry walk must cross the mount boundary upwards.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, covering,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(via_mount));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1_bind.path_disconnected
//
// A directory moved out of the subtree its bind mount exposes is disconnected:
// the mount's root is no longer among its ancestors, so a walk from a file
// under it reaches the root of the filesystem without passing the mount root.
// The rights that reaching the file through that mount carries are still the
// ones the mount root has, so a rule on the mount root applies. Implementations
// without the fix stop at the filesystem root and deny.
//
// This is erratum 3, from Linux commit 49c9e09d9610 ("landlock: Fix handling of
// disconnected directories"), so which answer is right depends on what the
// implementation reports.
TEST(LandlockV1Test, RuleOnBindMountRootReachesDisconnectedDirectory) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string src = JoinPath(root.path(), "src");
  const std::string mount_root = JoinPath(src, "a");
  const std::string dir = JoinPath(mount_root, "b");
  const std::string moved_dir = JoinPath(src, "b");
  const std::string mount_point = JoinPath(root.path(), "mp");
  ASSERT_THAT(mkdir(src.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_root.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_point.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(mount_root.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    // The only way to name the file once its directory has been moved out of
    // the mount is through a descriptor opened before the move.
    int dirfd = open(JoinPath(mount_point, "b").c_str(),
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    TEST_PCHECK(dirfd >= 0);
    TEST_PCHECK(rename(dir.c_str(), moved_dir.c_str()) == 0);

    // The rule names the root of the bind mount, which is no longer an ancestor
    // of the file in the filesystem, only in the mount.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, mount_root,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyFs(openat(dirfd, "f", O_RDONLY)));
  }));
  const int want = LandlockErratumFixed(3) ? kAllowed : kDenied;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.mount_and_pivot
//   fs_test.c layout1.topology_changes_with_net_and_fs
TEST(LandlockV1Test, MountDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string to = dst_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    // The same mount succeeds before the domain is enforced, so the failure
    // below is Landlock's and not a missing capability.
    TEST_PCHECK(mount(from.c_str(), to.c_str(), nullptr, MS_BIND, nullptr) ==
                0);
    TEST_PCHECK(umount2(to.c_str(), MNT_DETACH) == 0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyMount(
        mount(from.c_str(), to.c_str(), nullptr, MS_BIND, nullptr)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.mount_and_pivot
//   fs_test.c layout1.topology_changes_with_net_and_fs
TEST(LandlockV1Test, PivotRootDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath new_root_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string new_root = new_root_dir.path();
  const std::string put_old = JoinPath(new_root, "old");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    // pivot_root(2) requires the new root to be a mount point other than the
    // current root, so give it one of its own.
    TEST_PCHECK(mount("none", new_root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(put_old.c_str(), 0755) == 0);

    ApplyFsPolicy(kFsAccessV1, new_root, kFsAccessV1);
    // A pivot_root(2) that Landlock let through would fail with EINVAL, not
    // EPERM, if this setup were wrong.
    _exit(ClassifyMount(PivotRoot(new_root, put_old)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.move_mount
//   fs_test.c layout1.topology_changes_with_net_and_fs
TEST(LandlockV1Test, MoveMountDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath first_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath second_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string first = first_dir.path();
  const std::string second = second_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), first.c_str(), nullptr, MS_BIND, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyMount(MoveMount(AT_FDCWD, first, AT_FDCWD, second, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.topology_changes_with_net_and_fs
TEST(LandlockV1Test, Umount2DeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string to = dst_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), to.c_str(), nullptr, MS_BIND, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyMount(umount2(to.c_str(), MNT_DETACH)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.release_inodes
//   fs_test.c layout3_fs.release_inodes
//
// A rule is keyed by the file, not by the name it was added under: deleting
// the covered file and creating a new one at the same path must not let the
// old rule grant access to the new file. Linux guarantees this by holding the
// inode the rule refers to; gVisor by retiring the deleted file's inode
// number so a later file cannot inherit it, even if the host hands the same
// host inode number out again.
TEST(LandlockV1Test, RuleDiesWithTheFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string target;
  target = file.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    // Only READ_FILE is handled, so the unlink and the re-creation below are
    // unrestricted; the rule is added on the file itself.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, target,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(target) != kAllowed) {
      _exit(kSetup);
    }
    if (unlink(target.c_str()) != 0) {
      _exit(kSetup);
    }
    int fd = open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
      _exit(kSetup);
    }
    close(fd);
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.relative_open
//
// Ports the REL_OPEN and REL_CHDIR arms of test_relative_path(); the two
// chroot arms are listed in the gap list at the end of this file.
//
// Restriction is a property of the resolved file, not of the way it was
// named.
TEST(LandlockV1Test, RelativePathsAreEnforced) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed_abs = JoinPath(root.path(), "a");
  const std::string outside_abs = JoinPath(root.path(), "b");
  ASSERT_THAT(mkdir(allowed_abs.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(outside_abs.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(allowed_abs, "f")));
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(outside_abs, "g")));
  static std::string top;
  top = root.path();
  static std::string allowed;
  allowed = allowed_abs;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (chdir(top.c_str()) != 0) {
      _exit(kSetup);
    }
    int outside_dirfd = open("b", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (outside_dirfd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen("a/f") != kAllowed) {
      _exit(kOther);
    }
    int denied = open("b/g", O_RDONLY);
    if (denied >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    // Lookups starting from a directory fd are restricted all the same.
    _exit(ClassifyFs(openat(outside_dirfd, "g", O_RDONLY)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.execute
TEST(LandlockV1Test, ExecuteOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE, allowed,
                  LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.execute
//
// execve(2) opens the file with O_RDONLY, so Linux requires
// LANDLOCK_ACCESS_FS_READ_FILE in addition to LANDLOCK_ACCESS_FS_EXECUTE. A
// policy that handles only READ_FILE therefore still restricts execution, even
// though it does not handle EXECUTE at all.
TEST(LandlockV1Test, ExecuteOutsideAllowedTreeDeniedWhenOnlyReadFileHandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.execute
//
// Granting EXECUTE alone is not enough when the policy also handles READ_FILE:
// both rights are required, and both must be granted beneath the same
// directory.
TEST(LandlockV1Test, ExecuteInsideAllowedTreeDeniedWithoutReadFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                  allowed, LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.execute
//
// Conversely, READ_FILE is only required when the policy handles it. A policy
// handling EXECUTE alone must still permit an execve(2) it grants EXECUTE for.
// The exec fails on its missing interpreter rather than succeeding, so anything
// other than EACCES means Landlock allowed it.
TEST(LandlockV1Test, ExecuteInsideAllowedTreeAllowedWhenReadFileUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE, allowed,
                  LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.execute
//
// EXECUTE is handled and the rule grants only READ_FILE, so the execve is
// denied even though the very same file may be read.
TEST(LandlockV1Test, ExecuteInsideAllowedTreeDeniedWithoutExecuteGrant) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                  allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.link
//
// link(2) needs the right to create the file, but not the right to remove it:
// the source stays where it is.
TEST(LandlockV1Test, LinkSameDirAllowedWithMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.link
TEST(LandlockV1Test, LinkSameDirDeniedWithoutMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    EnforceOrDie(fd);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.link
TEST(LandlockV1Test, LinkSameDirDoesNotRequireRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.link
TEST(LandlockV1Test, LinkAcrossDirectoriesRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from, kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.link
//
// link(2) does not detach the source, so the source directory needs no removal
// right and its absence must not turn the EXDEV into an EACCES.
TEST(LandlockV1Test, LinkAcrossDirectoriesWithoutRemoveFileStillReportsExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "linked");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, from, 0,
        to, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.link
//
// It does need the right to create the file in the destination, though.
TEST(LandlockV1Test, LinkAcrossDirectoriesWithoutMakeRegReportsEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "linked");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, from,
                      LANDLOCK_ACCESS_FS_MAKE_REG, to, 0);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// Renaming a regular file within one directory needs both the right to create
// the file and the right to remove it.
TEST(LandlockV1Test, RenameSameDirAllowedWithMakeRegAndRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
TEST(LandlockV1Test, RenameSameDirDeniedWithoutRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
TEST(LandlockV1Test, RenameSameDirDeniedWithoutMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// A domain that handles none of the rights a rename needs does not constrain
// it.
TEST(LandlockV1Test, RenameSameDirAllowedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_DIR);
    EnforceOrDie(fd);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// Renaming over an existing file also needs the right to remove the file being
// replaced.
TEST(LandlockV1Test, RenameOverExistingFileDeniedWithoutRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = dst_file.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
TEST(LandlockV1Test, RenameOverExistingFileAllowedWithBothRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = dst_file.release();
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.rename_file
//   fs_test.c layout1.reparent_refer
//
// Only the v1-visible half of reparent_refer: without
// LANDLOCK_ACCESS_FS_REFER every reparenting rename is EXDEV.
//
// Reparenting is not expressible in ABI v1, so it is refused outright even when
// every v1 right is granted on both directories.
TEST(LandlockV1Test, RenameAcrossDirectoriesRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to, "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from, kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// The refusal does not depend on which rights the domain handles: merely having
// a domain is enough.
TEST(LandlockV1Test, RenameAcrossDirectoriesRefusedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_DIR);
    EnforceOrDie(fd);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// EXDEV is not the only answer reparenting can get. current_check_refer_path()
// prioritizes EACCES over EXDEV: if the policy denies a right the operation
// would need even within one directory, that denial is reported, and EXDEV is
// reserved for the case where the only thing missing is the ability to
// reparent. The comment on that function explains why — it lets a caller tell
// "there is no way to do this" apart from "copy the file instead".
//
// Here the destination grants the right to create the file but the source
// grants nothing, so the rename is denied for want of REMOVE_FILE.
TEST(LandlockV1Test, RenameAcrossDirectoriesWithoutRemoveFileReportsEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to_dir.path(), "moved");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, from, 0,
        to, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// The mirror image: the source may remove the file but the destination may not
// create one.
TEST(LandlockV1Test, RenameAcrossDirectoriesWithoutMakeRegReportsEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to_dir.path(), "moved");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, from,
        LANDLOCK_ACCESS_FS_REMOVE_FILE, to, 0);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// Kernel comment: "Checks that file1_s1d1 cannot be removed (instead of
// EISDIR)."
//
// The EISDIR for renaming a non-directory over a directory comes from
// vfs_rename() too, so it loses to the hook as well.
TEST(LandlockV1Test, RenameFileOverDirReportsEaccesNotEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string src;
  static std::string dst;
  src = src_file.path();
  dst = dst_dir.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  ASSERT_TRUE(WIFEXITED(control) && WEXITSTATUS(control) == kErrIsdir)
      << "control exit status " << control;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_file
//
// A same-directory RENAME_EXCHANGE of two regular files needs both MAKE_REG
// and REMOVE_FILE, the union current_check_refer_path() computes for it.
TEST(LandlockV1Test, RenameExchangeRequiresExchangeRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();
  TempPath a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  static std::string src;
  src = a.release();
  static std::string dst;
  dst = b.release();
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;
  // Filesystems that do not implement RENAME_EXCHANGE report EINVAL, which is
  // treated as unsupported rather than a failure.
  constexpr int kExchangeUnsupported = 107;
  auto classify = [](int rc) -> int {
    if (rc == 0) {
      return kAllowed;
    }
    switch (errno) {
      case EACCES:
        return kDenied;
      case EINVAL:
      case ENOSYS:
        return kExchangeUnsupported;
      default:
        return kOther;
    }
  };

  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  SKIP_IF(WIFEXITED(granted) && WEXITSTATUS(granted) == kExchangeUnsupported);
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kAllowed)
      << "exit status " << granted;

  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kDenied)
      << "exit status " << denied;
}

// Linux selftests:
//   fs_test.c layout1.rename_file
//   fs_test.c layout1.rename_dir
//
// RENAME_EXCHANGE reparents both ends, which no v1 layer can allow, and the
// EACCES-over-EXDEV priority applies to it the same as to a plain rename.
TEST(LandlockV1Test, RenameExchangeAcrossDirectoriesRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath a_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath b_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(a_dir.path()));
  TempPath b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(b_dir.path()));
  static std::string top;
  top = root.path();
  static std::string src;
  src = a.release();
  static std::string dst;
  dst = b.release();
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;
  constexpr int kExchangeUnsupported = 107;
  auto classify = [](int rc) -> int {
    if (rc == 0) {
      return kAllowed;
    }
    switch (errno) {
      case EACCES:
        return kErrAcces;
      case EXDEV:
        return kErrExdev;
      case EINVAL:
      case ENOSYS:
        return kExchangeUnsupported;
      default:
        return kOther;
    }
  };

  // With every needed make/remove right granted, a cross-directory exchange
  // is still refused with EXDEV because no v1 layer can allow reparenting.
  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, top, kRights);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  SKIP_IF(WIFEXITED(granted) && WEXITSTATUS(granted) == kExchangeUnsupported);
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kErrExdev)
      << "exit status " << granted;

  // EACCES takes priority over EXDEV when a needed right is missing.
  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, top, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kErrAcces)
      << "exit status " << denied;
}

// Linux selftest: fs_test.c layout1.rename_dir
//
// Renaming a directory needs the directory-flavored rights.
TEST(LandlockV1Test, RenameDirSameDirRequiresMakeDirAndRemoveDir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed));
  const std::string src = src_dir.release();
  const std::string dst = JoinPath(allowed, "renamed_dir");
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_dir
TEST(LandlockV1Test, RenameDirSameDirDeniedWithoutRemoveDir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed));
  const std::string src = src_dir.release();
  const std::string dst = JoinPath(allowed, "renamed_dir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.rename_dir
//
// Moving a directory needs MAKE_DIR and REMOVE_DIR rather than the file
// rights, so a policy that grants only the file rights denies it.
TEST(LandlockV1Test, RenameDirAcrossDirectoriesWithoutMakeDirReportsEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(from_dir.path()));
  const std::string src = src_dir.release();
  const std::string dst = JoinPath(to_dir.path(), "moved");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from, LANDLOCK_ACCESS_FS_REMOVE_DIR, to,
                      LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.remove_dir
TEST(LandlockV1Test, RemoveDirOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.remove_dir
TEST(LandlockV1Test, RemoveDirInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside_dir.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.remove_file
TEST(LandlockV1Test, RemoveFileOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.remove_file
TEST(LandlockV1Test, RemoveFileInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.make_fifo
//   fs_test.c layout1.make_reg_1
//   fs_test.c layout1.make_reg_2
//
// The kernel drives the same test_make_file() body for MAKE_CHAR and
// MAKE_BLOCK too; those need CAP_MKNOD and are in the gap list.
//
// Each mknod type demands its own MAKE_* right; granting one does not grant
// the others.
TEST(LandlockV1Test, MknodTypesRequireMatchingMakeRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();
  static std::string fifo_path;
  fifo_path = JoinPath(allowed, "fifo");
  static std::string reg_path;
  reg_path = JoinPath(allowed, "reg");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_REG,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_FIFO);
    if (mkfifo(fifo_path.c_str(), 0644) != 0) {
      _exit(kOther);
    }
    int rc = mknod(reg_path.c_str(), S_IFREG | 0644, 0);
    _exit(rc < 0 && errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.make_reg_1
//   fs_test.c layout1.make_reg_2
TEST(LandlockV1Test, MakeRegOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(root.path(), "new_file");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    int fd = open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftests:
//   fs_test.c layout1.make_reg_1
//   fs_test.c layout1.make_reg_2
TEST(LandlockV1Test, MakeRegInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(allowed_dir.path(), "new_file");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    int fd = open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.make_sym
//
// Renaming a symlink is governed by MAKE_SYM, not MAKE_REG: the right depends
// on the type of the file being moved, and the symlink itself is not followed.
TEST(LandlockV1Test, RenameSymlinkSameDirRequiresMakeSym) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_link =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(allowed, "target"));
  const std::string src = src_link.release();
  const std::string dst = JoinPath(allowed, "renamed_link");
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.make_sym
//
// Granting MAKE_REG instead of MAKE_SYM is not enough, which is what
// distinguishes this from the regular-file case.
TEST(LandlockV1Test, RenameSymlinkSameDirDeniedWithOnlyMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_link =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(allowed, "target"));
  const std::string src = src_link.release();
  const std::string dst = JoinPath(allowed, "renamed_link");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_MAKE_REG |
                      LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.make_dir
TEST(LandlockV1Test, MakeDirOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(root.path(), "new_dir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyFs(mkdir(target.c_str(), 0700)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.proc_unlinked_file
//
// A reopen through /proc/self/fd is a fresh open and gets the full Landlock
// check, as in the layout1.proc_pipeat-style selftests: holding a read fd does
// not let the thread reopen the file for writing.
TEST(LandlockV1Test, MagicLinkReopenCannotWidenAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    int fd = open(target.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    const std::string proc_path = "/proc/self/fd/" + std::to_string(fd);
    int ro = open(proc_path.c_str(), O_RDONLY);
    if (ro < 0) {
      _exit(kOther);
    }
    close(ro);
    _exit(ClassifyFs(open(proc_path.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.proc_pipe
//
// Files that live on a sentry-internal mount are reachable through procfs but
// can never be named by a rule, because no path leads to the mount itself.
// Landlock allows them unconditionally rather than making them permanently
// inaccessible; see is_nouser_or_private() and the MNT_INTERNAL case of
// is_access_to_paths_allowed() in Linux.
//
// Each of these enforces a domain that handles read and write with no rules at
// all, so nothing on an ordinary filesystem would be openable.
TEST(LandlockV1Test, PipeIsReopenableThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fds[2];
    if (pipe(fds) != 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/fd/" + std::to_string(fds[0])));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.proc_pipe
//
// Files on kernel-internal mounts are exempt from the policy, not just barred
// from rules: no rule could ever name them, so denying them would only make
// reopening a descriptor the thread already holds impossible under any domain.
// Linux allows them via SB_NOUSER/MNT_INTERNAL in is_nouser_or_private().
TEST(LandlockV1Test, ProcFdReopenOfPipeIsExempt) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fds[2];
    if (pipe(fds) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    const std::string path = "/proc/self/fd/" + std::to_string(fds[0]);
    _exit(TryReadOpen(path));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout1.truncate_unhandled
//
// A domain restricts only the rights that existed in its ABI: truncation
// looks like a write, but it has a right of its own that v1 predates.
TEST(LandlockV1Test, TruncateUnrestrictedByV1Domain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "content", 0666));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_WRONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    // LANDLOCK_ACCESS_FS_TRUNCATE is ABI v3; a v1 domain cannot restrict
    // truncation, even when it denies WRITE_FILE.
    if (truncate(target.c_str(), 3) != 0) {
      _exit(errno == EACCES ? kDenied : kOther);
    }
    if (ftruncate(fd, 0) != 0) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout2_overlay.same_content_different_file
//
// Writing to a file that exists only in an overlay's lower layer copies it up,
// which makes the filesystem itself create and open the copy in the upper
// layer. Those internal operations run under the credentials the overlay
// captured when it was mounted, which carry no domain, so the policy is applied
// once to the write the caller asked for and not again to the layer files it
// happens to touch. A rule can only ever name what is reachable through the
// merged directory, so checking the layers would deny a write the policy
// plainly grants.
//
// Matches Linux, which reaches the domain through cred->security and so drops
// it in ovl_override_creds().
TEST(LandlockV1Test, OverlayCopyUpAllowedByRuleOnMergedDir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string source = JoinPath(lower, "victim");
  const std::string target = JoinPath(merged, "victim");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    // The layers need a filesystem of their own: overlayfs refuses an upper
    // layer that is itself on an overlay, which is what a container's temporary
    // directory usually is.
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);

    // The file exists only in the lower layer, so opening it for writing
    // through the merged directory is what forces the copy-up.
    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      // No usable overlayfs here, so there is no copy-up to observe.
      _exit(kSetup);
    }

    ApplyFsPolicy(kFsAccessV1, merged, kFsAccessV1);
    _exit(ClassifyFs(open(target.c_str(), O_WRONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: fs_test.c layout2_overlay.same_content_different_file
//
// A rule names a file, and a copy-up does not make a new file: the file the
// rule was added on is the same file after the overlay moves it to the upper
// layer, so the rule still grants its rights. Linux gets this for free because
// the rule holds a reference to the overlayfs inode, which the copy-up does not
// replace.
TEST(LandlockV1Test, OverlayRuleOnLowerFileSurvivesCopyUp) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string source = JoinPath(lower, "victim");
  const std::string target = JoinPath(merged, "victim");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);

    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kSetup);
    }

    // The rule is added on the file itself, while it exists only in the lower
    // layer.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  target,
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);

    // Opening the file for writing copies it up, and closing the descriptor
    // lets the kernel forget everything it cached about the file. What it finds
    // when it looks the file up again lives in the upper layer only.
    int writable = open(target.c_str(), O_WRONLY);
    if (writable < 0) {
      _exit(ClassifyFs(writable));
    }
    TEST_PCHECK(close(writable) == 0);

    _exit(ClassifyFs(open(target.c_str(), O_RDONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// --------------------------------------------------------------------------
// Tests ported from tools/testing/selftests/landlock/ptrace_test.c.
//
// Upstream drives a single TEST_F(scoped_domains, trace) through the eight
// FIXTURE_VARIANTs declared in scoped_base_variants.h, each naming a
// (domain_both, domain_parent, domain_child) combination. Every variant
// checks PTRACE_MODE_READ (through /proc/<pid>/environ), PTRACE_ATTACH in
// both directions and PTRACE_TRACEME. gVisor splits that matrix into one
// gtest case per interesting cell, named below by the variant it comes from.
//
// Landlock scopes ptrace: a thread confined by a domain may only trace a
// target confined by that same domain or a descendant of it. Otherwise a
// sandboxed thread could escape by driving a less restricted one.
//
// The domains below handle only filesystem rights that no operation in these
// tests performs. Any denial therefore comes from the ptrace scoping rule
// rather than from a filesystem access right.
// --------------------------------------------------------------------------

// Linux selftest: ptrace_test.c scoped_domains.trace, variant child_domain
TEST(LandlockV1Test, PtraceAttachDeniedForUnsandboxedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Fork the tracee first so that it never inherits the domain. It is a
    // child of the tracer, so YAMA's relational scope permits the attach and
    // only Landlock can deny it.
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, variant inherited_domain
TEST(LandlockV1Test, PtraceAttachAllowedWithinSameDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, variants parent_domain
// and nested_domain
TEST(LandlockV1Test, PtraceAttachAllowedForMoreRestrictedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    // The tracee stacks a further layer, making it a descendant domain.
    int stop_fd;
    pid_t tracee = ForkTracee(true, &stop_fd);
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, variants sibling_domain
// and forked_domains
//
// Sibling domains — neither an ancestor of the other — cannot trace each
// other, whichever is "larger".
TEST(LandlockV1Test, PtraceAttachDeniedBetweenSiblingDomains) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // The tracee forks first, so it does not inherit the tracer's layer, and
    // stacks a layer of its own: two domains, neither nested in the other.
    int stop_fd;
    pid_t tracee = ForkTracee(true, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, variant child_domain
// (PTRACE_TRACEME leg)
//
// PTRACE_TRACEME is checked with the same polarity: the prospective tracer is
// the parent, so a sandboxed parent may not be asked to trace an unsandboxed
// child.
TEST(LandlockV1Test, PtraceTracemeDeniedWhenParentMoreRestricted) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int go[2], result[2];
    if (pipe(go) != 0 || pipe(result) != 0) {
      _exit(kSetup);
    }
    pid_t child = fork();
    if (child < 0) {
      _exit(kSetup);
    }
    if (child == 0) {
      close(go[1]);
      close(result[0]);
      // Wait for the parent to enforce its domain before asking to be traced.
      char c;
      while (read(go[0], &c, 1) == -1 && errno == EINTR) {
      }
      int rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
      char out = rc == 0 ? kAllowed : (errno == EPERM ? kDenied : kOther);
      write(result[1], &out, 1);
      _exit(0);
    }
    close(go[0]);
    close(result[1]);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    close(go[1]);

    char out = kOther;
    if (read(result[0], &out, 1) != 1) {
      out = kSetup;
    }
    waitpid(child, nullptr, 0);
    _exit(out);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, variant inherited_domain
// (PTRACE_TRACEME leg)
//
// PTRACE_TRACEME succeeds when the would-be tracer's domain is the child's
// own, inherited across the fork.
TEST(LandlockV1Test, PtraceTracemeAllowedWithinSameDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    int result[2];
    if (pipe(result) != 0) {
      _exit(kSetup);
    }
    pid_t child = fork();
    if (child < 0) {
      _exit(kSetup);
    }
    if (child == 0) {
      close(result[0]);
      int rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
      char out = rc == 0 ? kAllowed : (errno == EPERM ? kDenied : kOther);
      write(result[1], &out, 1);
      _exit(0);
    }
    close(result[1]);
    char out = kOther;
    if (read(result[0], &out, 1) != 1) {
      out = kSetup;
    }
    waitpid(child, nullptr, 0);
    _exit(out);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, PTRACE_MODE_READ leg
// (test_ptrace_read())
//
// Reading another thread's memory through procfs is gated by the same check, so
// the scoping rule cannot be sidestepped by opening /proc/[pid]/mem directly.
TEST(LandlockV1Test, ProcMemOfUnsandboxedTargetIsInaccessible) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    const std::string path = "/proc/" + std::to_string(tracee) + "/mem";
    ChildResult result = TryReadOpen(path);
    close(stop_fd);
    waitpid(tracee, nullptr, 0);
    _exit(result);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Linux selftest: ptrace_test.c scoped_domains.trace, PTRACE_MODE_READ leg
// (test_ptrace_read())
//
// /proc/[pid]/environ sits behind the ptrace-mode access check, so the ptrace
// scoping covers it too.
TEST(LandlockV1Test, ProcEnvironOfUnsandboxedTargetDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  static std::string environ_path;
  environ_path = "/proc/" + std::to_string(getpid()) + "/environ";

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(environ_path.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    char c;
    _exit(read(fd, &c, 1) >= 0 ? kAllowed : kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Handling an access unrelated to reads keeps path lookups
    // unrestricted, isolating the ptrace-scoping check, as in the kernel's
    // ptrace selftests.
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_BLOCK);
    int fd = open(environ_path.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(errno == EACCES ? kDenied : kOther);
    }
    char c;
    ssize_t n = read(fd, &c, 1);
    if (n < 0 && errno == EACCES) {
      _exit(kDenied);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// ----------------------------------------------------------------------------
// Linux Landlock selftests that are NOT ported here
// ----------------------------------------------------------------------------
//
// Scope: this list covers only the upstream selftests that exercise behaviour
// reachable through ABI v1. Selftests that exist solely to test a later ABI are
// summarised at the end, without an individual entry each.
//
// base_test.c
// -----------
//
//   restrict_self_fd
//     Passes a file descriptor that is not a ruleset -- an fd on /dev/null --
//     to landlock_restrict_self(2) and expects EBADFD, distinguishing it from
//     the EBADF a closed fd produces. RestrictSelfRejectsBadFd above covers
//     only the EBADF leg. Worth adding; nothing blocks it.
//
//   ruleset_fd_transfer
//     Sends a ruleset fd to another process over a UNIX socket with SCM_RIGHTS
//     and enforces it there, checking a ruleset is not bound to the process
//     that created it. Needs socket-passing plumbing plus a second process that
//     enforces and then reports back; not yet written.
//
//   cred_transfer
//     Checks that a domain survives keyctl(KEYCTL_SESSION_TO_PARENT), which is
//     the only caller of the security_transfer_creds LSM hook. gVisor's
//     keyctl(2) does not implement KEYCTL_SESSION_TO_PARENT, so there is no way
//     to reach that path from a syscall test.
//
// fs_test.c
// ---------
//
//   layout1.no_restriction
//   layout1_bind.no_restriction
//   layout2_overlay.no_restriction
//     Fixture sanity checks: they open every path in the fixture's layout with
//     no Landlock domain in place, to prove a later denial came from Landlock
//     and not from the layout being broken. gVisor builds a private temp tree
//     per test rather than one shared fixture layout, so there is no shared
//     layout to validate; each test's own pre-enforcement assertions play the
//     same role.
//
//   layout1.non_overlapping_accesses
//     Stacks two layers that handle *different* single rights (MAKE_REG, then
//     REMOVE_FILE) and checks both stay in force independently. The ported
//     layering tests (LayeredRulesetsOnlyIntersect,
//     SameFileRulesInTwoLayersIntersect, RulesInOneLayerUnionAcrossAncestry)
//     all use overlapping handled masks. Worth adding.
//
//   layout1.interleaved_masked_accesses
//     Seven stacked layers that alternately grant and withhold READ_FILE and
//     WRITE_FILE over nested directories, checking the per-layer mask
//     intersection at every depth. The gVisor suite stacks at most three
//     layers. Worth adding; only the setup is laborious.
//
//   layout1.inherit_subset
//   layout1.inherit_superset
//     Partially ported as LayeredRulesetsOnlyIntersect. The upstream tests walk
//     a much larger matrix of read/write rights over dir_s1d1..s1d3 in both
//     orders; the port covers the core "a second layer can only narrow" rule.
//
//   layout1.rule_over_root_allow_then_deny
//   layout1.rule_over_root_deny
//     Add rules on "/" itself, then check that a second layer can narrow them.
//     The semantics are those of layout1.effective_access, which is ported, but
//     with the rule at the filesystem root; the assertions read paths such as
//     /dev/null and depend on the root layout of whichever filesystem the test
//     runs over. Every rule in this port is scoped to a TempPath instead. Worth
//     adding if the assertions are rewritten against the test layout.
//
//   layout1.rule_inside_mount_ns
//     Enters a new mount namespace and pivot_root()s into the test layout
//     before adding a rule, checking rules are resolved against the caller's
//     namespace. Needs CAP_SYS_ADMIN plus namespace setup; not yet written.
//
//   layout1.covered_rule
//     Sets a rule on a directory and then mounts over it, checking the rule
//     still applies to the now-hidden directory and not to the covering mount.
//     gVisor has RuleSurvivesRenameOfCoveredDirectory (in landlock_v1.cc) for
//     the rename case but nothing for the mount-over case.
//
//   layout1.relative_open, REL_CHROOT_ONLY and REL_CHROOT_CHDIR arms
//     test_relative_path() runs four ways; RelativePathsAreEnforced above ports
//     REL_OPEN and REL_CHDIR. The two chroot arms need CAP_SYS_CHROOT and
//     change the process root, which the port has not covered.
//
//   layout1.umount_sandboxer
//     Copies a helper binary into a mount, has it sandbox itself and exec a
//     second helper outside the mount, then checks the mount can be unmounted
//     -- i.e. that a domain does not pin the sandboxer's mount. Needs two
//     separate helper executables; the syscall test suite builds one static
//     binary per test target and has nowhere to put them.
//
//   layout1.make_char
//   layout1.make_block
//     The MAKE_CHAR and MAKE_BLOCK arms of test_make_file(). Creating a
//     character or block device needs CAP_MKNOD, which the syscall tests do not
//     assume; the FIFO and regular-file arms are ported in
//     MknodTypesRequireMatchingMakeRights above.
//
//   layout1.make_sym, symlink(2) creation
//     The two ported cases cover renaming a symlink under MAKE_SYM. Creating
//     one with symlink(2) under a domain that grants or withholds MAKE_SYM is
//     not covered. Worth adding.
//
//   layout1_bind.same_content_same_file
//     Four stacked layers over a bind mount, checking that the source and the
//     destination of the bind mount are the same inode yet distinct path
//     hierarchies, so a rule on one does not leak into the other. gVisor covers
//     the single-layer cases (RuleReachesFileThroughBindMount,
//     RuleAboveBindMountPointReachesMountContents) but not the layered
//     source/destination interaction.
//
//   layout2_overlay.same_content_different_file
//     Partially ported as OverlayCopyUpAllowedByRuleOnMergedDir and
//     OverlayRuleOnLowerFileSurvivesCopyUp. Upstream walks a four-layer matrix
//     across lower/upper/merge for every file in the overlay; the port covers
//     copy-up and rule-follows-inode, which are the cases where gVisor's
//     overlay differs structurally from Linux's.
//
//   layout3_fs.tag_inode_dir_parent
//   layout3_fs.tag_inode_dir_mnt
//   layout3_fs.tag_inode_dir_child
//   layout3_fs.tag_inode_file
//     A matrix that tags a rule at each level of the hierarchy (".", the mount
//     point, the parent directory, the file itself) across six filesystem
//     types: tmpfs, ramfs, cgroup2, proc, sysfs and hostfs. gVisor's syscall
//     tests already re-run each target over several filesystem configurations
//     from the harness side, and ramfs, cgroup2 and sysfs are not mountable
//     from within the tests.
//
// ptrace_test.c
// -------------
//
//   scoped_domains.trace, variants without_domain and parent_domain
//     without_domain is the no-Landlock control case; parent_domain's
//     "P2 traces P1 is allowed" leg is the same check as
//     PtraceAttachAllowedForMoreRestrictedTarget above. Both are covered
//     indirectly; there is no separate case for the control arm.
//
//   The Yama-gated legs of scoped_domains.trace
//     Upstream skips or inverts several expectations depending on
//     /proc/sys/kernel/yama/ptrace_scope. gVisor does not implement Yama, so
//     the port always takes the Yama-disabled path.
//
// Not applicable to ABI v1
// ------------------------
//
//   ABI v2 (LANDLOCK_ACCESS_FS_REFER): fs_test.c layout1.reparent_refer,
//     refer_denied_by_default1..4, refer_mount_root_deny,
//     refer_part_mount_tree_is_allowed, reparent_link, reparent_rename,
//     reparent_exdev_layers_rename1/rename2/exchange1/exchange2/exchange3,
//     reparent_remove, reparent_dom_superset,
//     layout1_bind.reparent_cross_mount, path_disconnected_rename,
//     path_disconnected_link, and the whole layout4_disconnected_leafs and
//     layout5_disconnected_branch fixtures. Under v1 there is no REFER right at
//     all, so every reparenting rename or link is unconditionally EXDEV. That
//     v1-visible behaviour is covered by
//     RenameAcrossDirectoriesRefusedWithExdev,
//     LinkAcrossDirectoriesRefusedWithExdev and
//     RenameExchangeAcrossDirectoriesRefusedWithExdev above.
//
//   ABI v3 (LANDLOCK_ACCESS_FS_TRUNCATE): fs_test.c layout1.truncate,
//     layout1.ftruncate, the ftruncate fixture and its w_w/t_t/wt_w/wt_wt/wt_t
//     variants, memfd_ftruncate_and_ioctl and o_path_ftruncate_and_ioctl. A v1
//     domain never restricts truncation; that is what
//     TruncateUnrestrictedByV1Domain above asserts.
//
//   ABI v4 (network rights): the whole of net_test.c, plus fs_test.c
//     layout1.topology_changes_with_net_only.
//
//   ABI v5 (LANDLOCK_ACCESS_FS_IOCTL_DEV): fs_test.c
//     layout1.blanket_permitted_ioctls, layout1.named_pipe_ioctl,
//     layout1.named_unix_domain_socket_ioctl and the ioctl fixture with its
//     handled_i_allowed_none/handled_i_allowed_i/unhandled variants.
//
//   ABI v6 (LANDLOCK_SCOPE_*): scoped_abstract_unix_test.c,
//     scoped_signal_test.c and scoped_multiple_domain_test.c.
//
//   ABI v7 (audit and restrict_self flags): base_test.c
//     restrict_self_fd_logging_flags and restrict_self_logging_flags, the
//     22 tests of the fs_test.c audit_layout1 fixture, and ptrace_test.c
//     audit.trace.

}  // namespace
}  // namespace testing
}  // namespace gvisor
