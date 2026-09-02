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

// Landlock syscall tests (ABI v1).
//
// The tests here are gVisor's own: error-ordering checks derived from reading
// the Linux VFS, and coverage of paths the kernel selftests do not exercise
// (host-donated file descriptors, mqueue, fsconfig, overlay specifics and
// symlink races). The tests ported from the kernel's Landlock selftests, each
// annotated with the upstream test it corresponds to, are in
// landlock_v1_selftests.cc.

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
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

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// To an implementation whose highest ABI is 1 the attr ends at
// handled_access_fs, and any nonzero byte past those 8 bytes is an unknown
// tail reported as E2BIG, even where a later ABI put handled_access_net.
// Kernels that know the field reject its unknown bits as EINVAL before an
// all-empty request is reported; ENOMSG is wrong everywhere.
TEST(LandlockV1Test, CreateRulesetEmptyFsWithUnknownNetBitsIsNotEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_net = (1ULL << 63);
  int rc = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_LT(rc, 0);
  EXPECT_NE(errno, ENOMSG) << "empty handled_access_fs was reported before "
                              "the unknown bits elsewhere in the attr";
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

// Under gVisor, descriptors donated by the runtime — the application's stdio
// among them — live on the internal host mount, so they take the same
// exemption: a fully restrictive domain must not break reopening stderr, and
// a rule can no more name one than it can name a pipe.
TEST(LandlockV1Test, HostFdsAreInternal) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  // Control: without a domain, stderr must be reopenable through
  // /proc/self/fd, or the run below proves nothing.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open("/proc/self/fd/2", O_WRONLY);
    _exit(fd >= 0 ? kAllowed : kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = 2;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADFD));
  close(ruleset_fd);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    int fd = open("/proc/self/fd/2", O_WRONLY);
    if (fd >= 0) {
      _exit(kAllowed);
    }
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictionInheritedAcrossFork) {
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
    pid_t pid = fork();
    if (pid == 0) {
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) {
      _exit(kSetup);
    }
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// open(2) accepts a fourth access mode alongside O_RDONLY, O_WRONLY and O_RDWR,
// which yields a file that is neither readable nor writable. Landlock takes the
// rights an open requires from the mode the resulting file has, so this one
// requires none and a domain that grants nothing lets it through.
TEST(LandlockV1Test, OpenWithFourthAccessModeRequiresNoRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE |
                            LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_ACCMODE);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// A Landlock denial is one error among several that a removal can produce, and
// Linux fixes where it sits among them. do_unlinkat() and do_rmdir() call
// mnt_want_write() and resolve the victim before security_path_unlink() and
// security_path_rmdir(), and reach may_delete() and the filesystem's own
// removal only from inside vfs_unlink() and vfs_rmdir(), which run after the
// hook. So EROFS, ENOENT and a trailing slash outrank EACCES, and EACCES in
// turn outranks the sticky-bit EPERM, EISDIR, ENOTDIR and ENOTEMPTY.
//
// Getting this wrong leaks information in both directions: reporting EACCES
// where Linux reports ENOENT tells a sandboxed thread nothing it should not
// know, but reporting ENOTEMPTY where Linux reports EACCES tells it about a
// directory the policy is meant to hide.

// Creating over an existing file is EEXIST before it is the policy's EACCES:
// filename_create() resolves the child before security_path_mkdir() and its
// siblings run.
TEST(LandlockV1Test, MkdirOverExistingFileReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string target;
  target = existing.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyErrno(mkdir(target.c_str(), 0755)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrExist)
      << "exit status " << status;
}

// A denied open must fail before O_TRUNC takes effect: the check runs before
// the truncation in every implementation, so the file's contents survive.
TEST(LandlockV1Test, DeniedTruncatingOpenLeavesFileIntact) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "contents", 0644));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY | O_TRUNC);
    if (fd >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    struct stat st;
    if (stat(target.c_str(), &st) != 0) {
      _exit(kSetup);
    }
    _exit(st.st_size == 8 ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Binding a unix socket to a filesystem path creates a socket file, which
// needs MAKE_SOCK in the directory, through the same mknod hook.
TEST(LandlockV1Test, UnixBindRequiresMakeSock) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();

  // Binds to a name relative to the working directory, which is set to the
  // covered directory first: an absolute TEST_TMPDIR path can exceed
  // sun_path, and the cwd is resolved like any other path prefix.
  auto bind_at = [](const std::string& name) -> ChildResult {
    if (chdir(allowed.c_str()) != 0) {
      return kSetup;
    }
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      return kSetup;
    }
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name.c_str(), name.size() + 1);
    int rc = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int err = errno;
    close(sock);
    if (rc == 0) {
      return kAllowed;
    }
    return err == EACCES ? kDenied : kOther;
  };

  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_SOCK);
    _exit(bind_at("denied.sock"));
  }));
  SKIP_IF(WIFEXITED(denied) && WEXITSTATUS(denied) == kSetup);
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kDenied)
      << "exit status " << denied;

  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SOCK, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_SOCK);
    _exit(bind_at("granted.sock"));
  }));
  SKIP_IF(WIFEXITED(granted) && WEXITSTATUS(granted) == kSetup);
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kAllowed)
      << "exit status " << granted;
}

TEST(LandlockV1Test, UnlinkOfMissingFileReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = JoinPath(dir.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfMissingDirReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = JoinPath(dir.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

// filename_unlinkat() rejects a trailing slash before the hook, with the
// comment "Why not before? Because we want correct error value".
TEST(LandlockV1Test, UnlinkWithTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string target;
  target = victim_dir.path() + "/";

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

// unlink(2) acts on the covered dentry, not on what is mounted over it:
// do_unlinkat()'s __lookup_hash() does not follow mounts, so the trailing
// slash reports the mount point directory's EISDIR, with or without a domain.
// A resolution that followed the mount would instead restart in the mounted
// filesystem with no path left and misreport ENOENT.
TEST(LandlockV1Test, UnlinkOfMountPointWithTrailingSlashReportsEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath mnt_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string from;
  static std::string target;
  from = src_dir.path();
  target = mnt_dir.path() + "/";

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), mnt_dir.path().c_str(), nullptr, MS_BIND,
                      nullptr) == 0);
    // Without a domain first, so a failure below is an ordering bug and not
    // Landlock misapplied.
    TEST_PCHECK(unlink(target.c_str()) < 0 && errno == EISDIR);
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

// The same trailing-slash-before-the-hook ordering on a kernfs filesystem,
// where the victim walk reports ENOTDIR itself and only EISDIR is left for
// the explicit check.
TEST(LandlockV1Test, UnlinkKernfsTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink("/proc/sys/")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

// link(2) with a directory source is EPERM from vfs_link(), which do_linkat()
// reaches only after security_path_link(), so wherever the unrestricted link
// reports EPERM, a domain's cross-directory EXDEV wins, kernfs included.
TEST(LandlockV1Test, LinkOfProcDirectoryUnderDomainIsExdevNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);

  // Linux procfs fails the new-name lookup with ENOENT before any security
  // hook or link-support check runs; gVisor's procfs reports EPERM for the
  // unsupported link instead. Landlock's EXDEV can only take priority in the
  // latter ordering, so derive the expectation from the unrestricted errno.
  const int control =
      ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link"));
  SKIP_IF(control != kErrPerm && control != kErrNoent);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link")));
  }));
  const int want = control == kErrNoent ? kErrNoent : kErrExdev;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status << " want " << want;
}

// may_delete() is what turns unlink(2) of a directory into EISDIR, and it runs
// after the hook.
TEST(LandlockV1Test, UnlinkOfDirectoryReportsEaccesNotEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string target;
  target = victim_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfNonDirectoryReportsEaccesNotEnotdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string target;
  target = victim.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

// ENOTEMPTY comes from the filesystem's own ->rmdir(), which vfs_rmdir() calls
// after the hook. Reporting it would tell the sandboxed thread that a directory
// it may not remove is not empty.
TEST(LandlockV1Test, RmdirOfNonEmptyDirReportsEaccesNotEnotempty) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath occupant =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(victim_dir.path()));
  static std::string target;
  target = victim_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

// The sticky bit's EPERM comes from __check_sticky(), reached through
// may_delete() inside vfs_unlink(), so the hook decides first.
//
// The sticky check exempts the caller when it owns either the victim or the
// directory, or when it has CAP_FOWNER, so the test switches to a uid that
// owns neither and has no capabilities.
TEST(LandlockV1Test, UnlinkInStickyDirReportsEaccesNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath sticky_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sticky_dir.path()));
  ASSERT_THAT(chmod(sticky_dir.path().c_str(), 01777), SyscallSucceeds());
  // Any uid other than the caller's will do; nobody is conventional.
  constexpr uid_t kNobody = 65534;
  static std::string target;
  target = victim.path();

  // As kNobody the caller owns neither the sticky directory nor the victim
  // and loses all capabilities, so the unrestricted unlink fails the sticky
  // check with EPERM. Dropping privileges this way rather than chown'ing the
  // files to kNobody keeps the test independent of whether ownership changes
  // are honored by the backing filesystem (they are not with shared gofer
  // file access). The control establishes that a sticky denial was really
  // arranged, so that the EACCES below is the hook winning rather than the
  // sticky check quietly not applying.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kErrPerm));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

// mnt_want_write() runs before the hook, so a read-only mount is reported as
// such even when the policy would also have refused.
TEST(LandlockV1Test, UnlinkOnReadOnlyMountReportsErofsNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string victim = JoinPath(root, "victim");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    int fd = open(victim.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) == 0);
    if (mount(nullptr, root.c_str(), nullptr, MS_REMOUNT | MS_RDONLY,
              nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(victim.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

// The same ordering on a kernfs-backed filesystem: creating on a read-only
// proc mount is EROFS before it is the policy's EACCES.
TEST(LandlockV1Test, MkdirOnReadOnlyProcMountReportsErofsNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string target = JoinPath(root, "newdir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("proc", root.c_str(), "proc", MS_RDONLY, nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyErrno(mkdir(target.c_str(), 0755)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

// ENOENT and EROFS keep their kernel ordering under a domain denying
// REMOVE_FILE: which one wins depends on where in the walk the path goes
// missing.
TEST(LandlockV1Test, UnlinkMissingPathOnReadOnlyProcMountErrnos) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  // A missing intermediate component fails the parent walk with ENOENT
  // before the read-only mount is considered, while a missing final
  // component is only looked up after mnt_want_write() and so reports EROFS.
  const std::string missing_intermediate = JoinPath(root, "nonexistent/victim");
  const std::string missing_final = JoinPath(root, "nonexistent");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("proc", root.c_str(), "proc", MS_RDONLY, nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    int intermediate = ClassifyErrno(unlink(missing_intermediate.c_str()));
    if (intermediate != kErrNoent) {
      _exit(intermediate);
    }
    _exit(ClassifyErrno(unlink(missing_final.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

constexpr int kEexist = 105;
// The filesystem does not implement RENAME_NOREPLACE and rejects the flag
// outright, so the rename never reaches the point this is testing. rename.cc
// tolerates the same answer.
constexpr int kNoReplaceUnsupported = 106;

int ClassifyNoReplace(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  switch (errno) {
    case EEXIST:
      return kEexist;
    case ENOSYS:
    case EINVAL:
      return kNoReplaceUnsupported;
    case EACCES:
      return kDenied;
    case EXDEV:
      return kExdev;
    default:
      return kOther;
  }
}

// do_renameat2() rejects RENAME_NOREPLACE over an existing destination before
// it calls security_path_rename(), so a domain that would otherwise refuse the
// rename must not turn that EEXIST into its own error. Here the refusal would
// be EXDEV, since the two directories differ.
TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(to_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from_dir.path(), kFsAccessV1, to_dir.path(),
                      kFsAccessV1);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kEexist, kNoReplaceUnsupported));
}

// The same ordering holds within one directory, where the refusal would
// otherwise be EACCES.
TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    // Handle the rights the rename needs but grant none of them, so that the
    // domain would deny it.
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG |
                           LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kEexist, kNoReplaceUnsupported));
}

// RENAME_NOREPLACE onto a name that does not exist is an ordinary rename, so
// the domain still gets to refuse it.
TEST(LandlockV1Test, RenameNoReplaceOntoMissingStillRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from_dir.path(), kFsAccessV1, to_dir.path(),
                      kFsAccessV1);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kExdev, kNoReplaceUnsupported));
}

// Everything vfs_rename() checks comes after security_path_rename(), just as it
// does for unlink(2) and rmdir(2) above: filename_renameat2() calls the hook
// last, immediately before vfs_rename(). So the domain's EACCES outranks the
// ENOTEMPTY the filesystem's own ->rename() reports for a non-empty
// destination, which would otherwise tell a sandboxed thread what is inside a
// directory the policy is meant to hide.
TEST(LandlockV1Test, RenameOverNonEmptyDirReportsEaccesNotEnotempty) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath occupant =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dst_dir.path()));
  static std::string src;
  static std::string dst;
  src = src_dir.path();
  dst = dst_dir.path();

  // The control establishes that the rename really would fail with ENOTEMPTY:
  // the domain handles a right the rename does not need, so it permits it.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  ASSERT_TRUE(WIFEXITED(control) && WEXITSTATUS(control) == kErrNotempty)
      << "control exit status " << control;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

// do_linkat() calls may_linkat() — the protected_hardlinks check — before
// security_path_link(), and reaches everything else only from inside
// vfs_link(), after it. So the EPERM for an unsafe source outranks the domain's
// EACCES, the other way around from the EPERM that vfs_link() itself reports
// for a directory.
//
// A source is unsafe when the caller neither owns it nor may both read and
// write it, so the test switches to a uid for which the 0644 source is
// readable but not writable and no capability exempts the caller.
TEST(LandlockV1Test, LinkOfUnsafeSourceReportsEpermNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  ASSERT_THAT(chmod(src_file.path().c_str(), 0644), SyscallSucceeds());
  ASSERT_THAT(chmod(dir.path().c_str(), 0777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  static std::string src;
  static std::string dst;
  src = src_file.path();
  dst = JoinPath(dir.path(), "hardlink");

  // As kNobody the caller does not own the source, cannot write to it
  // (0644), and has no capabilities, so with protected_hardlinks the link
  // fails may_linkat() with EPERM. may_linkat() runs before
  // security_path_link() in do_linkat(), so EPERM must still win under a
  // Landlock domain denying MAKE_REG. Dropping privileges via setresuid
  // rather than chown'ing the source to kNobody keeps the test independent
  // of whether ownership changes are honored by the backing filesystem. The
  // control establishes that the link really is refused as unsafe, so that
  // the EPERM below is not the protected_hardlinks check quietly not
  // applying.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  SKIP_IF(!WIFEXITED(control) || WEXITSTATUS(control) != kErrPerm);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrPerm)
      << "exit status " << status;
}

// Creates an empty regular file at path.
void CreateFile(const std::string& path) {
  int fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
}

// A rule is attached to the file it was added for, the way Linux attaches it to
// a struct inode, rather than to the name the file had at the time. These tests
// reach a covered file by a name it did not have when the rule was added.
TEST(LandlockV1Test, RuleReachesFileThroughHardLink) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath other_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));

  const std::string target = JoinPath(covered_dir.path(), "target");
  ASSERT_NO_FATAL_FAILURE(CreateFile(target));
  const std::string link_path = JoinPath(other_dir.path(), "link");
  ASSERT_THAT(link(target.c_str(), link_path.c_str()), SyscallSucceeds());

  // A file alongside the link, to show that the rule reaches the link because
  // it names the covered file and not because the directory is unrestricted.
  const std::string uncovered = JoinPath(other_dir.path(), "uncovered");
  ASSERT_NO_FATAL_FAILURE(CreateFile(uncovered));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, target,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(uncovered) != kDenied) {
      _exit(kOther);
    }
    _exit(TryReadOpen(link_path));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleSurvivesRenameOfCoveredDirectory) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  // The child renames this directory, so let the enclosing directory's
  // recursive cleanup dispose of it under whatever name it ends up with.
  const std::string parent = root.path();
  const std::string dir = covered_dir.release();
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));
  const std::string renamed = JoinPath(parent, "renamed");

  constexpr uint64_t kHandled = LANDLOCK_ACCESS_FS_READ_FILE |
                                LANDLOCK_ACCESS_FS_MAKE_DIR |
                                LANDLOCK_ACCESS_FS_REMOVE_DIR;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kHandled);
    AddPathRule(fd, dir, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, parent,
                LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR);
    EnforceOrDie(fd);

    // The rename stays within one directory, so ABI v1 permits it given the
    // rights above.
    if (rename(dir.c_str(), renamed.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(JoinPath(renamed, "f")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// The counterpart: the rule keeps following the file for as long as any hard
// link to it remains, so removing one of two names must not retire it.
TEST(LandlockV1Test, RuleSurvivesUnlinkOfOneHardLink) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string first;
  first = file.release();
  static std::string second;
  second = JoinPath(dir.path(), "second");
  ASSERT_THAT(link(first.c_str(), second.c_str()), SyscallSucceeds());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, first,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (unlink(first.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(second));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// MAKE_REG guards creation, not the O_CREAT flag: whether it is needed depends
// on whether a file actually comes into existence.
TEST(LandlockV1Test, OpenCreatOnExistingFileDoesNotRequireMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string existing_path;
  existing_path = existing.path();
  static std::string missing_path;
  missing_path = JoinPath(dir.path(), "newfile");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_WRITE_FILE);
    // O_CREAT on an existing file creates nothing, so MAKE_REG is not
    // required.
    int fd = open(existing_path.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
      _exit(ClassifyFs(fd));
    }
    close(fd);
    // Actually creating a file still requires MAKE_REG.
    _exit(ClassifyFs(open(missing_path.c_str(), O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// The flip side: when O_CREAT finds the file already there, the rights for the
// requested access mode still apply, and MAKE_REG alone does not satisfy them.
TEST(LandlockV1Test, OpenCreatOnExistingFileStillRequiresOpenRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string existing_path;
  existing_path = existing.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyFs(open(existing_path.c_str(), O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// The domain gates opens, not fds that already exist.
TEST(LandlockV1Test, PreEnforcementFdsKeepWorking) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_RDWR);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    // Landlock checks accesses at open time only; fds opened before
    // enforcement retain their access.
    if (pwrite(fd, "x", 1, 0) != 1) {
      _exit(kOther);
    }
    char c;
    if (pread(fd, &c, 1, 0) != 1 || c != 'x') {
      _exit(kOther);
    }
    // A fresh open of the same file is denied.
    _exit(TryReadOpen(target) == kDenied ? kAllowed : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// The mount hooks run where Linux places them, which is after the syscall has
// copied in its arguments and resolved the paths it was given. A denial
// therefore never hides a malformed call: the errno the call would have failed
// with without a domain is still the one reported.
TEST(LandlockV1Test, MountWithMissingTargetReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string missing = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyErrno(
        mount(from.c_str(), missing.c_str(), nullptr, MS_BIND, nullptr)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

// umount(2) is the one mount hook Linux runs late: can_umount() rejects a path
// that names no mount of ours before do_umount() reaches
// security_sb_umount().
TEST(LandlockV1Test, Umount2OfNonMountpointReportsEinvalNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath plain_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string plain = plain_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, plain, kFsAccessV1);
    _exit(ClassifyErrno(umount2(plain.c_str(), MNT_DETACH)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrInval)
      << "exit status " << status;
}

TEST(LandlockV1Test, PivotRootWithMissingNewRootReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = root.path();
  const std::string missing = JoinPath(dir, "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, dir, kFsAccessV1);
    _exit(ClassifyErrno(PivotRoot(missing, dir)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

// Linux resolves both pivot_root paths with LOOKUP_DIRECTORY before the
// Landlock hook, so a non-directory new_root reports ENOTDIR, not EPERM.
TEST(LandlockV1Test, PivotRootWithNonDirectoryNewRootReportsEnotdirNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = root.path();
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir));
  const std::string nondir = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, dir, kFsAccessV1);
    _exit(ClassifyErrno(PivotRoot(nondir, dir)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNotdir)
      << "exit status " << status;
}

// Linux resolves move_mount's source path before its target path, so when
// both are bad the source's errno wins even for a landlocked caller.
TEST(LandlockV1Test, MoveMountResolvesSourceBeforeTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string bad_source = JoinPath(file.path(), "x");  // ENOTDIR
  const std::string missing_target = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, root.path(), kFsAccessV1);
    _exit(ClassifyErrno(
        MoveMount(AT_FDCWD, bad_source, AT_FDCWD, missing_target, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNotdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, MoveMountWithMissingSourceReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string to = dst_dir.path();
  const std::string missing = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyErrno(MoveMount(AT_FDCWD, missing, AT_FDCWD, to, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

// The overlay checks the policy before copying the parent up, so that a denied
// removal leaves the layers untouched. It must still resolve the victim first:
// removing a name that does not exist is ENOENT whatever the policy says.
TEST(LandlockV1Test, OverlayUnlinkOfMissingFileReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string missing_file = JoinPath(merged, "missing");
  const std::string missing_dir = JoinPath(merged, "missing_dir");
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
    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kSetup);
    }

    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    int rc = ClassifyErrno(unlink(missing_file.c_str()));
    if (rc != kErrNoent) {
      _exit(rc);
    }
    _exit(ClassifyErrno(rmdir(missing_dir.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

// A path names a different file at different moments. An operation resolves it
// once and acts on what that resolution found; the policy must be applied to
// that same file. Checking a separate resolution of the same path leaves a
// window in which the two disagree, and an operation can then land on a file
// the check never saw.
//
// These tests swap a symlink out from under a path while the operation runs.
// They assert only that nothing ever landed in the directory the policy does
// not cover, so a run that never wins the race still passes and they cannot
// flake; a run that does win fails only if the operation escaped.

constexpr int kRaceIterations = 300;

// Builds the layout the race tests share: covered/ and uncovered/ hold the
// files an operation might reach, and swap/link points at one of them.
void MakeRaceDirs(const std::string& root, std::string* covered,
                  std::string* uncovered, std::string* swap_dir,
                  std::string* link) {
  *covered = JoinPath(root, "covered");
  *uncovered = JoinPath(root, "uncovered");
  *swap_dir = JoinPath(root, "swap");
  *link = JoinPath(*swap_dir, "link");
  ASSERT_THAT(mkdir(covered->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(mkdir(uncovered->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(mkdir(swap_dir->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(symlink(covered->c_str(), link->c_str()), SyscallSucceeds());
}

// Repoints link at covered and uncovered in turn until stop is set. The rename
// is atomic, so a path through link always resolves to one of the two. Requires
// MAKE_SYM and REMOVE_FILE beneath the directory holding link.
void SwapLinkUntilStopped(const std::string& link, const std::string& covered,
                          const std::string& uncovered,
                          std::atomic<bool>* stop) {
  const std::string tmp = link + ".tmp";
  bool to_covered = false;
  while (!stop->load(std::memory_order_relaxed)) {
    unlink(tmp.c_str());
    if (symlink(to_covered ? covered.c_str() : uncovered.c_str(),
                tmp.c_str()) != 0) {
      continue;
    }
    if (rename(tmp.c_str(), link.c_str()) != 0) {
      continue;
    }
    to_covered = !to_covered;
  }
}

// Removes the symlinks the swapping leaves behind. TempPath's recursive delete
// follows a symlink to a directory and then cannot remove what it found.
void RemoveSwapLinks(const std::string& link) {
  EXPECT_THAT(unlink(link.c_str()), SyscallSucceeds());
  unlink((link + ".tmp").c_str());
}

// Each iteration creates a name of its own, so no create ever finds the file
// already there and every one of them is a fresh attempt.
TEST(LandlockV1Test, CreateThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  // A cooperative save between two of the racing operations decides the race
  // for them, and one per syscall of the setup below costs minutes.
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    // Both directories grant the right to write the new file, so that the only
    // thing standing between a create and the uncovered directory is MAKE_REG.
    AddPathRule(fd, covered,
                LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, uncovered, LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, swap_dir,
                LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);

    std::atomic<bool> stop(false);
    ScopedThread swapper(
        [&] { SwapLinkUntilStopped(link, covered, uncovered, &stop); });

    int created = 0;
    for (int i = 0; i < kRaceIterations; i++) {
      const std::string victim = JoinPath(link, "victim." + std::to_string(i));
      int victim_fd =
          open(victim.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
      if (victim_fd >= 0) {
        created++;
        close(victim_fd);
      }
    }
    stop.store(true, std::memory_order_relaxed);
    swapper.Join();

    // Some creates have to have gone through, or the swapping left the link
    // pointing at the uncovered directory for the whole run and the test
    // proved nothing.
    _exit(created > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  // Checked here because reading the uncovered directory is not something the
  // policy allows the child to do.
  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, true)),
              ::testing::IsEmpty());
  RemoveSwapLinks(link);
}

// The same for the other direction: an unlink must not remove a file the policy
// does not cover, however the path it was given resolves.
TEST(LandlockV1Test, UnlinkThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  // The same names beneath both directories, so an unlink through the link has
  // something to remove whichever way it resolves.
  for (int i = 0; i < kRaceIterations; i++) {
    const std::string name = "victim." + std::to_string(i);
    ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(covered, name)));
    ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(uncovered, name)));
  }

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    AddPathRule(fd, covered, LANDLOCK_ACCESS_FS_REMOVE_FILE);
    AddPathRule(fd, swap_dir,
                LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);

    std::atomic<bool> stop(false);
    ScopedThread swapper(
        [&] { SwapLinkUntilStopped(link, covered, uncovered, &stop); });

    int removed = 0;
    for (int i = 0; i < kRaceIterations; i++) {
      const std::string victim = JoinPath(link, "victim." + std::to_string(i));
      if (unlink(victim.c_str()) == 0) {
        removed++;
      }
    }
    stop.store(true, std::memory_order_relaxed);
    swapper.Join();

    _exit(removed > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, true)),
              ::testing::SizeIs(kRaceIterations));
  RemoveSwapLinks(link);
}

TEST(LandlockV1Test, MemfdIsReopenableThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int memfd = syscall(__NR_memfd_create, "landlock-test", 0);
    if (memfd < 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/fd/" + std::to_string(memfd)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// A socket has no path, but its procfs entry must still be openable for the
// same reason. Reopening it yields ENXIO on Linux rather than a Landlock
// denial, so the test only insists that it is not EACCES.
TEST(LandlockV1Test, SocketProcFdIsNotDeniedByLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    const std::string path = "/proc/self/fd/" + std::to_string(sock);
    int fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0) {
      close(fd);
      _exit(kAllowed);
    }
    _exit(errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// A POSIX message queue lives on the mqueue filesystem, which is mounted
// internally for each IPC namespace but is a mountable filesystem all the same.
// mq_open(2) therefore goes through the same open hook as open(2), and a domain
// that handles the rights the open needs denies it unless a rule names the
// queue or the mqueue root, neither of which is reachable by a path here.
TEST(LandlockV1Test, MqOpenDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_denied";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(ClassifyFs(mq_open(name.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// The denial above comes from the rights the open requires, not from mqueue
// being off limits to sandboxed threads in general: a domain that handles no
// right an open needs leaves mq_open(2) alone.
TEST(LandlockV1Test, MqOpenAllowedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_unhandled";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    mqd_t fd = mq_open(name.c_str(), O_RDWR);
    if (fd == static_cast<mqd_t>(-1)) {
      _exit(ClassifyFs(-1));
    }
    mq_close(fd);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// The walk that mq_open(2) performs reaches the root of the mqueue filesystem,
// so a rule added on a mount of it grants access to the queues beneath. This is
// the only way to name them: the mount that mq_open(2) itself uses is not in
// any path.
TEST(LandlockV1Test, MqOpenAllowedByRuleOnMqueueMount) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string mountpoint = dir.path();
  const std::string name = "/landlock_mq_open_allowed";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("mqueue", mountpoint.c_str(), "mqueue", 0, nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  mountpoint,
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
    mqd_t fd = mq_open(name.c_str(), O_RDWR);
    if (fd == static_cast<mqd_t>(-1)) {
      _exit(ClassifyFs(-1));
    }
    mq_close(fd);
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

#ifndef SYS_fsopen
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 0x6
#define FSCONFIG_CMD_RECONFIGURE 0x7
#endif

// Reconfiguring a superblock through a filesystem context descriptor changes
// the mount tree just as mount(2) with MS_REMOUNT does, so it is refused
// outright while a domain is active, whatever rights that domain handles.
TEST(LandlockV1Test, FsconfigReconfigureDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fs_fd = syscall(SYS_fsopen, "tmpfs", 0);
    if (fs_fd < 0) {
      _exit(kSetup);
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      _exit(kSetup);
    }
    // fsmount(2) leaves the context ready to reconfigure the superblock it
    // created, which is the only way to reach FSCONFIG_CMD_RECONFIGURE
    // without fspick(2).
    int mount_fd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mount_fd < 0) {
      _exit(kSetup);
    }

    // The domain handles a right that no reconfiguration could ever need, to
    // show that the denial does not depend on the rights it handles.
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    _exit(ClassifyMount(syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_RECONFIGURE,
                                nullptr, nullptr, 0)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

// The domain survives execve: the exec'd image is enforced, not just the
// process that called landlock_restrict_self(2). The policy lets the shell
// and its libraries be read and executed but grants WRITE_FILE nowhere, so
// the shell starts and its redirect fails.
TEST(LandlockV1Test, DomainEnforcedAfterExecve) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(access("/bin/sh", X_OK) != 0);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath control_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  const TempPath enforced_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string control_cmd;
  control_cmd = "echo x > " + control_file.path();
  static std::string enforced_cmd;
  enforced_cmd = "echo x > " + enforced_file.path();
  static std::string enforced_target;
  enforced_target = enforced_file.path();

  // Control: without a domain the shell and its redirect succeed, so the
  // failure below is the domain's doing.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    execl("/bin/sh", "sh", "-c", control_cmd.c_str(),
          static_cast<char*>(nullptr));
    _exit(kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == 0));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_WRITE_FILE |
                           LANDLOCK_ACCESS_FS_EXECUTE);
    AddPathRule(fd, "/",
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);
    EnforceOrDie(fd);
    execl("/bin/sh", "sh", "-c", enforced_cmd.c_str(),
          static_cast<char*>(nullptr));
    _exit(kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_NE(WEXITSTATUS(status), 0) << "the redirect was not denied";
  EXPECT_NE(WEXITSTATUS(status), kSetup) << "execve itself failed";
  // The denied redirect must not have truncated or written the file.
  struct stat st;
  ASSERT_THAT(stat(enforced_target.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, 0);
}

// The domain survives a change of identity: credentials are rebuilt by
// setuid(2), and the domain must come along, as it lives in Linux's cred
// blob.
TEST(LandlockV1Test, DomainSurvivesSetuid) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // The file lives directly under /tmp: TEST_TMPDIR's ancestors may not be
  // searchable by the unprivileged uid, and the control below would skip the
  // test.
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/tmp"));
  static std::string target;
  target = file.path();
  constexpr uid_t kNobody = 65534;

  // Control: after setuid alone, ordinary permissions still let the file be
  // read, so the denial below can only be the domain's.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (setuid(kNobody) != 0 || getuid() != kNobody) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    if (setuid(kNobody) != 0 || getuid() != kNobody) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// landlock_restrict_self(2) restricts the calling thread only; a sibling
// thread of the same process stays unrestricted, as domains are per-thread.
TEST(LandlockV1Test, RestrictSelfAppliesOnlyToCallingThread) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    std::atomic<int> thread_result{kOther};
    {
      ScopedThread t([&thread_result] {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
          thread_result = kSetup;
          return;
        }
        int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
        if (landlock_restrict_self(fd, 0) != 0) {
          thread_result = kSetup;
          return;
        }
        close(fd);
        thread_result = TryReadOpen(target);
      });
      t.Join();
    }
    if (thread_result == kSetup) {
      _exit(kSetup);
    }
    if (thread_result != kDenied) {
      _exit(kOther);
    }
    // The main thread never restricted itself.
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// The other direction: a thread created after the restriction inherits it.
TEST(LandlockV1Test, ThreadInheritsDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    std::atomic<int> thread_result{kOther};
    {
      ScopedThread t([&thread_result] { thread_result = TryReadOpen(target); });
      t.Join();
    }
    _exit(thread_result);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// A child that sandboxes itself does not restrict its parent; the inverse of
// RestrictionInheritedAcrossFork.
TEST(LandlockV1Test, ChildRestrictionDoesNotAffectParent) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    pid_t pid = fork();
    if (pid < 0) {
      _exit(kSetup);
    }
    if (pid == 0) {
      ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0 ||
        !(WIFEXITED(st) && WEXITSTATUS(st) == kDenied)) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// process_vm_readv(2) is gated by the same ptrace access check, so the
// scoping cannot be sidestepped by reading memory directly.
TEST(LandlockV1Test, ProcessVmReadvDeniedForUnsandboxedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  static char remote_buf[8] = "watched";
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    char local_buf[sizeof(remote_buf)] = {};
    struct iovec local = {local_buf, sizeof(local_buf)};
    // The tracee is a fork of this process, so remote_buf has the same
    // address there.
    struct iovec remote = {remote_buf, sizeof(remote_buf)};
    ssize_t n = process_vm_readv(tracee, &local, 1, &remote, 1, 0);
    int err = errno;
    ChildResult res =
        n >= 0 ? kAllowed
               : ((err == EPERM || err == EACCES) ? kDenied : kOther);
    close(stop_fd);
    waitpid(tracee, nullptr, 0);
    _exit(res);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
