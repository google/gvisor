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

// Landlock syscall tests.
//
// Landlock (https://docs.kernel.org/userspace-api/landlock.html) is an
// unprivileged, inherited, kernel-enforced sandbox. A task builds a ruleset
// (landlock_create_ruleset), populates it with rules (landlock_add_rule), then
// irreversibly applies it to itself (landlock_restrict_self). A domain is a
// stack of such rulesets; an access is permitted only if every layer permits
// it, and layers can only ever add restrictions.
//
// gVisor does not yet implement Landlock. Per the plan agreed in
// google/gvisor#13439, this suite is written against native Linux as the
// reference implementation and is skipped under gVisor via
// SKIP_IF(IsRunningOnGvisor()). It aims to cover every Landlock rule type and
// access right we would like gVisor to support, grouped by the ABI version
// that introduced it:
//
//   v1 filesystem access rights: EXECUTE, READ_FILE, WRITE_FILE, READ_DIR,
//                                REMOVE_{FILE,DIR}, and the MAKE_* family for
//                                creating filesystem objects (MAKE_REG and
//                                MAKE_DIR are exercised as representatives)
//   v2 LANDLOCK_ACCESS_FS_REFER  (cross-directory rename/link)
//   v3 LANDLOCK_ACCESS_FS_TRUNCATE
//   v4 LANDLOCK_RULE_NET_PORT    (BIND_TCP / CONNECT_TCP)
//   v5 LANDLOCK_ACCESS_FS_IOCTL_DEV
//   v6 scoping                   (abstract UNIX sockets, signals)
//   v7 audit                     (not yet covered here; see TODO at the end)
//
// Each test guards itself with SKIP_IF(LandlockAbiVersion() < N) so it only
// runs where the kernel actually supports the feature. As gVisor gains support
// for each rule type, the corresponding SKIP_IF(IsRunningOnGvisor()) guard
// should be removed one at a time.
//
// Because Landlock is irreversible, a test can never restrict itself directly
// (that would poison the whole test runner). Every enforcement test therefore
// runs its policy inside a forked child (InForkedProcess) and inspects the
// child's exit status from the parent. Note that EXPECT_*/ASSERT_* are NOT
// async-signal-safe and must not be called inside the child function; the child
// signals its outcome through exit codes instead.

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <asm/ioctls.h>  // TCGETS

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Landlock UAPI definitions.
//
// We deliberately do not #include <linux/landlock.h>. The build sysroot may
// ship kernel headers older than the ABI this suite targets (it exercises up to
// v6), in which case the header would be missing newer constants and struct
// fields (e.g. landlock_ruleset_attr::scoped, added in v6) and the test would
// fail to compile even though the syscalls are driven directly via syscall(2).
// Defining the UAPI locally keeps the test buildable against any kernel headers;
// these layouts and values are part of the stable kernel ABI. Each symbol is
// annotated with the ABI version that introduced it; tests guard their use with
// SKIP_IF(LandlockAbiVersion() < N) so nothing here runs on a kernel too old to
// support it.
struct landlock_ruleset_attr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;  // ABI v4+
  uint64_t scoped;              // ABI v6+
};

enum landlock_rule_type {
  LANDLOCK_RULE_PATH_BENEATH = 1,  // ABI v1+
  LANDLOCK_RULE_NET_PORT = 2,      // ABI v4+
};

struct landlock_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
} __attribute__((packed));

struct landlock_net_port_attr {
  uint64_t allowed_access;
  uint64_t port;
};

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)

// Filesystem access rights.
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)      // v1
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)   // v1
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)    // v1
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)     // v1
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)   // v1
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)  // v1
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)    // v1
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)     // v1
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)     // v1
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)    // v1
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)   // v1
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)  // v1
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)    // v1
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)       // v2
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)    // v3
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)   // v5

// Network access rights (ABI v4+).
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)

// Scope flags (ABI v6+).
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)

// glibc does not (portably) wrap the Landlock syscalls, so invoke them via
// syscall(2). The __NR_* numbers come from <asm/unistd.h> on supported kernels.
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

long landlock_create_ruleset(const struct landlock_ruleset_attr* attr,
                             size_t size, uint32_t flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

long landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
                       const void* attr, uint32_t flags) {
  return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

long landlock_restrict_self(int ruleset_fd, uint32_t flags) {
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

// Every filesystem access right introduced in ABI v1. Later ABIs added more FS
// rights (REFER in v2, TRUNCATE in v3, IOCTL_DEV in v5), which are covered by
// their own tests rather than folded in here. Unknown bits are rejected with
// EINVAL by create_ruleset, which is itself something we test.
constexpr uint64_t kFsAccessV1 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM;

// TCP ports used by the network tests. One is granted by the ruleset, the other
// is not; both are high and unlikely to collide with anything on loopback.
constexpr uint16_t kAllowedPort = 13370;
constexpr uint16_t kDeniedPort = 13371;

// Child exit codes used to report the outcome of an operation attempted under
// a Landlock policy. Kept small and distinct from any errno.
enum ChildResult {
  kAllowed = 0,   // operation succeeded (or failed for a non-Landlock reason)
  kDenied = 100,  // operation blocked by Landlock (EACCES, or EPERM for scopes)
  kSetup = 101,   // a setup step (ruleset/rule/restrict) failed unexpectedly
  kOther = 102,   // operation failed with an unexpected errno
};

// Returns the highest Landlock ABI version the running kernel supports, or a
// negative errno-style value if Landlock is unavailable.
int LandlockAbiVersion() {
  return landlock_create_ruleset(nullptr, 0,
                                 LANDLOCK_CREATE_RULESET_VERSION);
}

// ---- Child-side helpers ----------------------------------------------------
//
// These are only ever called inside an InForkedProcess child. Any setup
// failure terminates the child with _exit(kSetup); none of them use
// EXPECT_*/ASSERT_* (which are not async-signal-safe in a forked child).

// Creates a ruleset handling the given access masks (any may be 0). Returns the
// ruleset fd; terminates the child with kSetup on failure.
int CreateRuleset(uint64_t handled_fs, uint64_t handled_net, uint64_t scoped) {
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = handled_fs;
  attr.handled_access_net = handled_net;
  attr.scoped = scoped;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  if (fd < 0) {
    _exit(kSetup);
  }
  return fd;
}

// Adds a LANDLOCK_RULE_PATH_BENEATH rule granting `access` beneath `path`.
void AddPathRule(int ruleset_fd, const std::string& path, uint64_t access) {
  int parent_fd = open(path.c_str(), O_PATH | O_CLOEXEC);
  if (parent_fd < 0) {
    _exit(kSetup);
  }
  struct landlock_path_beneath_attr attr = {};
  attr.allowed_access = access;
  attr.parent_fd = parent_fd;
  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) != 0) {
    _exit(kSetup);
  }
  close(parent_fd);
}

// Adds a LANDLOCK_RULE_NET_PORT rule granting `access` on `port`.
void AddPortRule(int ruleset_fd, uint64_t access, uint16_t port) {
  struct landlock_net_port_attr attr = {};
  attr.allowed_access = access;
  attr.port = port;
  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &attr, 0) != 0) {
    _exit(kSetup);
  }
}

// Sets no_new_privs and irreversibly applies the ruleset to the child, then
// closes the fd. Landlock requires no_new_privs unless the caller has
// CAP_SYS_ADMIN.
void EnforceOrDie(int ruleset_fd) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    _exit(kSetup);
  }
  if (landlock_restrict_self(ruleset_fd, 0) != 0) {
    _exit(kSetup);
  }
  close(ruleset_fd);
}

// Convenience: the common single-rule filesystem policy. Handles
// `handled_access` and grants `allowed_access` beneath `allowed_path`.
void ApplyFsPolicy(uint64_t handled_access, const std::string& allowed_path,
                   uint64_t allowed_access) {
  int fd = CreateRuleset(handled_access, 0, 0);
  AddPathRule(fd, allowed_path, allowed_access);
  EnforceOrDie(fd);
}

// Classifies the result of a filesystem/enforcement syscall: kAllowed if it
// succeeded, kDenied on EACCES (a Landlock denial), kOther otherwise.
ChildResult ClassifyFs(int rc) {
  if (rc >= 0) {
    return kAllowed;
  }
  return errno == EACCES ? kDenied : kOther;
}

// Classifies the result of connect(2): the Landlock hook rejects with EACCES;
// any other failure (e.g. ECONNREFUSED because nothing is listening) means the
// syscall got past Landlock, i.e. it was allowed.
ChildResult ClassifyConnect(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  return errno == EACCES ? kDenied : kAllowed;
}

// Classifies an operation governed by a Landlock scope, whose denials surface
// as EPERM (and, for some object types, EACCES).
ChildResult ClassifyScope(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  if (errno == EPERM || errno == EACCES) {
    return kDenied;
  }
  return kOther;
}

// Attempts to open `path` for reading. See ClassifyFs for the return value.
ChildResult TryReadOpen(const std::string& path) {
  int fd = open(path.c_str(), O_RDONLY);
  if (fd >= 0) {
    close(fd);
    return kAllowed;
  }
  return errno == EACCES ? kDenied : kOther;
}

// ---- Parent-side helpers ---------------------------------------------------

// Builds a sockaddr_in for 127.0.0.1:port.
struct sockaddr_in LoopbackAddr(uint16_t port) {
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  return addr;
}

// Fills `addr` with an abstract-namespace AF_UNIX address for `name` and
// returns the address length to pass to bind/connect.
socklen_t AbstractAddr(const std::string& name, struct sockaddr_un* addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  // Leading NUL byte selects the abstract namespace.
  memcpy(&addr->sun_path[1], name.data(), name.size());
  return offsetof(struct sockaddr_un, sun_path) + 1 + name.size();
}

// ---- Availability / ABI ----------------------------------------------------

TEST(LandlockTest, AbiVersionIsSupported) {
  SKIP_IF(IsRunningOnGvisor());
  int version = LandlockAbiVersion();
  SKIP_IF(version < 0 && errno == ENOSYS);  // Kernel too old for Landlock.
  ASSERT_GE(version, 1) << "unexpected Landlock ABI version";
}

TEST(LandlockTest, CreateRulesetHandlingAllV1RightsSucceeds) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
}

// ---- create_ruleset / add_rule / restrict_self error paths -----------------

TEST(LandlockTest, CreateRulesetRejectsUnknownFlags) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), /*flags=*/0xffff),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, CreateRulesetRejectsUnknownAccessBits) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  // Set a bit far above any defined access right.
  attr.handled_access_fs = (1ULL << 63);
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, AddRuleRejectsUnknownRuleType) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  struct landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(fd, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EINVAL));
  close(fd);
}

TEST(LandlockTest, AddPathBeneathRejectsUnhandledAccess) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  struct landlock_path_beneath_attr path_beneath = {};
  // WRITE_FILE was not declared in handled_access_fs above.
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockTest, RestrictSelfWithoutNoNewPrivsFails) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);
  // Run in a child so we do not set no_new_privs / a policy on the test runner.
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    // Deliberately skip PR_SET_NO_NEW_PRIVS: restrict_self must fail EPERM.
    _exit(landlock_restrict_self(fd, 0) < 0 && errno == EPERM ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockTest, RestrictSelfRejectsBadFd) {
  SKIP_IF(IsRunningOnGvisor());
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

// ---- Filesystem enforcement: READ_FILE (ABI v1) ----------------------------

// A file OUTSIDE the allowed subtree cannot be read once restricted.
TEST(LandlockTest, ReadOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  // The target file lives in root, i.e. outside allowed_dir.
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

// A file INSIDE the allowed subtree can still be read after restricting.
TEST(LandlockTest, ReadInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
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

// The restriction is inherited across fork: a grandchild is equally confined.
TEST(LandlockTest, RestrictionInheritedAcrossFork) {
  SKIP_IF(IsRunningOnGvisor());
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
    // The policy must apply to a grandchild forked after restrict_self.
    pid_t pid = fork();
    if (pid == 0) {
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) {
      _exit(kSetup);
    }
    // Propagate the grandchild's verdict verbatim as our own exit code.
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Stacking a second, stricter layer can only ever remove access: a file that
// the first layer allowed reading becomes unreadable once a second layer that
// grants nothing is applied.
TEST(LandlockTest, LayeredRulesetsOnlyIntersect) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    // Layer 1 grants READ_FILE beneath allowed_dir.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    // Layer 2 handles READ_FILE but grants it nowhere, denying all reads.
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE, 0, 0);
    EnforceOrDie(fd);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// ---- Filesystem enforcement: WRITE_FILE (ABI v1) ---------------------------

TEST(LandlockTest, WriteFileOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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

TEST(LandlockTest, WriteFileInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
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

// ---- Filesystem enforcement: READ_DIR (ABI v1) -----------------------------

TEST(LandlockTest, ReadDirOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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

// ---- Filesystem enforcement: MAKE_REG / MAKE_DIR (ABI v1) ------------------

TEST(LandlockTest, MakeRegOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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

TEST(LandlockTest, MakeRegInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
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

TEST(LandlockTest, MakeDirOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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

// ---- Filesystem enforcement: REMOVE_FILE (ABI v1) --------------------------

TEST(LandlockTest, RemoveFileOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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

TEST(LandlockTest, RemoveFileInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  // The child unlinks this file; release it so the parent's TempPath cleanup
  // does not try (and noisily fail) to delete it again.
  target = inside.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// ---- Filesystem enforcement: REMOVE_DIR (ABI v1) ---------------------------
//
// REMOVE_DIR is checked against the directory that contains the target, so it
// is granted on (or denied by) the parent, not the directory being removed.

TEST(LandlockTest, RemoveDirOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  // The directory to remove lives in root, i.e. outside allowed_dir.
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

TEST(LandlockTest, RemoveDirInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  // The child removes this directory; release it so the parent's TempPath
  // cleanup does not try (and noisily fail) to delete it again.
  target = inside_dir.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// ---- Filesystem enforcement: EXECUTE (ABI v1) ------------------------------
//
// Only the denial case is checked: a clean "allowed" execve is fragile because
// the dynamic loader would also need EXECUTE on the interpreter and shared
// libraries outside the allowed subtree. The EXECUTE permission is checked
// during execve(2) before the file is read, so it is denied with EACCES
// regardless of whether the file is a valid executable.
TEST(LandlockTest, ExecuteOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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

// ---- Filesystem enforcement: REFER (ABI v2) --------------------------------
//
// REFER governs renaming/linking a file across directories. It is always denied
// by default, so a cross-directory rename into a subtree with no REFER rule is
// blocked even though REFER is handled. A rename refused by Landlock reports
// EXDEV (as if the directories were on different filesystems).
TEST(LandlockTest, ReferRenameOutOfAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 2);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath src =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string from;
  static std::string to;
  from = src.path();
  // Destination is in root, which has no REFER rule.
  to = JoinPath(root.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REFER, allowed, LANDLOCK_ACCESS_FS_REFER);
    int rc = rename(from.c_str(), to.c_str());
    // Landlock reports a refused cross-directory rename as EXDEV.
    _exit(rc == 0 ? kAllowed : (errno == EXDEV ? kDenied : kOther));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockTest, ReferRenameWithinAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 2);

  // Both subdirectories live under a common parent that grants REFER.
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent.path()));
  TempPath src =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(src_dir.path()));
  const std::string allowed = parent.path();
  static std::string from;
  static std::string to;
  // The child renames this file away; release it so the parent's TempPath
  // cleanup does not try (and noisily fail) to delete the old path.
  from = src.release();
  to = JoinPath(dst_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REFER, allowed, LANDLOCK_ACCESS_FS_REFER);
    _exit(ClassifyFs(rename(from.c_str(), to.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// ---- Filesystem enforcement: TRUNCATE (ABI v3) -----------------------------

TEST(LandlockTest, TruncateOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 3);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "content", 0600));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_TRUNCATE, allowed,
                  LANDLOCK_ACCESS_FS_TRUNCATE);
    _exit(ClassifyFs(truncate(target.c_str(), 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockTest, TruncateInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 3);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "content", 0600));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_TRUNCATE, allowed,
                  LANDLOCK_ACCESS_FS_TRUNCATE);
    _exit(ClassifyFs(truncate(target.c_str(), 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// ---- Network enforcement: BIND_TCP / CONNECT_TCP (ABI v4) ------------------

TEST(LandlockTest, BindTcpDisallowedPortDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 4);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, LANDLOCK_ACCESS_NET_BIND_TCP, 0);
    AddPortRule(fd, LANDLOCK_ACCESS_NET_BIND_TCP, kAllowedPort);
    EnforceOrDie(fd);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    struct sockaddr_in addr = LoopbackAddr(kDeniedPort);
    int rc = bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(s);
    _exit(ClassifyFs(rc));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockTest, BindTcpAllowedPortAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 4);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, LANDLOCK_ACCESS_NET_BIND_TCP, 0);
    AddPortRule(fd, LANDLOCK_ACCESS_NET_BIND_TCP, kAllowedPort);
    EnforceOrDie(fd);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    struct sockaddr_in addr = LoopbackAddr(kAllowedPort);
    int rc = bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(s);
    _exit(ClassifyFs(rc));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockTest, ConnectTcpDisallowedPortDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 4);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, LANDLOCK_ACCESS_NET_CONNECT_TCP, 0);
    AddPortRule(fd, LANDLOCK_ACCESS_NET_CONNECT_TCP, kAllowedPort);
    EnforceOrDie(fd);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    struct sockaddr_in addr = LoopbackAddr(kDeniedPort);
    int rc =
        connect(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(s);
    _exit(ClassifyConnect(rc));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockTest, ConnectTcpAllowedPortAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 4);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, LANDLOCK_ACCESS_NET_CONNECT_TCP, 0);
    AddPortRule(fd, LANDLOCK_ACCESS_NET_CONNECT_TCP, kAllowedPort);
    EnforceOrDie(fd);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    // Nothing is listening; ECONNREFUSED means Landlock let the connect through.
    struct sockaddr_in addr = LoopbackAddr(kAllowedPort);
    int rc =
        connect(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(s);
    _exit(ClassifyConnect(rc));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockTest, AddNetPortRuleWithoutHandledNetFails) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 4);
  // Ruleset handles a filesystem right but no network right.
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  struct landlock_net_port_attr net_port = {};
  net_port.allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP;
  net_port.port = kAllowedPort;
  EXPECT_THAT(landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &net_port, 0),
              SyscallFailsWithErrno(EINVAL));
  close(fd);
}

// ---- Filesystem enforcement: IOCTL_DEV (ABI v5) ----------------------------
//
// IOCTL_DEV governs non-allowlisted ioctls on device files. TCGETS on a
// non-tty normally fails with ENOTTY; under a ruleset that handles IOCTL_DEV
// but does not grant it on the device, the ioctl is rejected earlier with
// EACCES instead.
TEST(LandlockTest, IoctlDevDeniedWithoutRule) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 5);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Grant IOCTL_DEV only beneath /tmp, which does not cover /dev/null.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_IOCTL_DEV, "/tmp",
                  LANDLOCK_ACCESS_FS_IOCTL_DEV);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      _exit(kSetup);
    }
    char buf[64] = {};
    int rc = ioctl(fd, TCGETS, buf);
    close(fd);
    _exit(rc < 0 && errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockTest, IoctlDevAllowedWithRule) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 5);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Grant IOCTL_DEV beneath /dev, covering /dev/null.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_IOCTL_DEV, "/dev",
                  LANDLOCK_ACCESS_FS_IOCTL_DEV);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      _exit(kSetup);
    }
    char buf[64] = {};
    int rc = ioctl(fd, TCGETS, buf);
    close(fd);
    // Landlock permitted the ioctl; the device itself returns ENOTTY.
    _exit(rc < 0 && errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// ---- Scoping (ABI v6) ------------------------------------------------------

// A signal scope blocks sending signals to processes outside the domain. The
// child's parent (the test runner) is outside the child's scope.
TEST(LandlockTest, SignalScopeBlocksSignalToOutsideProcess) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  // Ignore SIGUSR1 in the parent in case the signal is (incorrectly) delivered.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  struct sigaction old = {};
  ASSERT_THAT(sigaction(SIGUSR1, &sa, &old), SyscallSucceeds());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_SIGNAL);
    EnforceOrDie(fd);
    _exit(ClassifyScope(kill(getppid(), SIGUSR1)));
  }));
  EXPECT_THAT(sigaction(SIGUSR1, &old, nullptr), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Signals to a process inside the same domain (a grandchild forked after the
// scope was applied) are still allowed.
TEST(LandlockTest, SignalScopeAllowsSignalWithinDomain) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_SIGNAL);
    EnforceOrDie(fd);
    pid_t pid = fork();
    if (pid == 0) {
      pause();
      _exit(0);
    }
    int rc = kill(pid, SIGKILL);
    int st;
    waitpid(pid, &st, 0);
    _exit(ClassifyScope(rc));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// An abstract-UNIX-socket scope blocks connecting to an abstract socket that
// was created outside the domain.
TEST(LandlockTest, AbstractUnixScopeBlocksConnectToOutsideSocket) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  const std::string name = "landlock_test_" + std::to_string(getpid());
  struct sockaddr_un addr;
  socklen_t addrlen = AbstractAddr(name, &addr);

  // Parent (outside the child's future domain) creates and listens.
  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_THAT(listener, SyscallSucceeds());
  ASSERT_THAT(
      bind(listener, reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());
  ASSERT_THAT(listen(listener, 1), SyscallSucceeds());

  static std::string child_name;
  child_name = name;
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
    EnforceOrDie(fd);
    struct sockaddr_un a;
    socklen_t alen = AbstractAddr(child_name, &a);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    int rc = connect(s, reinterpret_cast<struct sockaddr*>(&a), alen);
    close(s);
    _exit(ClassifyScope(rc));
  }));
  close(listener);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// The abstract-UNIX-socket scope does not affect pathname (filesystem) UNIX
// sockets: connecting to one created outside the domain still succeeds.
TEST(LandlockTest, AbstractUnixScopeAllowsPathnameSocket) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 6);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string sock_path = JoinPath(dir.path(), "sock");
  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  ASSERT_LT(sock_path.size(), sizeof(addr.sun_path));
  memcpy(addr.sun_path, sock_path.data(), sock_path.size());

  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_THAT(listener, SyscallSucceeds());
  ASSERT_THAT(bind(listener, reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(listener, 1), SyscallSucceeds());

  static std::string child_path;
  child_path = sock_path;
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(0, 0, LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
    EnforceOrDie(fd);
    struct sockaddr_un a = {};
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, child_path.data(), child_path.size());
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
      _exit(kSetup);
    }
    int rc = connect(s, reinterpret_cast<struct sockaddr*>(&a), sizeof(a));
    close(s);
    _exit(ClassifyScope(rc));
  }));
  close(listener);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// TODO(gvisor.dev/issue/13439): ABI v7 (audit) is not covered here because it
// requires a kernel exposing LANDLOCK_RESTRICT_SELF_LOG_* and the Landlock
// audit records. Add coverage once the test infrastructure runs on such a
// kernel. Each new rule type should keep the fork-and-verify shape above and,
// once implemented in gVisor, drop its SKIP_IF(IsRunningOnGvisor()) guard.

}  // namespace

}  // namespace testing
}  // namespace gvisor
