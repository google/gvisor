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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_LANDLOCK_UTIL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_LANDLOCK_UTIL_H_

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace gvisor {
namespace testing {

// Landlock UAPI definitions.
struct landlock_ruleset_attr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;  // ABI v4+
  uint64_t scoped;              // ABI v6+
};

enum landlock_rule_type : uint32_t {
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

constexpr uint32_t LANDLOCK_CREATE_RULESET_VERSION = (1U << 0);
constexpr uint32_t LANDLOCK_CREATE_RULESET_ERRATA = (1U << 1);

// Filesystem access rights.
constexpr uint64_t LANDLOCK_ACCESS_FS_EXECUTE = (1ULL << 0);      // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_WRITE_FILE = (1ULL << 1);   // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_READ_FILE = (1ULL << 2);    // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_READ_DIR = (1ULL << 3);     // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_REMOVE_DIR = (1ULL << 4);   // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_REMOVE_FILE = (1ULL << 5);  // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_CHAR = (1ULL << 6);    // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_DIR = (1ULL << 7);     // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_REG = (1ULL << 8);     // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_SOCK = (1ULL << 9);    // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_FIFO = (1ULL << 10);   // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1ULL << 11);  // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_MAKE_SYM = (1ULL << 12);    // v1
constexpr uint64_t LANDLOCK_ACCESS_FS_REFER = (1ULL << 13);       // v2
constexpr uint64_t LANDLOCK_ACCESS_FS_TRUNCATE = (1ULL << 14);    // v3
constexpr uint64_t LANDLOCK_ACCESS_FS_IOCTL_DEV = (1ULL << 15);   // v5

// Network access rights (ABI v4+).
constexpr uint64_t LANDLOCK_ACCESS_NET_BIND_TCP = (1ULL << 0);
constexpr uint64_t LANDLOCK_ACCESS_NET_CONNECT_TCP = (1ULL << 1);

// Scope flags (ABI v6+).
constexpr uint64_t LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = (1ULL << 0);
constexpr uint64_t LANDLOCK_SCOPE_SIGNAL = (1ULL << 1);

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

inline int landlock_create_ruleset(const landlock_ruleset_attr* attr,
                                   size_t size, uint32_t flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

inline int landlock_add_rule(int ruleset_fd, landlock_rule_type type,
                             const void* attr, uint32_t flags) {
  return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

inline int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

constexpr uint64_t kFsAccessV1 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM;

constexpr uint16_t kAllowedPort = 13370;
constexpr uint16_t kDeniedPort = 13371;

enum ChildResult {
  kAllowed = 0,
  kDenied = 100,
  kSetup = 101,
  kOther = 102,
};

inline int LandlockAbiVersion() {
  return landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

// LandlockErrataFixed reports whether the implementation says it has fixed
// erratum number, which it reports as bit number-1 of the errata bitmask.
// Implementations that predate the query report nothing as fixed.
inline bool LandlockErratumFixed(int number) {
  int errata =
      landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (errata < 0) {
    return false;
  }
  return (errata & (1 << (number - 1))) != 0;
}

inline int CreateRuleset(uint64_t handled_fs, uint64_t handled_net = 0,
                         uint64_t scoped = 0) {
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = handled_fs;
  attr.handled_access_net = handled_net;
  attr.scoped = scoped;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  if (fd < 0) {
    _exit(kSetup);
  }
  return fd;
}

inline void AddPathRule(int ruleset_fd, const std::string& path,
                        uint64_t access) {
  int parent_fd = open(path.c_str(), O_PATH | O_CLOEXEC);
  if (parent_fd < 0) {
    _exit(kSetup);
  }
  landlock_path_beneath_attr attr = {};
  attr.allowed_access = access;
  attr.parent_fd = parent_fd;
  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) !=
      0) {
    _exit(kSetup);
  }
  close(parent_fd);
}

inline void AddPortRule(int ruleset_fd, uint64_t access, uint16_t port) {
  landlock_net_port_attr attr = {};
  attr.allowed_access = access;
  attr.port = port;
  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &attr, 0) != 0) {
    _exit(kSetup);
  }
}

inline void EnforceOrDie(int ruleset_fd) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    _exit(kSetup);
  }
  if (landlock_restrict_self(ruleset_fd, 0) != 0) {
    _exit(kSetup);
  }
  close(ruleset_fd);
}

inline void ApplyFsPolicy(uint64_t handled_access,
                          const std::string& allowed_path,
                          uint64_t allowed_access) {
  int fd = CreateRuleset(handled_access);
  AddPathRule(fd, allowed_path, allowed_access);
  EnforceOrDie(fd);
}

// Enforces a domain that handles handled_access and grants it nowhere, so that
// every operation needing one of those rights is denied.
inline void ApplyFsPolicyDenyingAll(uint64_t handled_access) {
  EnforceOrDie(CreateRuleset(handled_access));
}

inline ChildResult ClassifyFs(int rc) {
  if (rc >= 0) {
    return kAllowed;
  }
  return errno == EACCES ? kDenied : kOther;
}

inline ChildResult ClassifyConnect(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  return errno == EACCES ? kDenied : kAllowed;
}

inline ChildResult ClassifyScope(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  if (errno == EPERM || errno == EACCES) {
    return kDenied;
  }
  return kOther;
}

inline ChildResult TryReadOpen(const std::string& path) {
  int fd = open(path.c_str(), O_RDONLY);
  if (fd >= 0) {
    close(fd);
    return kAllowed;
  }
  return errno == EACCES ? kDenied : kOther;
}

// Landlock ABI v1 has no LANDLOCK_ACCESS_FS_REFER right, so rename(2) and
// link(2) between two directories are refused with EXDEV rather than EACCES.
constexpr int kExdev = 103;

// Landlock has no right that grants a change to the mount tree, so a thread
// with a domain cannot make one however permissive its policy. These hooks
// return EPERM rather than the EACCES the filesystem access hooks return.
constexpr int kEperm = 104;

inline int ClassifyRefer(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  if (errno == EACCES) {
    return kDenied;
  }
  if (errno == EXDEV) {
    return kExdev;
  }
  return kOther;
}

inline int ClassifyMount(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  return errno == EPERM ? kEperm : kOther;
}

// Exit codes that name the exact errno an operation produced, for the tests
// that check where a Landlock denial sits among the other errors a syscall can
// return.
enum ErrnoResult {
  kErrOk = 0,
  kErrRofs = 110,
  kErrNoent = 111,
  kErrAcces = 112,
  kErrPerm = 113,
  kErrIsdir = 114,
  kErrNotdir = 115,
  kErrNotempty = 116,
  kErrInval = 117,
  kErrExist = 118,
  kErrUnexpected = 119,
  kErrExdev = 120,
};

inline int ClassifyErrno(int rc) {
  if (rc >= 0) {
    return kErrOk;
  }
  switch (errno) {
    case EROFS:
      return kErrRofs;
    case ENOENT:
      return kErrNoent;
    case EACCES:
      return kErrAcces;
    case EPERM:
      return kErrPerm;
    case EISDIR:
      return kErrIsdir;
    case ENOTDIR:
      return kErrNotdir;
    case ENOTEMPTY:
      return kErrNotempty;
    case EINVAL:
      return kErrInval;
    case EEXIST:
      return kErrExist;
    case EXDEV:
      return kErrExdev;
    default:
      return kErrUnexpected;
  }
}

// Enforces a policy handling handled_access and granting access1 beneath dir1
// and access2 beneath dir2. A zero access grants nothing for that directory.
inline void ApplyTwoDirPolicy(uint64_t handled_access, const std::string& dir1,
                              uint64_t access1, const std::string& dir2,
                              uint64_t access2) {
  int fd = CreateRuleset(handled_access);
  if (access1 != 0) {
    AddPathRule(fd, dir1, access1);
  }
  if (access2 != 0) {
    AddPathRule(fd, dir2, access2);
  }
  EnforceOrDie(fd);
}

#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif

inline int PivotRoot(const std::string& new_root, const std::string& put_old) {
  return syscall(SYS_pivot_root, new_root.c_str(), put_old.c_str());
}

inline int MoveMount(int from_dirfd, const std::string& from, int to_dirfd,
                     const std::string& to, uint32_t flags) {
  return syscall(SYS_move_mount, from_dirfd, from.c_str(), to_dirfd, to.c_str(),
                 flags);
}

// ForkTracee forks a process that optionally stacks a second Landlock layer on
// top of whatever it inherited, then blocks until *stop_fd is closed. It has
// returned only once the tracee is ready to be traced. Must be called from a
// forked test process: it exits the caller on failure.
inline pid_t ForkTracee(bool extra_layer, int* stop_fd) {
  int stop[2], ready[2];
  if (pipe(stop) != 0 || pipe(ready) != 0) {
    _exit(kSetup);
  }
  pid_t pid = fork();
  if (pid < 0) {
    _exit(kSetup);
  }
  if (pid == 0) {
    close(stop[1]);
    close(ready[0]);
    if (extra_layer) {
      EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG));
    }
    // Closing the write end reports readiness as EOF on the read end.
    close(ready[1]);
    char c;
    while (read(stop[0], &c, 1) == -1 && errno == EINTR) {
    }
    _exit(0);
  }
  close(stop[0]);
  close(ready[1]);
  char c;
  while (read(ready[0], &c, 1) == -1 && errno == EINTR) {
  }
  close(ready[0]);
  *stop_fd = stop[1];
  return pid;
}

// TryAttach attaches to tracee, detaches again if that succeeded, then reaps
// it.
inline ChildResult TryAttach(pid_t tracee, int stop_fd) {
  int rc = ptrace(PTRACE_ATTACH, tracee, nullptr, nullptr);
  int err = errno;
  if (rc == 0) {
    // PTRACE_ATTACH stops the tracee; wait for the stop before detaching.
    waitpid(tracee, nullptr, 0);
    ptrace(PTRACE_DETACH, tracee, nullptr, nullptr);
  }
  close(stop_fd);
  waitpid(tracee, nullptr, 0);
  if (rc == 0) {
    return kAllowed;
  }
  return err == EPERM ? kDenied : kOther;
}

inline sockaddr_in LoopbackAddr(uint16_t port) {
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  return addr;
}

inline socklen_t AbstractAddr(const std::string& name, sockaddr_un* addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  memcpy(&addr->sun_path[1], name.data(), name.size());
  return offsetof(sockaddr_un, sun_path) + 1 + name.size();
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_LANDLOCK_UTIL_H_
