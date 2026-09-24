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
