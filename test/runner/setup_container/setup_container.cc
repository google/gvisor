// Copyright 2021 The gVisor Authors.
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

#include <linux/capability.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <ostream>

#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

// EnableAtime preserves the test's host filesystem while providing the atime
// semantics needed by timestamp tests. This must run before creating a user
// namespace, which locks inherited noatime flags.
PosixError EnableAtime() {
  const char* tmpdir = getenv("TEST_TMPDIR");
  if (tmpdir == nullptr || *tmpdir == '\0') {
    return PosixError(EINVAL, "--require-atime requires TEST_TMPDIR");
  }
  struct statvfs fs = {};
  if (statvfs(tmpdir, &fs) == -1) {
    return PosixError(errno, "statvfs TEST_TMPDIR");
  }
  if ((fs.f_flag & (ST_NOATIME | ST_NODIRATIME)) == 0) {
    return NoError();
  }

  // Own the mount namespace and prevent propagation to the test executor.
  // Creating only a mount namespace retains the caller's mount capabilities.
  if (unshare(CLONE_NEWNS) == -1) {
    return PosixError(errno,
                      "atime setup requires CAP_SYS_ADMIN for CLONE_NEWNS");
  }
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1) {
    return PosixError(errno, "make atime setup mounts private");
  }
  if (mount(tmpdir, tmpdir, nullptr, MS_BIND, nullptr) == -1) {
    return PosixError(errno, "bind TEST_TMPDIR for atime updates");
  }

  // Bind-remount changes only this mount, not the underlying superblock. Keep
  // its security flags, and preserve strictatime if only nodiratime was set.
  unsigned long flags = MS_BIND | MS_REMOUNT;
  if (fs.f_flag & ST_RDONLY) flags |= MS_RDONLY;
  if (fs.f_flag & ST_NOSUID) flags |= MS_NOSUID;
  if (fs.f_flag & ST_NODEV) flags |= MS_NODEV;
  if (fs.f_flag & ST_NOEXEC) flags |= MS_NOEXEC;
  // Linux reports ST_NOSYMFOLLOW even when libc predates the named constant.
  // The statvfs conversion preserves the kernel's f_flags bits.
  // https://github.com/torvalds/linux/blob/830b3c68c/include/linux/statfs.h#L44
  // https://github.com/torvalds/linux/blob/830b3c68c/include/uapi/linux/mount.h#L21
  // https://github.com/bminor/glibc/blob/3c03baca3/sysdeps/unix/sysv/linux/internal_statvfs.c#L86
  constexpr unsigned long kSTNosymfollow = 0x2000;
  constexpr unsigned long kMSNosymfollow = 0x100;
  if (fs.f_flag & kSTNosymfollow) flags |= kMSNosymfollow;
  flags |=
      (fs.f_flag & (ST_NOATIME | ST_RELATIME)) ? MS_RELATIME : MS_STRICTATIME;
  if (mount(nullptr, tmpdir, nullptr, flags, nullptr) == -1) {
    return PosixError(
        errno, "enable TEST_TMPDIR atime (inherited flags may be locked)");
  }
  return NoError();
}

// SetupContainer sets up the networking settings in the current container.
PosixError SetupContainer() {
  const PosixErrorOr<bool> have_net_admin = HaveCapability(CAP_NET_ADMIN);
  if (!have_net_admin.ok()) {
    std::cerr << "Cannot determine if we have CAP_NET_ADMIN." << std::endl;
    return have_net_admin.error();
  }
  if (have_net_admin.ValueOrDie()) {
    PosixErrorOr<FileDescriptor> sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
    if (!sockfd.ok()) {
      std::cerr << "Cannot open socket." << std::endl;
      return sockfd.error();
    }
    int sock = sockfd.ValueOrDie().get();
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
      std::cerr << "Cannot get 'lo' flags: " << strerror(errno) << std::endl;
      return PosixError(errno);
    }
    if ((ifr.ifr_flags & IFF_UP) == 0) {
      ifr.ifr_flags |= IFF_UP;
      if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        std::cerr << "Cannot set 'lo' as UP: " << strerror(errno) << std::endl;
        return PosixError(errno);
      }
    }
  } else {
    std::cerr
        << "Capability CAP_NET_ADMIN not granted, so cannot bring up "
        << "'lo' interface. This may cause host-network-related tests to fail."
        << std::endl;
  }
  return NoError();
}

}  // namespace testing
}  // namespace gvisor

using ::gvisor::testing::EnableAtime;
using ::gvisor::testing::SetupContainer;

// Binary setup_container initializes a test container, or prepares host atime
// semantics before the runner creates containers, then execs the given binary.
// Usage:
//   ./setup_container test_binary [arguments forwarded to test_binary...]
//   ./setup_container --require-atime runner [arguments forwarded to runner...]
int main(int argc, char* argv[], char* envp[]) {
  if (argc < 2) {
    std::cerr << "Must provide arguments to exec." << std::endl;
    return 2;
  }
  int command = 1;
  if (strcmp(argv[1], "--require-atime") == 0) {
    if (argc < 3) {
      std::cerr << "Must provide arguments to exec." << std::endl;
      return 2;
    }
    auto err = EnableAtime();
    if (!err.ok()) {
      std::cerr << "Cannot prepare test atime: " << err << std::endl;
      return 1;
    }
    command = 2;
  } else if (!SetupContainer().ok()) {
    return 1;
  }
  if (execve(argv[command], &argv[command], envp) == -1) {
    std::cerr << "execv returned errno " << errno << std::endl;
    return 1;
  }
}
