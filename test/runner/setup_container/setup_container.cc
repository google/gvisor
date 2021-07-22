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
#include <sys/ioctl.h>
#include <unistd.h>

#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

// SetupContainer sets up the networking settings in the current container.
PosixError SetupContainer() {
  const PosixErrorOr<bool> have_net_admin = HaveCapability(CAP_NET_ADMIN);
  if (!have_net_admin.ok()) {
    std::cerr << "Cannot determine if we have CAP_NET_ADMIN." << std::endl;
    return have_net_admin.error();
  }
  if (have_net_admin.ValueOrDie() && !IsRunningOnGvisor()) {
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
  }
  return NoError();
}

}  // namespace testing
}  // namespace gvisor

using ::gvisor::testing::SetupContainer;

// Binary setup_container initializes the container environment in which tests
// with container=True will run, then execs the actual test binary.
// Usage:
//   ./setup_container test_binary [arguments forwarded to test_binary...]
int main(int argc, char *argv[], char *envp[]) {
  if (!SetupContainer().ok()) {
    return 1;
  }
  if (argc < 2) {
    std::cerr << "Must provide arguments to exec." << std::endl;
    return 2;
  }
  if (execve(argv[1], &argv[1], envp) == -1) {
    std::cerr << "execv returned errno " << errno << std::endl;
    return 1;
  }
}
