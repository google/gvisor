// Copyright 2019 The gVisor Authors.
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

#ifndef GVISOR_TEST_SYSCALLS_SOCKET_BIND_TO_DEVICE_UTILS_H_
#define GVISOR_TEST_SYSCALLS_SOCKET_BIND_TO_DEVICE_UTILS_H_

#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

class Tunnel {
 public:
  static PosixErrorOr<std::unique_ptr<Tunnel>> New(
      std::string tunnel_name = "");
  const std::string& GetName() const { return name_; }

  ~Tunnel() {
    if (fd_ != -1) {
      close(fd_);
    }
  }

 private:
  Tunnel(int fd) : fd_(fd) {}
  int fd_ = -1;
  std::string name_;
};

std::unordered_set<std::string> GetInterfaceNames();

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_SOCKET_BIND_TO_DEVICE_UTILS_H_
