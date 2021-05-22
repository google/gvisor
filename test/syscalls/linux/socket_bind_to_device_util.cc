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

#include "test/syscalls/linux/socket_bind_to_device_util.h"

#include <arpa/inet.h>
#include <fcntl.h>
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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

using std::string;

PosixErrorOr<std::unique_ptr<Tunnel>> Tunnel::New(string tunnel_name) {
  int fd;
  RETURN_ERROR_IF_SYSCALL_FAIL(fd = open("/dev/net/tun", O_RDWR));

  // Using `new` to access a non-public constructor.
  auto new_tunnel = absl::WrapUnique(new Tunnel(fd));

  ifreq ifr = {};
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, tunnel_name.c_str(), sizeof(ifr.ifr_name));

  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(fd, TUNSETIFF, &ifr));
  new_tunnel->name_ = ifr.ifr_name;
  return new_tunnel;
}

std::unordered_set<string> GetInterfaceNames() {
  std::unordered_set<string> names;
#ifndef ANDROID
  // Android does not support if_nameindex in r22.
  struct if_nameindex* interfaces = if_nameindex();
  if (interfaces == nullptr) {
    return names;
  }
  for (auto interface = interfaces;
       interface->if_index != 0 || interface->if_name != nullptr; interface++) {
    names.insert(interface->if_name);
  }
  if_freenameindex(interfaces);
#endif
  return names;
}

}  // namespace testing
}  // namespace gvisor
