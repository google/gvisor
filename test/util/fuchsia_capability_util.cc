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

#ifdef __Fuchsia__

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

// On Linux, access to raw IP and packet socket is controlled by a single
// capability (CAP_NET_RAW). However on Fuchsia, access to raw IP and packet
// sockets are controlled by separate capabilities/protocols.

namespace {

PosixErrorOr<bool> HaveSocketCapability(int domain, int type, int protocol) {
  // Fuchsia does not have a platform supported way to check the protocols made
  // available to a sandbox. As a workaround, simply try to create the specified
  // socket and assume no access if we get a no permissions error.
  auto s = Socket(domain, type, protocol);
  if (s.ok()) {
    return true;
  }
  if (s.error().errno_value() == EPERM) {
    return false;
  }
  return s.error();
}

}  // namespace

PosixErrorOr<bool> HaveRawIPSocketCapability() {
  static PosixErrorOr<bool> result(false);
  static std::once_flag once;

  std::call_once(once, [&]() {
    result = HaveSocketCapability(AF_INET, SOCK_RAW, IPPROTO_UDP);
  });

  return result;
}

PosixErrorOr<bool> HavePacketSocketCapability() {
  static PosixErrorOr<bool> result(false);
  static std::once_flag once;

  std::call_once(once, [&]() {
    result = HaveSocketCapability(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  });

  return result;
}

}  // namespace testing
}  // namespace gvisor

#endif  // __Fuchsia__
