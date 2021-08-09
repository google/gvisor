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

#include "test/util/fuchsia_capability_util.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<bool> HaveCapability(int cap) {
  if (cap == CAP_NET_RAW) {
    auto s = Socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s.ok()) {
      return true;
    }
    if (s.error().errno_value() == EPERM) {
      return false;
    }
    return s.error();
  }

  return false;
}

}  // namespace testing
}  // namespace gvisor

#endif  // __Fuchsia__
