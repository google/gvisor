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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_IPTABLES_UTIL_H_
#define GVISOR_TEST_SYSCALLS_LINUX_IPTABLES_UTIL_H_

#include <vector>

namespace gvisor {
namespace testing {

// Creates an iptables (IPv4) replace payload for the "filter" table where a
// built-in hook entry point (LOCAL_IN) points directly to a user-defined chain
// header (an XT_ERROR_TARGET whose errorname is "my_chain"), which gVisor
// unmarshals as a UserChainTarget.
std::vector<char> MakeUserChainTargetReplacePayload4();

// Creates an ip6tables (IPv6) replace payload for the "filter" table where a
// built-in hook entry point (LOCAL_IN) points directly to a user-defined chain
// header (an XT_ERROR_TARGET whose errorname is "my_chain"), which gVisor
// unmarshals as a UserChainTarget.
std::vector<char> MakeUserChainTargetReplacePayload6();

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_IPTABLES_UTIL_H_
