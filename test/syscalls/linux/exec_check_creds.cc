// Copyright 2025 The gVisor Authors.
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
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>

#include "absl/strings/numbers.h"

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_IS_SET 1
#endif

namespace {

bool GetCaps(uint64_t* permitted, uint64_t* effective, uint64_t* ambient) {
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
  if (syscall(SYS_capget, &header, &caps) < 0) {
    return false;
  }
  *permitted =
      (static_cast<uint64_t>(caps[1].permitted) << 32) | caps[0].permitted;
  *effective =
      (static_cast<uint64_t>(caps[1].effective) << 32) | caps[0].effective;
  *ambient = 0;
  for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
    int ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
    if (ret < 0) {
      return false;
    }
    if (ret == 1) {
      *ambient |= 1ULL << cap;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char** argv, char** envp) {
  if (argc != 4 && argc != 7) {
    std::cerr << "Usage: " << argv[0]
              << " <want_euid> <want_egid> <want_dumpability>"
              << " [<want_permitted> <want_effective> <want_ambient>]"
              << std::endl;
    return 1;
  }
  uint want_euid;
  if (!absl::SimpleAtoi(argv[1], &want_euid)) {
    std::cerr << "want_euid is not an integer: " << argv[1] << std::endl;
    return 1;
  }
  uint want_egid;
  if (!absl::SimpleAtoi(argv[2], &want_egid)) {
    std::cerr << "want_egid is not an integer: " << argv[2] << std::endl;
    return 1;
  }
  int want_dumpability;
  if (!absl::SimpleAtoi(argv[3], &want_dumpability)) {
    std::cerr << "want_dumpability is not an integer: " << argv[3] << std::endl;
    return 1;
  }
  if (geteuid() != want_euid) {
    return 2;
  }
  if (getegid() != want_egid) {
    return 3;
  }
  if (prctl(PR_GET_DUMPABLE) != want_dumpability) {
    return 4;
  }
  if (argc == 4) {
    return 0;
  }

  // Capability sets are given and reported in hex, like /proc/[pid]/status.
  uint64_t want_permitted, want_effective, want_ambient;
  if (!absl::SimpleHexAtoi(argv[4], &want_permitted) ||
      !absl::SimpleHexAtoi(argv[5], &want_effective) ||
      !absl::SimpleHexAtoi(argv[6], &want_ambient)) {
    std::cerr << "capability sets must be hex integers" << std::endl;
    return 1;
  }
  uint64_t permitted, effective, ambient;
  if (!GetCaps(&permitted, &effective, &ambient)) {
    std::cerr << "failed to read capability sets" << std::endl;
    return 1;
  }
  if (permitted != want_permitted) {
    std::cerr << std::hex << "permitted: got " << permitted << ", want "
              << want_permitted << std::endl;
    return 5;
  }
  if (effective != want_effective) {
    std::cerr << std::hex << "effective: got " << effective << ", want "
              << want_effective << std::endl;
    return 6;
  }
  if (ambient != want_ambient) {
    std::cerr << std::hex << "ambient: got " << ambient << ", want "
              << want_ambient << std::endl;
    return 7;
  }
  return 0;
}
