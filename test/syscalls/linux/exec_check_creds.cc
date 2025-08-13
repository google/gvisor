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

#include <sys/prctl.h>
#include <unistd.h>

#include <iostream>

#include "absl/strings/numbers.h"

int main(int argc, char** argv, char** envp) {
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0]
              << " <want_euid> <want_egid> <want_dumpability>" << std::endl;
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
  return 0;
}
