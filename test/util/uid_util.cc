// Copyright 2018 The gVisor Authors.
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

#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<bool> IsRoot() {
  uid_t ruid, euid, suid;
  int rc = getresuid(&ruid, &euid, &suid);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "getresuid");
  }
  if (ruid != 0 || euid != 0 || suid != 0) {
    return false;
  }
  gid_t rgid, egid, sgid;
  rc = getresgid(&rgid, &egid, &sgid);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "getresgid");
  }
  if (rgid != 0 || egid != 0 || sgid != 0) {
    return false;
  }
  return true;
}

}  // namespace testing
}  // namespace gvisor
