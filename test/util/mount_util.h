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

#ifndef GVISOR_TEST_UTIL_MOUNT_UTIL_H_
#define GVISOR_TEST_UTIL_MOUNT_UTIL_H_

#include <errno.h>
#include <sys/mount.h>
#include <functional>
#include <string>

#include "gmock/gmock.h"
#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Mount mounts the filesystem, and unmounts when the returned reference is
// destroyed.
inline PosixErrorOr<Cleanup> Mount(const std::string &source,
                                   const std::string &target,
                                   const std::string &fstype, uint64_t mountflags,
                                   const std::string &data,
                                   uint64_t umountflags) {
  if (mount(source.c_str(), target.c_str(), fstype.c_str(), mountflags,
            data.c_str()) == -1) {
    return PosixError(errno, "mount failed");
  }
  return Cleanup([target, umountflags]() {
    EXPECT_THAT(umount2(target.c_str(), umountflags), SyscallSucceeds());
  });
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_MOUNT_UTIL_H_
