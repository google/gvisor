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

// Utilities for testing capabilities.

#ifndef GVISOR_TEST_UTIL_CAPABILITY_UTIL_H_
#define GVISOR_TEST_UTIL_CAPABILITY_UTIL_H_

#ifdef __linux__

#include <errno.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

#ifndef _LINUX_CAPABILITY_VERSION_3
#error Expecting _LINUX_CAPABILITY_VERSION_3 support
#endif

namespace gvisor {
namespace testing {

// HaveCapability returns true if the process has the specified EFFECTIVE
// capability.
inline PosixErrorOr<bool> HaveCapability(int cap) {
  if (!cap_valid(cap)) {
    return PosixError(EINVAL, "Invalid capability");
  }

  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
  RETURN_ERROR_IF_SYSCALL_FAIL(syscall(__NR_capget, &header, &caps));
  MaybeSave();

  return (caps[CAP_TO_INDEX(cap)].effective & CAP_TO_MASK(cap)) != 0;
}

// SetCapability sets the specified EFFECTIVE capability.
inline PosixError SetCapability(int cap, bool set) {
  if (!cap_valid(cap)) {
    return PosixError(EINVAL, "Invalid capability");
  }

  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
  RETURN_ERROR_IF_SYSCALL_FAIL(syscall(__NR_capget, &header, &caps));
  MaybeSave();

  if (set) {
    caps[CAP_TO_INDEX(cap)].effective |= CAP_TO_MASK(cap);
  } else {
    caps[CAP_TO_INDEX(cap)].effective &= ~CAP_TO_MASK(cap);
  }
  header = {_LINUX_CAPABILITY_VERSION_3, 0};
  RETURN_ERROR_IF_SYSCALL_FAIL(syscall(__NR_capset, &header, &caps));
  MaybeSave();

  return NoError();
}

// DropPermittedCapability drops the specified PERMITTED. The EFFECTIVE
// capabilities must be a subset of PERMITTED, so those are dropped as well.
inline PosixError DropPermittedCapability(int cap) {
  if (!cap_valid(cap)) {
    return PosixError(EINVAL, "Invalid capability");
  }

  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
  RETURN_ERROR_IF_SYSCALL_FAIL(syscall(__NR_capget, &header, &caps));
  MaybeSave();

  caps[CAP_TO_INDEX(cap)].effective &= ~CAP_TO_MASK(cap);
  caps[CAP_TO_INDEX(cap)].permitted &= ~CAP_TO_MASK(cap);

  header = {_LINUX_CAPABILITY_VERSION_3, 0};
  RETURN_ERROR_IF_SYSCALL_FAIL(syscall(__NR_capset, &header, &caps));
  MaybeSave();

  return NoError();
}

PosixErrorOr<bool> CanCreateUserNamespace();

class AutoCapability {
 public:
  AutoCapability(int cap, bool set) : cap_(cap), set_(set) {
    const bool has = EXPECT_NO_ERRNO_AND_VALUE(HaveCapability(cap));
    if (set != has) {
      EXPECT_NO_ERRNO(SetCapability(cap_, set_));
      applied_ = true;
    }
  }

  ~AutoCapability() {
    if (applied_) {
      EXPECT_NO_ERRNO(SetCapability(cap_, !set_));
    }
  }

 private:
  int cap_;
  bool set_;
  bool applied_ = false;
};

}  // namespace testing
}  // namespace gvisor

#endif  // __linux__

#endif  // GVISOR_TEST_UTIL_CAPABILITY_UTIL_H_
