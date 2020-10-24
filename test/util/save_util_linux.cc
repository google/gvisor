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

#ifdef __linux__

#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test/util/save_util.h"

#if defined(__x86_64__) || defined(__i386__)
#define SYS_TRIGGER_SAVE SYS_create_module
#elif defined(__aarch64__)
#define SYS_TRIGGER_SAVE SYS_finit_module
#else
#error "Unknown architecture"
#endif

namespace gvisor {
namespace testing {
namespace internal {

void DoCooperativeSave() {
  int orig_errno = errno;
  // We use it to trigger saving the sentry state
  // when this syscall is called.
  // Notice: this needs to be a valid syscall
  // that is not used in any of the syscall tests.
  syscall(SYS_TRIGGER_SAVE, nullptr, 0);
  errno = orig_errno;
}

}  // namespace internal
}  // namespace testing
}  // namespace gvisor

#endif  // __linux__
