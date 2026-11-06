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

#include "tools/ioctl_sniffer/ioctl_hook.h"

#include <dlfcn.h>

#include <cerrno>

#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(IoctlHookTest, PreservesErrnoOnInvalidDescriptor) {
  void* handle =
      dlopen(RunfilePath("tools/ioctl_sniffer/libioctl_hook.so").c_str(),
             RTLD_NOW | RTLD_LOCAL);
  ASSERT_NE(handle, nullptr) << dlerror();
  const Cleanup close_hook([handle] { dlclose(handle); });
  auto hooked_ioctl = reinterpret_cast<libc_ioctl>(dlsym(handle, "ioctl"));
  ASSERT_NE(hooked_ioctl, nullptr) << dlerror();

  // The real ioctl fails with EBADF. The hook's subsequent readlink on
  // /proc/self/fd/-1 fails with ENOENT, which must not replace that errno.
  errno = 0;
  const int result = hooked_ioctl(-1, 0, nullptr);
  const int result_errno = errno;
  EXPECT_EQ(result, -1);
  EXPECT_EQ(result_errno, EBADF);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
