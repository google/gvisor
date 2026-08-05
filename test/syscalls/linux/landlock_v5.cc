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

// Landlock syscall tests (ABI v5).

#include <asm/ioctls.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV5Test, IoctlDevDeniedWithoutRule) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 5);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_IOCTL_DEV, "/tmp",
                  LANDLOCK_ACCESS_FS_IOCTL_DEV);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      _exit(kSetup);
    }
    char buf[64] = {};
    int rc = ioctl(fd, TCGETS, buf);
    close(fd);
    _exit(rc < 0 && errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV5Test, IoctlDevAllowedWithRule) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 5);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_IOCTL_DEV, "/dev",
                  LANDLOCK_ACCESS_FS_IOCTL_DEV);
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      _exit(kSetup);
    }
    char buf[64] = {};
    int rc = ioctl(fd, TCGETS, buf);
    close(fd);
    _exit(rc < 0 && errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
