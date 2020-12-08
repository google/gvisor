// Copyright 2020 The gVisor Authors.
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

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "gtest/gtest.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(FuseMount, FDNotParsable) {
  int devfd;
  EXPECT_THAT(devfd = open("/dev/fuse", O_RDWR), SyscallSucceeds());
  std::string mount_opts = "fd=thiscantbeparsed";
  TempPath mount_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("fuse", mount_dir.path().c_str(), "fuse",
                    MS_NODEV | MS_NOSUID, mount_opts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
