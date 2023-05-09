// Copyright 2023 The gVisor Authors.
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

#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(FuseTest, RejectBadInit) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR, 0));

  auto mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", fd.get());

  EXPECT_THAT(mount("fuse", mount_point.path().c_str(), "fuse",
                    MS_NODEV | MS_NOSUID, mount_opts.c_str()),
              SyscallSucceeds());
  mount_point.release();

  struct response {
    uint32_t len;
    int32_t err;
    uint64_t uid;
  } resp;
  // min value for length is 24 + sizeof(response)
  resp.len = 24 + sizeof(resp) - 1;
  resp.err = 0;
  resp.uid = 2;

  ASSERT_THAT(write(fd.get(), reinterpret_cast<char*>(&resp), sizeof(resp)),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
