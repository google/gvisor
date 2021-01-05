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
#include "test/util/mount_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(FuseMount, Success) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_WRONLY));
  std::string mopts = absl::StrCat("fd=", std::to_string(fd.get()));

  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  const auto mount =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("", dir.path(), "fuse", 0, mopts, 0));
}

TEST(FuseMount, FDNotParsable) {
  int devfd;
  EXPECT_THAT(devfd = open("/dev/fuse", O_RDWR), SyscallSucceeds());
  std::string mount_opts = "fd=thiscantbeparsed";
  TempPath mount_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  EXPECT_THAT(mount("fuse", mount_dir.path().c_str(), "fuse",
                    MS_NODEV | MS_NOSUID, mount_opts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseMount, NoDevice) {
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), "fuse", 0, ""),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseMount, ClosedFD) {
  FileDescriptor f = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_WRONLY));
  int fd = f.release();
  close(fd);
  std::string mopts = absl::StrCat("fd=", std::to_string(fd));

  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  EXPECT_THAT(mount("", dir.path().c_str(), "fuse", 0, mopts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FuseMount, BadFD) {
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  std::string mopts = absl::StrCat("fd=", std::to_string(fd.get()));

  EXPECT_THAT(mount("", dir.path().c_str(), "fuse", 0, mopts.c_str()),
              SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
