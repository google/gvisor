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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// A host-backed FIFO exists before runsc applies the overlay, so in the
// overlay variant it is a lower-layer dentry that cannot be copied up.
TEST(CopyUpTest, LowerFIFOAccessForWriteFails) {
  const char* fifo_root = getenv("TEST_FIFO_TREE");
  ASSERT_NE(fifo_root, nullptr);

  const std::string path = JoinPath(fifo_root, "out");

  const struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Lstat(path));
  ASSERT_TRUE(S_ISFIFO(st.st_mode));

  // This test specifically exercises overlay copy-up behavior. Other generated
  // syscall-test variants don't have the relevant lower/upper relationship.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(path)));

  EXPECT_THAT(access(path.c_str(), W_OK), SyscallFailsWithErrno(EACCES));
}

TEST(CopyUpTest, LowerFIFOOpenForWriteFails) {
  const char* fifo_root = getenv("TEST_FIFO_TREE");
  ASSERT_NE(fifo_root, nullptr);

  // "out" has a host-side reader, so opening the FIFO for writing does not
  // block waiting for a reader.
  const std::string path = JoinPath(fifo_root, "out");

  const struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Lstat(path));
  ASSERT_TRUE(S_ISFIFO(st.st_mode));

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(path)));

  EXPECT_THAT(open(path.c_str(), O_WRONLY), SyscallFailsWithErrno(EPERM));
}

TEST(CopyUpTest, LowerSocketAccessForWriteFails) {
  const char* socket_root = getenv("TEST_UDS_TREE");
  ASSERT_NE(socket_root, nullptr);

  const std::string path = JoinPath(socket_root, "stream", "echo");

  const struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Lstat(path));
  ASSERT_TRUE(S_ISSOCK(st.st_mode));

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(path)));

  EXPECT_THAT(access(path.c_str(), W_OK), SyscallFailsWithErrno(EACCES));
}

TEST(CopyUpTest, LowerSocketOpenForWriteFails) {
  const char* socket_root = getenv("TEST_UDS_TREE");
  ASSERT_NE(socket_root, nullptr);

  const std::string path = JoinPath(socket_root, "stream", "echo");

  const struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Lstat(path));
  ASSERT_TRUE(S_ISSOCK(st.st_mode));

  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsOverlayfs(path)));

  EXPECT_THAT(open(path.c_str(), O_WRONLY),
              SyscallFailsWithErrno(EPERM));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
