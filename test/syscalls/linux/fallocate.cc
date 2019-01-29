// Copyright 2018 Google LLC
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
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// These tests are very rudimentary because fallocate is not
// implemented.  We just want to make sure the expected error codes are
// returned.

TEST(FallocateTest, NotImplemented) {
  auto temp_path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(temp_path.path(), O_RDWR));

  // Test that a completely unassigned fallocate mode returns EOPNOTSUPP.
  ASSERT_THAT(fallocate(fd.get(), 0x80, 0, 32768),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

TEST(FallocateTest, BadOffset) {
  auto temp_path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(temp_path.path(), O_RDWR));
  ASSERT_THAT(fallocate(fd.get(), 0, -1, 32768), SyscallFailsWithErrno(EINVAL));
}

TEST(FallocateTest, BadLength) {
  auto temp_path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(temp_path.path(), O_RDWR));
  ASSERT_THAT(fallocate(fd.get(), 0, 0, -1), SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
