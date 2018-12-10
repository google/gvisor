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

#include <errno.h>
#include <syscall.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(FAdvise64Test, Basic) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  // fadvise64 is noop in gVisor, so just test that it succeeds.
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, POSIX_FADV_NORMAL),
              SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, POSIX_FADV_RANDOM),
              SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, POSIX_FADV_SEQUENTIAL),
              SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, POSIX_FADV_WILLNEED),
              SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, POSIX_FADV_DONTNEED),
              SyscallSucceeds());
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, POSIX_FADV_NOREUSE),
              SyscallSucceeds());
}

TEST(FAdvise64Test, InvalidArgs) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  // Note: offset is allowed to be negative.
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, static_cast<off_t>(-1),
                      POSIX_FADV_NORMAL),
              SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(syscall(__NR_fadvise64, fd.get(), 0, 10, 12345),
              SyscallFailsWithErrno(EINVAL));
}

TEST(FAdvise64Test, NoPipes) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  const FileDescriptor read(fds[0]);
  const FileDescriptor write(fds[1]);

  ASSERT_THAT(syscall(__NR_fadvise64, read.get(), 0, 10, POSIX_FADV_NORMAL),
              SyscallFailsWithErrno(ESPIPE));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
