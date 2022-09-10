// Copyright 2022 The gVisor Authors.
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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/io_uring_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(IoUringTest, ValidFD) {
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIoUringFD(1));
}

TEST(IoUringTest, SetUp) {
  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  ASSERT_THAT(IoUringSetup(1, &params), SyscallSucceeds());
}

TEST(IoUringTest, ParamsNonZeroResv) {
  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  params.resv[1] = 1;
  ASSERT_THAT(IoUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
