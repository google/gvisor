// Copyright 2021 The gVisor Authors.
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

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <linux/io_uring.h>

#include "gtest/gtest.h"
#include "test/util/memory_util.h"
#include "test/util/test_util.h"
#include "test/util/file_descriptor.h"

namespace gvisor {
namespace testing {

namespace {

int io_uring_enter(unsigned int fd, unsigned int to_submit, 
		   unsigned int min_complete, unsigned int flags,
                   sigset_t *sig)

{
    return (int) syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig);
}

TEST(IoUringSetupEnter, Exist) {
  int ret = io_uring_enter(0, 0, 0, 0, NULL);

  EXPECT_THAT(ret, SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
