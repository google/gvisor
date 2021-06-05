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
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <linux/io_uring.h>

#include "gtest/gtest.h"

namespace gvisor {
namespace testing {

namespace {

int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return (int) syscall(__NR_io_uring_setup, entries, p);
}

TEST(IoUringSetupTest, Exist) {
  struct io_uring_params params;
  const int nb_entries = 2;
  io_uring_setup(nb_entries, &params);

  ASSERT_NE(errno, ENOSYS);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
