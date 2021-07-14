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

TEST(IoUringSetupTest, ReturnsFd) {
  struct io_uring_params params = { 0 };
  const int nb_entries = 2;
  int fd = io_uring_setup(nb_entries, &params);

  ASSERT_NE(fd , -1);
}

TEST(IoUringSetupTest, IsMappable) {
  struct io_uring_params params = { 0 };
  const int nb_entries = 2;
  int fd = io_uring_setup(nb_entries, &params);

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz =
      params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
  int sqring_sz = params.sq_entries * sizeof(struct io_uring_sqe);

  void *addr = mmap(0, sring_sz, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
  ASSERT_NE(addr , MAP_FAILED);

  addr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
              fd, IORING_OFF_CQ_RING);
  ASSERT_NE(addr , MAP_FAILED);

  addr = mmap(0, sqring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
              fd, IORING_OFF_SQES);
  ASSERT_NE(addr , MAP_FAILED);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
