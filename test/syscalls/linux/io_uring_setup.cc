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

int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return (int) syscall(__NR_io_uring_setup, entries, p);
}

TEST(IoUringSetupTest, Exist) {
  struct io_uring_params params = { 0 };
  const int nb_entries = 2;
  FileDescriptor fd = FileDescriptor(io_uring_setup(nb_entries, &params));

  EXPECT_THAT(fd.get(), SyscallSucceeds());
}

TEST(IoUringSetupTest, IsMappable) {
  struct io_uring_params params = { 0 };
  const int nb_entries = 2;
  FileDescriptor fd = FileDescriptor(io_uring_setup(nb_entries, &params));

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz =
      params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
  int sqring_sz = params.sq_entries * sizeof(struct io_uring_sqe);

  Mapping map_sring = ASSERT_NO_ERRNO_AND_VALUE(Mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd.get(), IORING_OFF_SQ_RING));
  EXPECT_THAT(map_sring.addr(), SyscallSucceeds());

  Mapping map_cring = ASSERT_NO_ERRNO_AND_VALUE(Mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
              fd.get(), IORING_OFF_CQ_RING));
  EXPECT_THAT(map_cring.addr(), SyscallSucceeds());

  Mapping map_sqring = ASSERT_NO_ERRNO_AND_VALUE(Mmap(0, sqring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
              fd.get(), IORING_OFF_SQES));
  EXPECT_THAT(map_sqring.addr(), SyscallSucceeds());
}

TEST(IoUringSetupTest, IsReadyForIoUringEnter) {

  struct io_uring_params params = { 0 };
  const int nb_entries = 2;
  FileDescriptor fd = FileDescriptor(io_uring_setup(nb_entries, &params));

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz =
      params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
  int sqring_sz = params.sq_entries * sizeof(struct io_uring_sqe);

  Mapping map_sring = ASSERT_NO_ERRNO_AND_VALUE(Mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd.get(), IORING_OFF_SQ_RING));
  Mapping map_cring = ASSERT_NO_ERRNO_AND_VALUE(Mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
              fd.get(), IORING_OFF_CQ_RING));
  Mapping map_sqring = ASSERT_NO_ERRNO_AND_VALUE(Mmap(0, sqring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
              fd.get(), IORING_OFF_SQES));

    unsigned int *sring_head = (unsigned int *)(map_sring.addr() + params.sq_off.head);
    unsigned int *sring_tail = (unsigned int *)(map_sring.addr() + params.sq_off.tail);
    unsigned int *sring_mask = (unsigned int *)(map_sring.addr() + params.sq_off.ring_mask);
    unsigned int *sring_array = (unsigned int *)(map_sring.addr() + params.sq_off.array);
    struct io_uring_sqe *sqes = (struct io_uring_sqe *)map_sqring.addr();

    unsigned int tail = *sring_tail;
    unsigned int index = tail & *sring_mask;
    struct io_uring_sqe *sqe = &sqes[index];

    /* Dummy value */
    sqe->fd = -1;
    sqe->flags = 0;
    sqe->opcode = IORING_OP_READV;
    sqe->addr = 0;
    sqe->len = 0;
    sqe->off = 0;
    sqe->user_data = 0;
    sring_array[index] = index;

    /* At this stage, io_uring_enter syscall is ready to be called */
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
