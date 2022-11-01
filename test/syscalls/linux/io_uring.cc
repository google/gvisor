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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "gtest/gtest.h"
#include "test/util/io_uring_util.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Testing that io_uring_setup(2) successfully returns a valid file descriptor.
TEST(IOUringTest, ValidFD) {
  IOUringParams params;
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));
}

// Testing that io_uring_setup(2) fails with EINVAL on non-zero params.
TEST(IOUringTest, ParamsNonZeroResv) {
  IOUringParams params;
  memset(&params, 0, sizeof(params));
  params.resv[1] = 1;
  ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

TEST(IOUringTest, ZeroCQEntries) {
  IOUringParams params;
  params.cq_entries = 0;
  params.flags = IORING_SETUP_CQSIZE;
  ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

TEST(IOUringTest, ZeroCQEntriesLessThanSQEntries) {
  IOUringParams params;
  params.cq_entries = 16;
  params.flags = IORING_SETUP_CQSIZE;
  ASSERT_THAT(IOUringSetup(32, &params), SyscallFailsWithErrno(EINVAL));
}

// Testing that io_uring_setup(2) fails with EINVAL on unsupported flags.
TEST(IOUringTest, UnsupportedFlags) {
  if (IsRunningOnGvisor()) {
    IOUringParams params;
    memset(&params, 0, sizeof(params));
    params.flags |= IORING_SETUP_SQPOLL;
    ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
  }
}

// Testing that both mmap and munmap calls succeed and subsequent access to
// unmapped memory results in SIGSEGV.
TEST(IOUringTest, MMapMUnMapWork) {
  IOUringParams params;
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  void *ptr = nullptr;
  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);

  ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
             iouringfd.get(), IORING_OFF_SQ_RING);

  EXPECT_NE(ptr, MAP_FAILED);

  const auto rest = [&] {
    // N.B. we must be in a single-threaded subprocess to ensure that another
    // thread doesn't racily remap at ptr.
    TEST_PCHECK_MSG(MunmapSafe(ptr, sring_sz) == 0, "munmap failed");
    // This should SIGSEGV.
    *reinterpret_cast<volatile int *>(ptr) = 42;
  };

  int child_exit_status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess(rest));
  EXPECT_TRUE(WIFSIGNALED(child_exit_status) &&
              WTERMSIG(child_exit_status) == SIGSEGV)
      << "exit status: " << child_exit_status;
}

// Testing that both mmap fails with EINVAL when an invalid offset is passed.
TEST(IOUringTest, MMapWrongOffset) {
  IOUringParams params;
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);

  EXPECT_THAT(reinterpret_cast<uintptr_t>(
                  mmap(0, sring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, iouringfd.get(), 66)),
              SyscallFailsWithErrno(EINVAL));
}

// Testing that mmap() handles all three IO_URING-specific offsets and that
// returned addresses are page aligned.
TEST(IOUringTest, MMapOffsets) {
  IOUringParams params;
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  void *sq_ptr = nullptr;
  void *cq_ptr = nullptr;
  void *sqe_ptr = nullptr;

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz = params.cq_off.cqes + params.cq_entries * sizeof(IOUringCqe);

  sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                iouringfd.get(), IORING_OFF_SQ_RING);

  cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                iouringfd.get(), IORING_OFF_CQ_RING);

  sqe_ptr = mmap(0, sizeof(IOUringSqe), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, iouringfd.get(), IORING_OFF_SQES);

  EXPECT_NE(sq_ptr, MAP_FAILED);
  EXPECT_NE(cq_ptr, MAP_FAILED);
  EXPECT_NE(sqe_ptr, MAP_FAILED);

  EXPECT_EQ(reinterpret_cast<uintptr_t>(sq_ptr) % kPageSize, 0);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(cq_ptr) % kPageSize, 0);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(sqe_ptr) % kPageSize, 0);

  ASSERT_THAT(munmap(sq_ptr, sring_sz), SyscallSucceeds());
  ASSERT_THAT(munmap(cq_ptr, cring_sz), SyscallSucceeds());
  ASSERT_THAT(munmap(sqe_ptr, sizeof(IOUringSqe)), SyscallSucceeds());
}

// Testing that IOUringParams are populated with correct values.
TEST(IOUringTest, ReturnedParamsValues) {
  if (IsRunningOnGvisor()) {
    IOUringParams params;
    FileDescriptor iouringfd =
        ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

    EXPECT_EQ(params.sq_entries, 1);
    EXPECT_EQ(params.cq_entries, 2);

    EXPECT_EQ(params.sq_off.head, 0);
    EXPECT_EQ(params.sq_off.tail, 64);
    EXPECT_EQ(params.sq_off.ring_mask, 256);
    EXPECT_EQ(params.sq_off.ring_entries, 264);
    EXPECT_EQ(params.sq_off.flags, 276);
    EXPECT_EQ(params.sq_off.dropped, 272);
    EXPECT_EQ(params.sq_off.array, 384);

    EXPECT_EQ(params.cq_off.head, 128);
    EXPECT_EQ(params.cq_off.tail, 192);
    EXPECT_EQ(params.cq_off.ring_mask, 260);
    EXPECT_EQ(params.cq_off.ring_entries, 268);
    EXPECT_EQ(params.cq_off.overflow, 284);
    EXPECT_EQ(params.cq_off.cqes, 320);
    EXPECT_EQ(params.cq_off.flags, 280);

    // gVisor should support IORING_FEAT_SINGLE_MMAP.
    EXPECT_NE((params.features & IORING_FEAT_SINGLE_MMAP), 0);
  }
}

// Testing that offset of SQE indices array is cacheline aligned.
TEST(IOUringTest, SqeIndexArrayCacheAligned) {
  IOUringParams params;
  for (uint32_t i = 1; i < 10; ++i) {
    FileDescriptor iouringfd =
        ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(i, params));
    ASSERT_EQ(params.sq_off.array % 64, 0);
  }
}

// Testing that io_uring_enter(2) successfully handles a single NOP operation.
TEST(IOUringTest, SingleNOPTest) {
  IOUringParams params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  IOUringSqe *sqe = io_uring->get_sqes();
  sqe->opcode = IORING_OP_NOP;
  sqe->user_data = 42;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  IOUringCqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->user_data, 42);
  ASSERT_EQ(cqe->res, 0);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully queueing NOP operations.
TEST(IOUringTest, QueueingNOPTest) {
  IOUringParams params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned *sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe *sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 4; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  ASSERT_EQ(sq_tail, 0);
  io_uring->store_sq_tail(sq_tail + 4);

  int ret = io_uring->Enter(2, 2, 0, nullptr);
  ASSERT_EQ(ret, 2);

  IOUringCqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 2);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 2);

  for (size_t i = 0; i < 2; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 2);

  ret = io_uring->Enter(2, 2, 0, nullptr);
  ASSERT_EQ(ret, 2);

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 4);

  cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 4);

  for (size_t i = 2; i < 4; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 2);
}

// Testing that io_uring_enter(2) successfully multiple NOP operations.
TEST(IOUringTest, MultipleNOPTest) {
  IOUringParams params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned *sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe *sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 3; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  ASSERT_EQ(sq_tail, 0);
  io_uring->store_sq_tail(sq_tail + 3);

  int ret = io_uring->Enter(3, 3, 0, nullptr);
  ASSERT_EQ(ret, 3);

  IOUringCqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 3);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 3);

  for (size_t i = 0; i < 3; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 3);
}

// Testing that io_uring_enter(2) successfully handles multiple threads
// submitting NOP operations.
TEST(IOUringTest, MultiThreadedNOPTest) {
  IOUringParams params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned *sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe *sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 4; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 4);

  for (int i = 0; i < 4; i++) {
    ScopedThread t([&] {
      IOUring *io_uring_ptr = io_uring.get();
      int ret = io_uring_ptr->Enter(1, 1, 0, nullptr);
      ASSERT_EQ(ret, 1);
    });
  }

  IOUringCqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 4);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 4);

  for (size_t i = 0; i < 4; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 4);
}

// Testing that io_uring_enter(2) successfully consumes submission with an
// invalid opcode and returned CQE contains EINVAL in its result field.
TEST(IOUringTest, InvalidOpCodeTest) {
  IOUringParams params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  IOUringSqe *sqe = io_uring->get_sqes();
  sqe->opcode = 255;  // maximum value for one-byte unsigned integer
  sqe->user_data = 42;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  IOUringCqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->user_data, 42);
  ASSERT_EQ(cqe->res, -EINVAL);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully consumes submission and SQE ring
// buffers wrap around.
TEST(IOUringTest, SQERingBuffersWrapAroundTest) {
  IOUringParams params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned *sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe *sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 4; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 4);

  int ret = io_uring->Enter(4, 4, 0, nullptr);
  ASSERT_EQ(ret, 4);

  IOUringCqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 4);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 4);

  for (size_t i = 0; i < 4; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 4);

  for (size_t i = 0; i < 4; ++i) {
    sqe[i].user_data = 42 + 2 * (i + 1);
  }

  sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 4);

  ret = io_uring->Enter(4, 4, 0, nullptr);
  ASSERT_EQ(ret, 4);

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 8);

  cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 8);

  for (size_t i = 0; i < 4; ++i) {
    ASSERT_EQ(cqe[4 + i].res, 0);
    ASSERT_EQ(cqe[4 + i].user_data, 42 + 2 * (i + 1));
  }

  cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 4);
}

// Testing that io_uring_enter(2) fails with EFAULT when non-null sigset_t has
// been passed as we currently don't support replacing signal mask.
TEST(IOUringTest, NonNullSigsetTest) {
  if (IsRunningOnGvisor()) {
    IOUringParams params;
    std::unique_ptr<IOUring> io_uring =
        ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

    uint32_t sq_head = io_uring->load_sq_head();
    ASSERT_EQ(sq_head, 0);

    IOUringSqe *sqe = io_uring->get_sqes();
    sqe->opcode = IORING_OP_NOP;
    sqe->user_data = 42;

    uint32_t sq_tail = io_uring->load_sq_tail();
    io_uring->store_sq_tail(sq_tail + 1);

    sigset_t non_null_sigset;
    EXPECT_THAT(io_uring->Enter(1, 1, 0, &non_null_sigset),
                SyscallFailsWithErrno(EFAULT));
  }
}

// Testing that completion queue overflow counter is incremented when the
// completion queue is not drained by the user and completion queue entries are
// not overwritten.
TEST(IOUringTest, OverflowCQTest) {
  if (IsRunningOnGvisor()) {
    IOUringParams params;
    std::unique_ptr<IOUring> io_uring =
        ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

    uint32_t sq_head = io_uring->load_sq_head();
    ASSERT_EQ(sq_head, 0);

    unsigned *sq_array = io_uring->get_sq_array();
    unsigned index = 0;
    IOUringSqe *sqe = io_uring->get_sqes();
    IOUringCqe *cqe = io_uring->get_cqes();

    for (size_t submission_round = 0; submission_round < 2;
         ++submission_round) {
      for (size_t i = 0; i < 4; ++i) {
        sqe[i].opcode = IORING_OP_NOP;
        sqe[i].user_data = 42 + i + submission_round;
        index = i & io_uring->get_sq_mask();
        sq_array[index] = index;
      }

      uint32_t sq_tail = io_uring->load_sq_tail();
      ASSERT_EQ(sq_tail, 4 * submission_round);
      io_uring->store_sq_tail(sq_tail + 4);

      int ret = io_uring->Enter(4, 4, 0, nullptr);
      ASSERT_EQ(ret, 4);

      sq_head = io_uring->load_sq_head();
      ASSERT_EQ(sq_head, 4 * (submission_round + 1));

      uint32_t dropped = io_uring->load_sq_dropped();
      ASSERT_EQ(dropped, 0);

      uint32_t cq_overflow_counter = io_uring->load_cq_overflow();
      ASSERT_EQ(cq_overflow_counter, 0);

      uint32_t cq_tail = io_uring->load_cq_tail();
      ASSERT_EQ(cq_tail, 4 * (submission_round + 1));

      for (size_t i = 0; i < 4; ++i) {
        ASSERT_EQ(cqe[i + 4 * submission_round].res, 0);
        ASSERT_EQ(cqe[i + 4 * submission_round].user_data,
                  42 + i + submission_round);
      }
    }

    for (size_t i = 0; i < 2; ++i) {
      sqe[i].opcode = IORING_OP_NOP;
      sqe[i].user_data = 52 + i;
      index = i & io_uring->get_sq_mask();
      sq_array[index] = index;
    }

    uint32_t sq_tail = io_uring->load_sq_tail();
    ASSERT_EQ(sq_tail, 8);
    io_uring->store_sq_tail(sq_tail + 2);

    int ret = io_uring->Enter(2, 2, 0, nullptr);
    ASSERT_EQ(ret, 2);

    sq_head = io_uring->load_sq_head();
    ASSERT_EQ(sq_head, 10);

    uint32_t cq_tail = io_uring->load_cq_tail();
    ASSERT_EQ(cq_tail, 8);

    ASSERT_EQ(cqe[0].res, 0);
    ASSERT_EQ(cqe[0].user_data, 42);
    ASSERT_EQ(cqe[1].res, 0);
    ASSERT_EQ(cqe[1].user_data, 43);

    uint32_t dropped = io_uring->load_sq_dropped();
    ASSERT_EQ(dropped, 0);

    uint32_t cq_overflow_counter = io_uring->load_cq_overflow();
    ASSERT_EQ(cq_overflow_counter, 2);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
