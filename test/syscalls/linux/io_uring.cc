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

#include <asm-generic/errno-base.h>
#include <errno.h>
#include <fcntl.h>
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
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// IOVecContainsString checks that a tuple argument of (struct iovec *, int)
// corresponding to an iovec array and its length, contains data that matches
// the string length strlen and the string value str.
MATCHER_P(IOVecContainsString, str, "") {
  struct iovec *iovs = arg.first;
  int len = strlen(str);
  int niov = arg.second;
  int offset = 0;

  for (int i = 0; i < niov; i++) {
    struct iovec iov = iovs[i];
    if (len < offset) {
      *result_listener << "strlen " << len << " < offset " << offset;
      return false;
    }
    if (strncmp(static_cast<char *>(iov.iov_base), &str[offset], iov.iov_len)) {
      absl::string_view iovec_string(static_cast<char *>(iov.iov_base),
                                     iov.iov_len);
      *result_listener << iovec_string << " @offset " << offset;
      return false;
    }
    offset += iov.iov_len;
  }
  if (offset != len) {
    *result_listener << offset;
    return false;
  }

  return true;
}

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

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
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

  int ret = io_uring->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
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

  ret = io_uring->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
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

  int ret = io_uring->Enter(3, 3, IORING_ENTER_GETEVENTS, nullptr);
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
      int ret = io_uring_ptr->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
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

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
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

// Tests that filling the shared memory region with garbage data doesn't cause a
// kernel panic.
TEST(IOUringTest, CorruptRingHeader) {
  const int kEntries = 64;

  IOUringParams params;
  FileDescriptor iouringfd =
      ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(kEntries, params));

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz = params.cq_off.cqes + params.cq_entries * sizeof(IOUringCqe);
  int sqes_sz = params.sq_entries * sizeof(IOUringSqe);

  void *sq_ptr =
      mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd.get(), IORING_OFF_SQ_RING);

  void *cq_ptr =
      mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd.get(), IORING_OFF_CQ_RING);

  void *sqe_ptr =
      mmap(0, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd.get(), IORING_OFF_SQES);

  EXPECT_NE(sq_ptr, MAP_FAILED);
  EXPECT_NE(cq_ptr, MAP_FAILED);
  EXPECT_NE(sqe_ptr, MAP_FAILED);

  // Corrupt all the buffers.
  memset(sq_ptr, 0xff, sring_sz);
  memset(cq_ptr, 0xff, cring_sz);
  memset(sqe_ptr, 0xff, sqes_sz);

  IOUringEnter(iouringfd.get(), 1, 0, IORING_ENTER_GETEVENTS, nullptr);

  // If kernel hasn't panicked, the test succeeds.

  EXPECT_THAT(munmap(sq_ptr, sring_sz), SyscallSucceeds());
  EXPECT_THAT(munmap(cq_ptr, cring_sz), SyscallSucceeds());
  EXPECT_THAT(munmap(sqe_ptr, sizeof(IOUringSqe)), SyscallSucceeds());
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

  int ret = io_uring->Enter(4, 4, IORING_ENTER_GETEVENTS, nullptr);
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

  ret = io_uring->Enter(4, 4, IORING_ENTER_GETEVENTS, nullptr);
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
    EXPECT_THAT(io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, &non_null_sigset),
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

      int ret = io_uring->Enter(4, 4, IORING_ENTER_GETEVENTS, nullptr);
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

    int ret = io_uring->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
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

// Testing that io_uring_enter(2) successfully handles single READV operation.
TEST(IOUringTest, SingleREADVTest) {
  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  off_t file_sz = st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void *buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, file_sz);

  struct iovec *fi = reinterpret_cast<struct iovec *>(cqe->user_data);

  std::pair<struct iovec *, int> iovec_desc(fi, num_blocks);
  EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Tests that IORING_OP_READV handles EOF on an empty file correctly.
TEST(IOUringTest, ReadvEmptyFile) {
  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  uint32_t sq_head = io_uring->load_sq_head();

  std::string file_name = NewTempAbsPath();
  ASSERT_NO_ERRNO(CreateWithContents(file_name, "", 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = 0;
  void *buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = 1;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, 0);  // 0 length read, EOF.

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully handles three READV operations
// from three different files submitted through a single invocation.
TEST(IOUringTest, ThreeREADVSingleEnterTest) {
  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  ASSERT_EQ(params.sq_entries, 4);
  ASSERT_EQ(params.cq_entries, 8);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  FileDescriptor filefd[3];
  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();
  off_t file_sz[3];
  int num_blocks[3];
  struct iovec iov[3];

  for (size_t i = 0; i < 3; i++) {
    std::string file_name = NewTempAbsPath();
    std::string contents("DEADBEEF");
    for (size_t j = 0; j < i; ++j) {
      contents.append(" DEADBEEF");
    }
    ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

    filefd[i] = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
    ASSERT_GE(filefd[i].get(), 0);

    struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
    file_sz[i] = st.st_size;
    ASSERT_GT(file_sz[i], 0);

    num_blocks[i] = (file_sz[i] + BLOCK_SZ - 1) / BLOCK_SZ;
    ASSERT_EQ(num_blocks[i], 1);

    iov[i].iov_len = file_sz[i];
    void *buf;
    ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
    iov[i].iov_base = buf;

    sqe[i].flags = 0;
    sqe[i].fd = filefd[i].get();
    sqe[i].opcode = IORING_OP_READV;
    sqe[i].addr = reinterpret_cast<uint64_t>(&iov[i]);
    sqe[i].len = num_blocks[i];
    sqe[i].off = 0;
    sqe[i].user_data = reinterpret_cast<uint64_t>(&iov[i]);
    sq_array[i] = i;

    uint32_t sq_tail = io_uring->load_sq_tail();
    io_uring->store_sq_tail(sq_tail + 1);
  }

  ASSERT_EQ(file_sz[0], 8);
  ASSERT_EQ(file_sz[1], 17);
  ASSERT_EQ(file_sz[2], 26);

  int ret = io_uring->Enter(3, 3, 0, nullptr);
  ASSERT_EQ(ret, 3);

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 3);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 3);

  ASSERT_EQ(cqe[0].res, file_sz[0]);
  ASSERT_EQ(cqe[1].res, file_sz[1]);
  ASSERT_EQ(cqe[2].res, file_sz[2]);

  for (size_t i = 0; i < 3; i++) {
    struct iovec *fi = reinterpret_cast<struct iovec *>(cqe->user_data);

    std::string contents("DEADBEEF");
    for (size_t j = 0; j < i; ++j) {
      contents.append(" DEADBEEF");
    }

    std::pair<struct iovec *, int> iovec_desc(&fi[i], num_blocks[i]);
    EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

    uint32_t cq_head = io_uring->load_cq_head();
    io_uring->store_cq_head(cq_head + 1);
  }
}

// Testing that io_uring_enter(2) successfully handles READV operation, which is
// racing with deletion of the same file.
TEST(IOUringTest, READVRaceWithDeleteTest) {
  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(2, params));

  ASSERT_EQ(params.sq_entries, 2);
  ASSERT_EQ(params.cq_entries, 4);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name[2];
  FileDescriptor filefd[2];
  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();
  off_t file_sz[2];
  int num_blocks[2];
  struct iovec iov[2];

  for (size_t i = 0; i < 2; i++) {
    file_name[i] = NewTempAbsPath();
    std::string contents("DEADBEEF");
    for (size_t j = 0; j < i; ++j) {
      contents.append(" DEADBEEF");
    }
    ASSERT_NO_ERRNO(CreateWithContents(file_name[i], contents, 0666));

    filefd[i] = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name[i], O_RDONLY));
    ASSERT_GE(filefd[i].get(), 0);

    struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name[i]));
    file_sz[i] = st.st_size;
    ASSERT_GT(file_sz[i], 0);

    num_blocks[i] = (file_sz[i] + BLOCK_SZ - 1) / BLOCK_SZ;
    ASSERT_EQ(num_blocks[i], 1);

    iov[i].iov_len = file_sz[i];
    void *buf;
    ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
    iov[i].iov_base = buf;

    sqe[i].flags = 0;
    sqe[i].fd = filefd[i].get();
    sqe[i].opcode = IORING_OP_READV;
    sqe[i].addr = reinterpret_cast<uint64_t>(&iov[i]);
    sqe[i].len = num_blocks[i];
    sqe[i].off = 0;
    sqe[i].user_data = reinterpret_cast<uint64_t>(&iov[i]);
    sq_array[i] = i;

    uint32_t sq_tail = io_uring->load_sq_tail();
    io_uring->store_sq_tail(sq_tail + 1);
  }

  ASSERT_EQ(file_sz[0], 8);
  ASSERT_EQ(file_sz[1], 17);

  ScopedThread t1([&] {
    IOUring *io_uring_ptr = io_uring.get();
    int ret = io_uring_ptr->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
    ASSERT_EQ(ret, 2);
  });

  ScopedThread t2([&] { filefd[0].reset(); });

  t1.Join();
  t2.Join();

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 2);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 2);

  ASSERT_TRUE(cqe[0].res == -EBADF || cqe[0].res == 8);
  ASSERT_EQ(cqe[1].res, file_sz[1]);

  for (size_t i = 0; i < 2; i++) {
    if (cqe[i].res == -EBADF) {
      uint32_t cq_head = io_uring->load_cq_head();
      io_uring->store_cq_head(cq_head + 1);

      continue;
    }

    struct iovec *fi = reinterpret_cast<struct iovec *>(cqe->user_data);

    std::string contents("DEADBEEF");
    for (size_t j = 0; j < i; ++j) {
      contents.append(" DEADBEEF");
    }

    std::pair<struct iovec *, int> iovec_desc(&fi[i], num_blocks[i]);
    EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

    uint32_t cq_head = io_uring->load_cq_head();
    io_uring->store_cq_head(cq_head + 1);
  }
}

// Testing that io_uring_enter(2) successfully handles single READV operation
// with short read situation.
TEST(IOUringTest, ShortReadREADVTest) {
  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  // Set file size to be twice of its actual size to mimic the short read.
  off_t file_sz = 2 * st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void *buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, file_sz / 2);

  struct iovec *fi = reinterpret_cast<struct iovec *>(cqe->user_data);
  fi->iov_len = file_sz / 2;

  std::pair<struct iovec *, int> iovec_desc(fi, num_blocks);
  EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully handles single READV operation
// when there file does not have read permissions.
TEST(IOUringTest, NoReadPermissionsREADVTest) {
  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_WRONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  off_t file_sz = st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void *buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, -EBADF);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

struct SqeFieldsUT {
  uint16_t ioprio;
  uint16_t buf_index;
};

class IOUringSqeFieldsTest : public ::testing::Test,
                             public ::testing::WithParamInterface<SqeFieldsUT> {
};

// Testing that io_uring_enter(2) successfully handles single READV operation
// and returns EINVAL error in the CQE when either ioprio or buf_index is set.
TEST_P(IOUringSqeFieldsTest, READVWithInvalidSqeFieldValue) {
  const SqeFieldsUT p = GetParam();

  struct io_uring_params params;
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  off_t file_sz = st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned *sq_array = io_uring->get_sq_array();
  struct io_uring_sqe *sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void *buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sqe->ioprio = p.ioprio;
  sqe->buf_index = p.buf_index;
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, 0, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe *cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, -EINVAL);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

INSTANTIATE_TEST_SUITE_P(
    IOUringSqeFields, IOUringSqeFieldsTest,
    ::testing::Values(SqeFieldsUT{.ioprio = 0, .buf_index = 1},
                      SqeFieldsUT{.ioprio = 1, .buf_index = 0}));

}  // namespace

}  // namespace testing
}  // namespace gvisor
