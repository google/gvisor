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

#include <cstdint>

#include "gtest/gtest.h"
#include "test/util/io_uring_util.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Testing that io_uring_setup(2) successfully returns a valid file descriptor.
TEST(IOUringTest, ValidFD) {
  struct io_uring_params params;
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));
}

// Testing that io_uring_setup(2) fails with EINVAL on non-zero params.
TEST(IOUringTest, ParamsNonZeroResv) {
  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  params.resv[1] = 1;
  ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

// Testing that io_uring_setup(2) fails with EINVAL on unsupported flags.
TEST(IOUringTest, UnsupportedFlags) {
  if (IsRunningOnGvisor()) {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    params.flags |= IORING_SETUP_SQPOLL;
    ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
  }
}

// Testing that both mmap and munmap calls succeed and subsequent access to
// unmapped memory results in SIGSEGV.
TEST(IOUringTest, MMapMUnMapWork) {
  struct io_uring_params params;
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
  struct io_uring_params params;
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
  struct io_uring_params params;
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  void *sqPtr = nullptr;
  void *cqPtr = nullptr;
  void *sqePtr = nullptr;

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz = params.cq_off.cqes + params.cq_entries * 32;

  sqPtr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               iouringfd.get(), IORING_OFF_SQ_RING);

  cqPtr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               iouringfd.get(), IORING_OFF_CQ_RING);

  sqePtr = mmap(0, 64, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                iouringfd.get(), IORING_OFF_SQES);

  EXPECT_NE(sqPtr, MAP_FAILED);
  EXPECT_NE(cqPtr, MAP_FAILED);
  EXPECT_NE(sqePtr, MAP_FAILED);

  EXPECT_EQ((uintptr_t)sqPtr % kPageSize, 0);
  EXPECT_EQ((uintptr_t)cqPtr % kPageSize, 0);
  EXPECT_EQ((uintptr_t)sqePtr % kPageSize, 0);

  ASSERT_THAT(munmap(sqPtr, sring_sz), SyscallSucceeds());
  ASSERT_THAT(munmap(cqPtr, cring_sz), SyscallSucceeds());
  ASSERT_THAT(munmap(sqePtr, 64), SyscallSucceeds());
}

// Testing that io_uring_params are populated with correct values.
TEST(IOUringTest, ReturnedParamsValues) {
  if (IsRunningOnGvisor()) {
    struct io_uring_params params;
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
  struct io_uring_params params;
  for (uint32_t i = 1; i < 10; ++i) {
    FileDescriptor iouringfd =
        ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(i, params));
    ASSERT_EQ(params.sq_off.array % 64, 0);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
