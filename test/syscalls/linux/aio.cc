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
#include <linux/aio_abi.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr char kData[] = "hello world!";

int SubmitCtx(aio_context_t ctx, long nr, struct iocb** iocbpp) {
  return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

}  // namespace

class AIOTest : public FileTest {
 public:
  AIOTest() : ctx_(0) {}

  int SetupContext(unsigned int nr) {
    return syscall(__NR_io_setup, nr, &ctx_);
  }

  int Submit(long nr, struct iocb** iocbpp) {
    return SubmitCtx(ctx_, nr, iocbpp);
  }

  int GetEvents(long min, long max, struct io_event* events,
                struct timespec* timeout) {
    return RetryEINTR(syscall)(__NR_io_getevents, ctx_, min, max, events,
                               timeout);
  }

  int DestroyContext() { return syscall(__NR_io_destroy, ctx_); }

  void TearDown() override {
    FileTest::TearDown();
    if (ctx_ != 0) {
      ASSERT_THAT(DestroyContext(), SyscallSucceeds());
    }
  }

  struct iocb CreateCallback() {
    struct iocb cb = {};
    cb.aio_data = 0x123;
    cb.aio_fildes = test_file_fd_.get();
    cb.aio_lio_opcode = IOCB_CMD_PWRITE;
    cb.aio_buf = reinterpret_cast<uint64_t>(kData);
    cb.aio_offset = 0;
    cb.aio_nbytes = strlen(kData);
    return cb;
  }

 protected:
  aio_context_t ctx_;
};

TEST_F(AIOTest, BasicWrite) {
  // Copied from fs/aio.c.
  constexpr unsigned AIO_RING_MAGIC = 0xa10a10a1;
  struct aio_ring {
    unsigned id;
    unsigned nr;
    unsigned head;
    unsigned tail;
    unsigned magic;
    unsigned compat_features;
    unsigned incompat_features;
    unsigned header_length;
    struct io_event io_events[0];
  };

  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  // Check that 'ctx_' points to a valid address. libaio uses it to check if
  // aio implementation uses aio_ring. gVisor doesn't and returns all zeroes.
  // Linux implements aio_ring, so skip the zeroes check.
  //
  // TODO: Remove when gVisor implements aio_ring.
  auto ring = reinterpret_cast<struct aio_ring*>(ctx_);
  auto magic = IsRunningOnGvisor() ? 0 : AIO_RING_MAGIC;
  EXPECT_EQ(ring->magic, magic);

  struct iocb cb = CreateCallback();
  struct iocb* cbs[1] = {&cb};

  // Submit the request.
  ASSERT_THAT(Submit(1, cbs), SyscallSucceedsWithValue(1));

  // Get the reply.
  struct io_event events[1];
  ASSERT_THAT(GetEvents(1, 1, events, nullptr), SyscallSucceedsWithValue(1));

  // Verify that it is as expected.
  EXPECT_EQ(events[0].data, 0x123);
  EXPECT_EQ(events[0].obj, reinterpret_cast<long>(&cb));
  EXPECT_EQ(events[0].res, strlen(kData));

  // Verify that the file contains the contents.
  char verify_buf[32] = {};
  ASSERT_THAT(read(test_file_fd_.get(), &verify_buf[0], strlen(kData)),
              SyscallSucceeds());
  EXPECT_EQ(strcmp(kData, &verify_buf[0]), 0);
}

TEST_F(AIOTest, BadWrite) {
  // Create a pipe and immediately close the read end.
  int pipefd[2];
  ASSERT_THAT(pipe(pipefd), SyscallSucceeds());

  FileDescriptor rfd(pipefd[0]);
  FileDescriptor wfd(pipefd[1]);

  rfd.reset();  // Close the read end.

  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  // Try to write to the read end.
  cb.aio_fildes = wfd.get();
  struct iocb* cbs[1] = {&cb};

  // Submit the request.
  ASSERT_THAT(Submit(1, cbs), SyscallSucceedsWithValue(1));

  // Get the reply.
  struct io_event events[1];
  ASSERT_THAT(GetEvents(1, 1, events, nullptr), SyscallSucceedsWithValue(1));

  // Verify that it fails with the right error code.
  EXPECT_EQ(events[0].data, 0x123);
  EXPECT_EQ(events[0].obj, reinterpret_cast<uint64_t>(&cb));
  EXPECT_LT(events[0].res, 0);
}

TEST_F(AIOTest, ExitWithPendingIo) {
  // Setup a context that is 5 entries deep.
  ASSERT_THAT(SetupContext(5), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  struct iocb* cbs[] = {&cb};

  // Submit a request but don't complete it to make it pending.
  EXPECT_THAT(Submit(1, cbs), SyscallSucceeds());
}

int Submitter(void* arg) {
  auto test = reinterpret_cast<AIOTest*>(arg);

  struct iocb cb = test->CreateCallback();
  struct iocb* cbs[1] = {&cb};

  // Submit the request.
  TEST_CHECK(test->Submit(1, cbs) == 1);
  return 0;
}

TEST_F(AIOTest, CloneVm) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  const size_t kStackSize = 5 * kPageSize;
  std::unique_ptr<char[]> stack(new char[kStackSize]);
  char* bp = stack.get() + kStackSize;
  pid_t child;
  ASSERT_THAT(child = clone(Submitter, bp, CLONE_VM | SIGCHLD,
                            reinterpret_cast<void*>(this)),
              SyscallSucceeds());

  // Get the reply.
  struct io_event events[1];
  ASSERT_THAT(GetEvents(1, 1, events, nullptr), SyscallSucceedsWithValue(1));

  // Verify that it is as expected.
  EXPECT_EQ(events[0].data, 0x123);
  EXPECT_EQ(events[0].res, strlen(kData));

  // Verify that the file contains the contents.
  char verify_buf[32] = {};
  ASSERT_THAT(read(test_file_fd_.get(), &verify_buf[0], strlen(kData)),
              SyscallSucceeds());
  EXPECT_EQ(strcmp(kData, &verify_buf[0]), 0);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
      << " status " << status;
}

// Tests that AIO context can be remapped to a different address.
TEST_F(AIOTest, Mremap) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  struct iocb* cbs[1] = {&cb};

  // Reserve address space for the mremap target so we have something safe to
  // map over.
  //
  // N.B. We reserve 2 pages because we'll attempt to remap to 2 pages below.
  // That should fail with EFAULT, but will fail with EINVAL if this mmap
  // returns the page immediately below ctx_, as
  // [new_address, new_address+2*kPageSize) overlaps [ctx_, ctx_+kPageSize).
  void* new_address = mmap(nullptr, 2 * kPageSize, PROT_READ,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_THAT(reinterpret_cast<intptr_t>(new_address), SyscallSucceeds());
  auto mmap_cleanup = Cleanup([new_address] {
    EXPECT_THAT(munmap(new_address, 2 * kPageSize), SyscallSucceeds());
  });

  // Test that remapping to a larger address fails.
  void* res = mremap(reinterpret_cast<void*>(ctx_), kPageSize, 2 * kPageSize,
                     MREMAP_FIXED | MREMAP_MAYMOVE, new_address);
  ASSERT_THAT(reinterpret_cast<intptr_t>(res), SyscallFailsWithErrno(EFAULT));

  // Remap context 'handle' to a different address.
  res = mremap(reinterpret_cast<void*>(ctx_), kPageSize, kPageSize,
               MREMAP_FIXED | MREMAP_MAYMOVE, new_address);
  ASSERT_THAT(
      reinterpret_cast<intptr_t>(res),
      SyscallSucceedsWithValue(reinterpret_cast<intptr_t>(new_address)));
  mmap_cleanup.Release();
  aio_context_t old_ctx = ctx_;
  ctx_ = reinterpret_cast<aio_context_t>(new_address);

  // Check that submitting the request with the old 'ctx_' fails.
  ASSERT_THAT(SubmitCtx(old_ctx, 1, cbs), SyscallFailsWithErrno(EINVAL));

  // Submit the request with the new 'ctx_'.
  ASSERT_THAT(Submit(1, cbs), SyscallSucceedsWithValue(1));

  // Remap again.
  new_address =
      mmap(nullptr, kPageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_THAT(reinterpret_cast<int64_t>(new_address), SyscallSucceeds());
  auto mmap_cleanup2 = Cleanup([new_address] {
    EXPECT_THAT(munmap(new_address, kPageSize), SyscallSucceeds());
  });
  res = mremap(reinterpret_cast<void*>(ctx_), kPageSize, kPageSize,
               MREMAP_FIXED | MREMAP_MAYMOVE, new_address);
  ASSERT_THAT(reinterpret_cast<int64_t>(res),
              SyscallSucceedsWithValue(reinterpret_cast<int64_t>(new_address)));
  mmap_cleanup2.Release();
  ctx_ = reinterpret_cast<aio_context_t>(new_address);

  // Get the reply with yet another 'ctx_' and verify it.
  struct io_event events[1];
  ASSERT_THAT(GetEvents(1, 1, events, nullptr), SyscallSucceedsWithValue(1));
  EXPECT_EQ(events[0].data, 0x123);
  EXPECT_EQ(events[0].obj, reinterpret_cast<long>(&cb));
  EXPECT_EQ(events[0].res, strlen(kData));

  // Verify that the file contains the contents.
  char verify_buf[32] = {};
  ASSERT_THAT(read(test_file_fd_.get(), &verify_buf[0], strlen(kData)),
              SyscallSucceeds());
  EXPECT_EQ(strcmp(kData, &verify_buf[0]), 0);
}

// Tests that AIO context can be replaced with a different mapping at the same
// address and continue working. Don't ask why, but Linux allows it.
TEST_F(AIOTest, MremapOver) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  struct iocb* cbs[1] = {&cb};

  ASSERT_THAT(Submit(1, cbs), SyscallSucceedsWithValue(1));

  // Allocate a new VMA, copy 'ctx_' content over, and remap it on top
  // of 'ctx_'.
  void* new_address = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_THAT(reinterpret_cast<int64_t>(new_address), SyscallSucceeds());
  auto mmap_cleanup = Cleanup([new_address] {
    EXPECT_THAT(munmap(new_address, kPageSize), SyscallSucceeds());
  });

  memcpy(new_address, reinterpret_cast<void*>(ctx_), kPageSize);
  void* res =
      mremap(new_address, kPageSize, kPageSize, MREMAP_FIXED | MREMAP_MAYMOVE,
             reinterpret_cast<void*>(ctx_));
  ASSERT_THAT(reinterpret_cast<int64_t>(res), SyscallSucceedsWithValue(ctx_));
  mmap_cleanup.Release();

  // Everything continues to work just fine.
  struct io_event events[1];
  ASSERT_THAT(GetEvents(1, 1, events, nullptr), SyscallSucceedsWithValue(1));
  EXPECT_EQ(events[0].data, 0x123);
  EXPECT_EQ(events[0].obj, reinterpret_cast<long>(&cb));
  EXPECT_EQ(events[0].res, strlen(kData));

  // Verify that the file contains the contents.
  char verify_buf[32] = {};
  ASSERT_THAT(read(test_file_fd_.get(), &verify_buf[0], strlen(kData)),
              SyscallSucceeds());
  EXPECT_EQ(strcmp(kData, &verify_buf[0]), 0);
}

// Tests that AIO calls fail if context's address is inaccessible.
TEST_F(AIOTest, Mprotect) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  struct iocb* cbs[1] = {&cb};

  ASSERT_THAT(Submit(1, cbs), SyscallSucceedsWithValue(1));

  // Makes the context 'handle' inaccessible and check that all subsequent
  // calls fail.
  ASSERT_THAT(mprotect(reinterpret_cast<void*>(ctx_), kPageSize, PROT_NONE),
              SyscallSucceeds());
  struct io_event events[1];
  EXPECT_THAT(GetEvents(1, 1, events, nullptr), SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(Submit(1, cbs), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(DestroyContext(), SyscallFailsWithErrno(EINVAL));

  // Prevent TearDown from attempting to destroy the context and fail.
  ctx_ = 0;
}

TEST_F(AIOTest, Timeout) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct timespec timeout;
  timeout.tv_sec = 0;
  timeout.tv_nsec = 10;
  struct io_event events[1];
  ASSERT_THAT(GetEvents(1, 1, events, &timeout), SyscallSucceedsWithValue(0));
}

class AIOReadWriteParamTest : public AIOTest,
                              public ::testing::WithParamInterface<int> {};

TEST_P(AIOReadWriteParamTest, BadOffset) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  struct iocb* cbs[1] = {&cb};

  // Create a buffer that we can write to.
  char buf[] = "hello world!";
  cb.aio_buf = reinterpret_cast<uint64_t>(buf);

  // Set the operation on the callback and give a negative offset.
  const int opcode = GetParam();
  cb.aio_lio_opcode = opcode;

  iovec iov = {};
  if (opcode == IOCB_CMD_PREADV || opcode == IOCB_CMD_PWRITEV) {
    // Create a valid iovec and set it in the callback.
    iov.iov_base = reinterpret_cast<void*>(buf);
    iov.iov_len = 1;
    cb.aio_buf = reinterpret_cast<uint64_t>(&iov);
    // aio_nbytes is the number of iovecs.
    cb.aio_nbytes = 1;
  }

  // Pass a negative offset.
  cb.aio_offset = -1;

  // Should get error on submission.
  ASSERT_THAT(Submit(1, cbs), SyscallFailsWithErrno(EINVAL));
}

INSTANTIATE_TEST_CASE_P(BadOffset, AIOReadWriteParamTest,
                        ::testing::Values(IOCB_CMD_PREAD, IOCB_CMD_PWRITE,
                                          IOCB_CMD_PREADV, IOCB_CMD_PWRITEV));

class AIOVectorizedParamTest : public AIOTest,
                               public ::testing::WithParamInterface<int> {};

TEST_P(AIOVectorizedParamTest, BadIOVecs) {
  // Setup a context that is 128 entries deep.
  ASSERT_THAT(SetupContext(128), SyscallSucceeds());

  struct iocb cb = CreateCallback();
  struct iocb* cbs[1] = {&cb};

  // Modify the callback to use the operation from the param.
  cb.aio_lio_opcode = GetParam();

  // Create an iovec with address in kernel range, and pass that as the buffer.
  iovec iov = {};
  iov.iov_base = reinterpret_cast<void*>(0xFFFFFFFF00000000);
  iov.iov_len = 1;
  cb.aio_buf = reinterpret_cast<uint64_t>(&iov);
  // aio_nbytes is the number of iovecs.
  cb.aio_nbytes = 1;

  // Should get error on submission.
  ASSERT_THAT(Submit(1, cbs), SyscallFailsWithErrno(EFAULT));
}

INSTANTIATE_TEST_CASE_P(BadIOVecs, AIOVectorizedParamTest,
                        ::testing::Values(IOCB_CMD_PREADV, IOCB_CMD_PWRITEV));

}  // namespace testing
}  // namespace gvisor
