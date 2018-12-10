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

#include "test/syscalls/linux/socket_unix_non_stream.h"

#include <stdio.h>
#include <sys/mman.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/memory_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(UnixNonStreamSocketPairTest, RecvMsgTooLarge) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int rcvbuf;
  socklen_t length = sizeof(rcvbuf);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVBUF, &rcvbuf, &length),
      SyscallSucceeds());

  // Make the call larger than the receive buffer.
  const int recv_size = 3 * rcvbuf;

  // Write a message that does fit in the receive buffer.
  const int write_size = rcvbuf - kPageSize;

  std::vector<char> write_buf(write_size, 'a');
  const int ret = RetryEINTR(write)(sockets->second_fd(), write_buf.data(),
                                    write_buf.size());
  if (ret < 0 && errno == ENOBUFS) {
    // NOTE: Linux may stall the write for a long time and
    // ultimately return ENOBUFS. Allow this error, since a retry will likely
    // result in the same error.
    return;
  }
  ASSERT_THAT(ret, SyscallSucceeds());

  std::vector<char> recv_buf(recv_size);

  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(sockets->first_fd(), recv_buf.data(),
                                     recv_buf.size(), write_size));

  recv_buf.resize(write_size);
  EXPECT_EQ(recv_buf, write_buf);
}

// Create a region of anonymous memory of size 'size', which is fragmented in
// FileMem.
//
// ptr contains the start address of the region. The returned vector contains
// all of the mappings to be unmapped when done.
PosixErrorOr<std::vector<Mapping>> CreateFragmentedRegion(const int size,
                                                          void** ptr) {
  Mapping region;
  ASSIGN_OR_RETURN_ERRNO(region, Mmap(nullptr, size, PROT_NONE,
                                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

  *ptr = region.ptr();

  // Don't save hundreds of times for all of these mmaps.
  DisableSave ds;

  std::vector<Mapping> pages;

  // Map and commit a single page at a time, mapping and committing an unrelated
  // page between each call to force FileMem fragmentation.
  for (uintptr_t addr = region.addr(); addr < region.endaddr();
       addr += kPageSize) {
    Mapping page;
    ASSIGN_OR_RETURN_ERRNO(
        page,
        Mmap(reinterpret_cast<void*>(addr), kPageSize, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0));
    *reinterpret_cast<volatile char*>(page.ptr()) = 42;

    pages.emplace_back(std::move(page));

    // Unrelated page elsewhere.
    ASSIGN_OR_RETURN_ERRNO(page,
                           Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    *reinterpret_cast<volatile char*>(page.ptr()) = 42;

    pages.emplace_back(std::move(page));
  }

  // The mappings above have taken ownership of the region.
  region.release();

  return pages;
}

// A contiguous iov that is heavily fragmented in FileMem can still be sent
// successfully.
TEST_P(UnixNonStreamSocketPairTest, FragmentedSendMsg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  const int buffer_size = UIO_MAXIOV * kPageSize;
  // Extra page for message header overhead.
  const int sndbuf = buffer_size + kPageSize;
  // N.B. setsockopt(SO_SNDBUF) doubles the passed value.
  const int set_sndbuf = sndbuf / 2;

  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &set_sndbuf, sizeof(set_sndbuf)),
              SyscallSucceeds());

  int actual_sndbuf = 0;
  socklen_t length = sizeof(actual_sndbuf);
  ASSERT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &actual_sndbuf, &length),
              SyscallSucceeds());

  if (actual_sndbuf != sndbuf) {
    // Unable to get the sndbuf we want.
    //
    // N.B. At minimum, the socketpair gofer should provide a socket that is
    // already the correct size.
    //
    // TODO: When internal UDS support SO_SNDBUF, we can assert that
    // we always get the right SO_SNDBUF on gVisor.
    LOG(INFO) << "SO_SNDBUF = " << actual_sndbuf << ", want " << sndbuf
              << ". Skipping test";
    return;
  }

  // Create a contiguous region of memory of 2*UIO_MAXIOV*PAGE_SIZE. We'll call
  // sendmsg with a single iov, but the goal is to get the sentry to split this
  // into > UIO_MAXIOV iovs when calling the kernel.
  void* ptr;
  std::vector<Mapping> pages =
      ASSERT_NO_ERRNO_AND_VALUE(CreateFragmentedRegion(buffer_size, &ptr));

  struct iovec iov = {};
  iov.iov_base = ptr;
  iov.iov_len = buffer_size;

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // NOTE: Linux has poor behavior in the presence of
  // physical memory fragmentation. As a result, this may stall for a long time
  // and ultimately return ENOBUFS. Allow this error, since it means that we
  // made it to the host kernel and started the sendmsg.
  EXPECT_THAT(RetryEINTR(sendmsg)(sockets->first_fd(), &msg, 0),
              AnyOf(SyscallSucceedsWithValue(buffer_size),
                    SyscallFailsWithErrno(ENOBUFS)));
}

// A contiguous iov that is heavily fragmented in FileMem can still be received
// into successfully.
TEST_P(UnixNonStreamSocketPairTest, FragmentedRecvMsg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  const int buffer_size = UIO_MAXIOV * kPageSize;
  // Extra page for message header overhead.
  const int sndbuf = buffer_size + kPageSize;
  // N.B. setsockopt(SO_SNDBUF) doubles the passed value.
  const int set_sndbuf = sndbuf / 2;

  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &set_sndbuf, sizeof(set_sndbuf)),
              SyscallSucceeds());

  int actual_sndbuf = 0;
  socklen_t length = sizeof(actual_sndbuf);
  ASSERT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF,
                         &actual_sndbuf, &length),
              SyscallSucceeds());

  if (actual_sndbuf != sndbuf) {
    // Unable to get the sndbuf we want.
    //
    // N.B. At minimum, the socketpair gofer should provide a socket that is
    // already the correct size.
    //
    // TODO: When internal UDS support SO_SNDBUF, we can assert that
    // we always get the right SO_SNDBUF on gVisor.
    LOG(INFO) << "SO_SNDBUF = " << actual_sndbuf << ", want " << sndbuf
              << ". Skipping test";
    return;
  }

  std::vector<char> write_buf(buffer_size, 'a');
  const int ret = RetryEINTR(write)(sockets->first_fd(), write_buf.data(),
                                    write_buf.size());
  if (ret < 0 && errno == ENOBUFS) {
    // NOTE: Linux may stall the write for a long time and
    // ultimately return ENOBUFS. Allow this error, since a retry will likely
    // result in the same error.
    return;
  }
  ASSERT_THAT(ret, SyscallSucceeds());

  // Create a contiguous region of memory of 2*UIO_MAXIOV*PAGE_SIZE. We'll call
  // sendmsg with a single iov, but the goal is to get the sentry to split this
  // into > UIO_MAXIOV iovs when calling the kernel.
  void* ptr;
  std::vector<Mapping> pages =
      ASSERT_NO_ERRNO_AND_VALUE(CreateFragmentedRegion(buffer_size, &ptr));

  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(
      sockets->second_fd(), reinterpret_cast<char*>(ptr), buffer_size));

  EXPECT_EQ(0, memcmp(write_buf.data(), ptr, buffer_size));
}

}  // namespace testing
}  // namespace gvisor
