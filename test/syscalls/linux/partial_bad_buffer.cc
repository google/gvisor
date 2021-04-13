// Copyright 2018 The gVisor Authors.
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
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::Gt;

namespace gvisor {
namespace testing {

namespace {

constexpr char kMessage[] = "hello world";

// PartialBadBufferTest checks the result of various IO syscalls when passed a
// buffer that does not have the space specified in the syscall (most of it is
// PROT_NONE). Linux is annoyingly inconsistent among different syscalls, so we
// test all of them.
class PartialBadBufferTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create and open a directory for getdents cases.
    directory_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(
        directory_fd_ = open(directory_.path().c_str(), O_RDONLY | O_DIRECTORY),
        SyscallSucceeds());

    // Create and open a normal file, placing it in the directory
    // so the getdents cases have some dirents.
    name_ = JoinPath(directory_.path(), "a");
    ASSERT_THAT(fd_ = open(name_.c_str(), O_RDWR | O_CREAT, 0644),
                SyscallSucceeds());

    // Write some initial data.
    size_t size = sizeof(kMessage) - 1;
    EXPECT_THAT(WriteFd(fd_, &kMessage, size), SyscallSucceedsWithValue(size));
    ASSERT_THAT(lseek(fd_, 0, SEEK_SET), SyscallSucceeds());

    // Map a useable buffer.
    addr_ = mmap(0, 2 * kPageSize, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(addr_, MAP_FAILED);
    char* buf = reinterpret_cast<char*>(addr_);

    // Guard page for our read to run into.
    ASSERT_THAT(mprotect(reinterpret_cast<void*>(buf + kPageSize), kPageSize,
                         PROT_NONE),
                SyscallSucceeds());

    // Leave only one free byte in the buffer.
    bad_buffer_ = buf + kPageSize - 1;
  }

  off_t Size() {
    struct stat st;
    int rc = fstat(fd_, &st);
    if (rc < 0) {
      return static_cast<off_t>(rc);
    }
    return st.st_size;
  }

  void TearDown() override {
    EXPECT_THAT(munmap(addr_, 2 * kPageSize), SyscallSucceeds()) << addr_;
    EXPECT_THAT(close(fd_), SyscallSucceeds());
    EXPECT_THAT(unlink(name_.c_str()), SyscallSucceeds());
    EXPECT_THAT(close(directory_fd_), SyscallSucceeds());
  }

  // Return buffer with n bytes of free space.
  // N.B. this is the same buffer used to back bad_buffer_.
  char* FreeBytes(size_t n) {
    TEST_CHECK(n <= static_cast<size_t>(4096));
    return reinterpret_cast<char*>(addr_) + kPageSize - n;
  }

  std::string name_;
  int fd_;
  TempPath directory_;
  int directory_fd_;
  void* addr_;
  char* bad_buffer_;
};

// We do both "big" and "small" tests to try to hit the "zero copy" and
// non-"zero copy" paths, which have different code paths for handling faults.

TEST_F(PartialBadBufferTest, ReadBig) {
  EXPECT_THAT(RetryEINTR(read)(fd_, bad_buffer_, kPageSize),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, ReadSmall) {
  EXPECT_THAT(RetryEINTR(read)(fd_, bad_buffer_, 10),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadBig) {
  EXPECT_THAT(RetryEINTR(pread)(fd_, bad_buffer_, kPageSize, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadSmall) {
  EXPECT_THAT(RetryEINTR(pread)(fd_, bad_buffer_, 10, 0),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, ReadvBig) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;

  EXPECT_THAT(RetryEINTR(readv)(fd_, &vec, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, ReadvSmall) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;

  EXPECT_THAT(RetryEINTR(readv)(fd_, &vec, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadvBig) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;

  EXPECT_THAT(RetryEINTR(preadv)(fd_, &vec, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, PreadvSmall) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;

  EXPECT_THAT(RetryEINTR(preadv)(fd_, &vec, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_EQ('h', bad_buffer_[0]);
}

TEST_F(PartialBadBufferTest, WriteBig) {
  off_t orig_size = Size();
  int n;

  ASSERT_THAT(lseek(fd_, orig_size, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(
      (n = RetryEINTR(write)(fd_, bad_buffer_, kPageSize)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, WriteSmall) {
  off_t orig_size = Size();
  int n;

  ASSERT_THAT(lseek(fd_, orig_size, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(
      (n = RetryEINTR(write)(fd_, bad_buffer_, 10)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, PwriteBig) {
  off_t orig_size = Size();
  int n;

  EXPECT_THAT(
      (n = RetryEINTR(pwrite)(fd_, bad_buffer_, kPageSize, orig_size)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, PwriteSmall) {
  off_t orig_size = Size();
  int n;

  EXPECT_THAT(
      (n = RetryEINTR(pwrite)(fd_, bad_buffer_, 10, orig_size)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, WritevBig) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;
  off_t orig_size = Size();
  int n;

  ASSERT_THAT(lseek(fd_, orig_size, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(
      (n = RetryEINTR(writev)(fd_, &vec, 1)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, WritevSmall) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;
  off_t orig_size = Size();
  int n;

  ASSERT_THAT(lseek(fd_, orig_size, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(
      (n = RetryEINTR(writev)(fd_, &vec, 1)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, PwritevBig) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = kPageSize;
  off_t orig_size = Size();
  int n;

  EXPECT_THAT(
      (n = RetryEINTR(pwritev)(fd_, &vec, 1, orig_size)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

TEST_F(PartialBadBufferTest, PwritevSmall) {
  struct iovec vec;
  vec.iov_base = bad_buffer_;
  vec.iov_len = 10;
  off_t orig_size = Size();
  int n;

  EXPECT_THAT(
      (n = RetryEINTR(pwritev)(fd_, &vec, 1, orig_size)),
      AnyOf(SyscallFailsWithErrno(EFAULT), SyscallSucceedsWithValue(1)));
  EXPECT_EQ(Size(), orig_size + (n >= 0 ? n : 0));
}

// getdents returns EFAULT when the you claim the buffer is large enough, but
// it actually isn't.
TEST_F(PartialBadBufferTest, GetdentsBig) {
  EXPECT_THAT(RetryEINTR(syscall)(SYS_getdents64, directory_fd_, bad_buffer_,
                                  kPageSize),
              SyscallFailsWithErrno(EFAULT));
}

// getdents returns EINVAL when the you claim the buffer is too small.
TEST_F(PartialBadBufferTest, GetdentsSmall) {
  EXPECT_THAT(
      RetryEINTR(syscall)(SYS_getdents64, directory_fd_, bad_buffer_, 10),
      SyscallFailsWithErrno(EINVAL));
}

// getdents will write entries into a buffer if there is space before it faults.
TEST_F(PartialBadBufferTest, GetdentsOneEntry) {
  // 30 bytes is enough for one (small) entry.
  char* buf = FreeBytes(30);

  EXPECT_THAT(
      RetryEINTR(syscall)(SYS_getdents64, directory_fd_, buf, kPageSize),
      SyscallSucceedsWithValue(Gt(0)));
}

PosixErrorOr<sockaddr_storage> InetLoopbackAddr(int family) {
  struct sockaddr_storage addr;
  memset(&addr, 0, sizeof(addr));
  addr.ss_family = family;
  switch (family) {
    case AF_INET:
      reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr.s_addr =
          htonl(INADDR_LOOPBACK);
      break;
    case AF_INET6:
      reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr =
          in6addr_loopback;
      break;
    default:
      return PosixError(EINVAL,
                        absl::StrCat("unknown socket family: ", family));
  }
  return addr;
}

// SendMsgTCP verifies that calling sendmsg with a bad address returns an
// EFAULT. It also verifies that passing a buffer which is made up of 2
// pages one valid and one guard page succeeds as long as the write is
// for exactly the size of 1 page.
TEST_F(PartialBadBufferTest, SendMsgTCP) {
  // FIXME(b/171436815): Netstack save/restore is broken.
  const DisableSave ds;

  auto listen_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

  // Initialize address to the loopback one.
  sockaddr_storage addr = ASSERT_NO_ERRNO_AND_VALUE(InetLoopbackAddr(AF_INET));
  socklen_t addrlen = sizeof(addr);

  // Bind to some port then start listening.
  ASSERT_THAT(bind(listen_socket.get(),
                   reinterpret_cast<struct sockaddr*>(&addr), addrlen),
              SyscallSucceeds());

  ASSERT_THAT(listen(listen_socket.get(), SOMAXCONN), SyscallSucceeds());

  // Get the address we're listening on, then connect to it. We need to do this
  // because we're allowing the stack to pick a port for us.
  ASSERT_THAT(getsockname(listen_socket.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), &addrlen),
              SyscallSucceeds());

  auto send_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

  ASSERT_THAT(
      RetryEINTR(connect)(send_socket.get(),
                          reinterpret_cast<struct sockaddr*>(&addr), addrlen),
      SyscallSucceeds());

  // Accept the connection.
  auto recv_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(listen_socket.get(), nullptr, nullptr));

  // TODO(gvisor.dev/issue/674): Update this once Netstack matches linux
  //   behaviour on a setsockopt of SO_RCVBUF/SO_SNDBUF.
  //
  // Set SO_SNDBUF for socket to exactly kPageSize+1.
  //
  // gVisor does not double the value passed in SO_SNDBUF like linux does so we
  // just increase it by 1 byte here for gVisor so that we can test writing 1
  // byte past the valid page and check that it triggers an EFAULT
  // correctly. Otherwise in gVisor the sendmsg call will just return with no
  // error with kPageSize bytes written successfully.
  const uint32_t buf_size = kPageSize + 1;
  ASSERT_THAT(setsockopt(send_socket.get(), SOL_SOCKET, SO_SNDBUF, &buf_size,
                         sizeof(buf_size)),
              SyscallSucceedsWithValue(0));

  struct msghdr hdr = {};
  struct iovec iov = {};
  iov.iov_base = bad_buffer_;
  iov.iov_len = kPageSize;
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(send_socket.get(), &hdr, 0),
              SyscallFailsWithErrno(EFAULT));

  // Now assert that writing kPageSize from addr_ succeeds.
  iov.iov_base = addr_;
  ASSERT_THAT(RetryEINTR(sendmsg)(send_socket.get(), &hdr, 0),
              SyscallSucceedsWithValue(kPageSize));
  // Read all the data out so that we drain the socket SND_BUF on the sender.
  std::vector<char> buffer(kPageSize);
  ASSERT_THAT(RetryEINTR(read)(recv_socket.get(), buffer.data(), kPageSize),
              SyscallSucceedsWithValue(kPageSize));

  // Sleep for a shortwhile to ensure that we have time to process the
  // ACKs. This is not strictly required unless running under gotsan which is a
  // lot slower and can result in the next write to write only 1 byte instead of
  // our intended kPageSize + 1.
  absl::SleepFor(absl::Milliseconds(50));

  // Now assert that writing > kPageSize results in EFAULT.
  iov.iov_len = kPageSize + 1;
  ASSERT_THAT(RetryEINTR(sendmsg)(send_socket.get(), &hdr, 0),
              SyscallFailsWithErrno(EFAULT));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
