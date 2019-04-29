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

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/syscalls/linux/readv_common.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class ReadvSocketTest : public SocketTest {
  void SetUp() override {
    SocketTest::SetUp();
    ASSERT_THAT(
        write(test_unix_stream_socket_[1], kReadvTestData, kReadvTestDataSize),
        SyscallSucceedsWithValue(kReadvTestDataSize));
    ASSERT_THAT(
        write(test_unix_dgram_socket_[1], kReadvTestData, kReadvTestDataSize),
        SyscallSucceedsWithValue(kReadvTestDataSize));
    ASSERT_THAT(write(test_unix_seqpacket_socket_[1], kReadvTestData,
                      kReadvTestDataSize),
                SyscallSucceedsWithValue(kReadvTestDataSize));
    // FIXME(b/69821513): Enable when possible.
    // ASSERT_THAT(write(test_tcp_socket_[1], kReadvTestData,
    // kReadvTestDataSize),
    //             SyscallSucceedsWithValue(kReadvTestDataSize));
  }
};

TEST_F(ReadvSocketTest, ReadOneBufferPerByte_StreamSocket) {
  ReadOneBufferPerByte(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadOneBufferPerByte_DgramSocket) {
  ReadOneBufferPerByte(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadOneBufferPerByte_SeqPacketSocket) {
  ReadOneBufferPerByte(test_unix_seqpacket_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadOneHalfAtATime_StreamSocket) {
  ReadOneHalfAtATime(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadOneHalfAtATime_DgramSocket) {
  ReadOneHalfAtATime(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadAllOneBuffer_StreamSocket) {
  ReadAllOneBuffer(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadAllOneBuffer_DgramSocket) {
  ReadAllOneBuffer(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadAllOneLargeBuffer_StreamSocket) {
  ReadAllOneLargeBuffer(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadAllOneLargeBuffer_DgramSocket) {
  ReadAllOneLargeBuffer(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadBuffersOverlapping_StreamSocket) {
  ReadBuffersOverlapping(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadBuffersOverlapping_DgramSocket) {
  ReadBuffersOverlapping(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadBuffersDiscontinuous_StreamSocket) {
  ReadBuffersDiscontinuous(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadBuffersDiscontinuous_DgramSocket) {
  ReadBuffersDiscontinuous(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadIovecsCompletelyFilled_StreamSocket) {
  ReadIovecsCompletelyFilled(test_unix_stream_socket_[0]);
}

TEST_F(ReadvSocketTest, ReadIovecsCompletelyFilled_DgramSocket) {
  ReadIovecsCompletelyFilled(test_unix_dgram_socket_[0]);
}

TEST_F(ReadvSocketTest, BadIovecsPointer_StreamSocket) {
  ASSERT_THAT(readv(test_unix_stream_socket_[0], nullptr, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvSocketTest, BadIovecsPointer_DgramSocket) {
  ASSERT_THAT(readv(test_unix_dgram_socket_[0], nullptr, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvSocketTest, BadIovecBase_StreamSocket) {
  struct iovec iov[1];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_unix_stream_socket_[0], iov, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvSocketTest, BadIovecBase_DgramSocket) {
  struct iovec iov[1];
  iov[0].iov_base = nullptr;
  iov[0].iov_len = 1024;
  ASSERT_THAT(readv(test_unix_dgram_socket_[0], iov, 1),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(ReadvSocketTest, ZeroIovecs_StreamSocket) {
  struct iovec iov[1];
  iov[0].iov_base = 0;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_unix_stream_socket_[0], iov, 1), SyscallSucceeds());
}

TEST_F(ReadvSocketTest, ZeroIovecs_DgramSocket) {
  struct iovec iov[1];
  iov[0].iov_base = 0;
  iov[0].iov_len = 0;
  ASSERT_THAT(readv(test_unix_dgram_socket_[0], iov, 1), SyscallSucceeds());
}

TEST_F(ReadvSocketTest, WouldBlock_StreamSocket) {
  struct iovec iov[1];
  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_unix_stream_socket_[0], iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  free(iov[0].iov_base);

  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  ASSERT_THAT(readv(test_unix_stream_socket_[0], iov, 1),
              SyscallFailsWithErrno(EAGAIN));
  free(iov[0].iov_base);
}

TEST_F(ReadvSocketTest, WouldBlock_DgramSocket) {
  struct iovec iov[1];
  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  iov[0].iov_len = kReadvTestDataSize;
  ASSERT_THAT(readv(test_unix_dgram_socket_[0], iov, 1),
              SyscallSucceedsWithValue(kReadvTestDataSize));
  free(iov[0].iov_base);

  iov[0].iov_base = reinterpret_cast<char*>(malloc(kReadvTestDataSize));
  ASSERT_THAT(readv(test_unix_dgram_socket_[0], iov, 1),
              SyscallFailsWithErrno(EAGAIN));
  free(iov[0].iov_base);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
