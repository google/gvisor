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

#include "test/syscalls/linux/socket_non_stream.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(NonStreamSocketPairTest, SendMsgTooLarge) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int sndbuf;
  socklen_t length = sizeof(sndbuf);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF, &sndbuf, &length),
      SyscallSucceeds());

  // Make the call too large to fit in the send buffer.
  const int buffer_size = 3 * sndbuf;

  EXPECT_THAT(SendLargeSendMsg(sockets, buffer_size, false /* reader */),
              SyscallFailsWithErrno(EMSGSIZE));
}

// Stream sockets allow data sent with a single (e.g. write, sendmsg) syscall
// to be read in pieces with multiple (e.g. read, recvmsg) syscalls.
//
// SplitRecv checks that control messages can only be read on the first (e.g.
// read, recvmsg) syscall, even if it doesn't provide space for the control
// message.
TEST_P(NonStreamSocketPairTest, SplitRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data) / 2];
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(received_data)));
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_DONTWAIT),
              SyscallFailsWithErrno(EWOULDBLOCK));
}

// Stream sockets allow data sent with multiple sends to be read in a single
// recv. Datagram sockets do not.
//
// SingleRecv checks that only a single message is readable in a single recv.
TEST_P(NonStreamSocketPairTest, SingleRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data1, sizeof(sent_data1), 0),
      SyscallSucceedsWithValue(sizeof(sent_data1)));
  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data2, sizeof(sent_data2), 0),
      SyscallSucceedsWithValue(sizeof(sent_data2)));
  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
}

TEST_P(NonStreamSocketPairTest, RecvmsgMsghdrFlagMsgTrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[10];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data) / 2] = {};

  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  struct msghdr msg = {};
  msg.msg_flags = -1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(received_data, sent_data, sizeof(received_data)));

  // Check that msghdr flags were updated.
  EXPECT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);
}

// Stream sockets allow data sent with multiple sends to be peeked at in a
// single recv. Datagram sockets (except for unix sockets) do not.
//
// SinglePeek checks that only a single message is peekable in a single recv.
TEST_P(NonStreamSocketPairTest, SinglePeek) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data1, sizeof(sent_data1), 0),
      SyscallSucceedsWithValue(sizeof(sent_data1)));
  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data2, sizeof(sent_data2), 0),
      SyscallSucceedsWithValue(sizeof(sent_data2)));
  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];
  for (int i = 0; i < 3; i++) {
    memset(received_data, 0, sizeof(received_data));
    ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                                 sizeof(received_data), MSG_PEEK),
                SyscallSucceedsWithValue(sizeof(sent_data1)));
    EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  }
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(sent_data1), 0),
              SyscallSucceedsWithValue(sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(sent_data2), 0),
              SyscallSucceedsWithValue(sizeof(sent_data2)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data, sizeof(sent_data2)));
}

TEST_P(NonStreamSocketPairTest, MsgTruncTruncation) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data) / 2, MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));

  // Check that we didn't get any extra data.
  EXPECT_NE(0, memcmp(sent_data + sizeof(sent_data) / 2,
                      received_data + sizeof(received_data) / 2,
                      sizeof(sent_data) / 2));
}

TEST_P(NonStreamSocketPairTest, MsgTruncTruncationRecvmsgMsghdrFlagMsgTrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[10];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data) / 2] = {};

  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  struct msghdr msg = {};
  msg.msg_flags = -1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  EXPECT_EQ(0, memcmp(received_data, sent_data, sizeof(received_data)));

  // Check that msghdr flags were updated.
  EXPECT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);
}

TEST_P(NonStreamSocketPairTest, MsgTruncSameSize) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)];
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(NonStreamSocketPairTest, MsgTruncNotFull) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[2 * sizeof(sent_data)];
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

// This test tests reading from a socket with MSG_TRUNC and a zero length
// receive buffer. The user should be able to get the message length.
TEST_P(NonStreamSocketPairTest, RecvmsgMsgTruncZeroLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[10];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  // The receive buffer is of zero length.
  char received_data[0] = {};

  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  struct msghdr msg = {};
  msg.msg_flags = -1;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // The syscall succeeds returning the full size of the message on the socket.
  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  // Check that MSG_TRUNC is set on msghdr flags.
  EXPECT_EQ(msg.msg_flags & MSG_TRUNC, MSG_TRUNC);
}

// This test tests reading from a socket with MSG_TRUNC | MSG_PEEK and a zero
// length receive buffer. The user should be able to get the message length
// without reading data off the socket.
TEST_P(NonStreamSocketPairTest, RecvmsgMsgTruncMsgPeekZeroLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[10];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  // The receive buffer is of zero length.
  char peek_data[0] = {};

  struct iovec peek_iov;
  peek_iov.iov_base = peek_data;
  peek_iov.iov_len = sizeof(peek_data);
  struct msghdr peek_msg = {};
  peek_msg.msg_flags = -1;
  peek_msg.msg_iov = &peek_iov;
  peek_msg.msg_iovlen = 1;

  // The syscall succeeds returning the full size of the message on the socket.
  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &peek_msg,
                                  MSG_TRUNC | MSG_PEEK),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  // Check that MSG_TRUNC is set on msghdr flags because the receive buffer is
  // smaller than the message size.
  EXPECT_EQ(peek_msg.msg_flags & MSG_TRUNC, MSG_TRUNC);

  char received_data[sizeof(sent_data)] = {};

  struct iovec received_iov;
  received_iov.iov_base = received_data;
  received_iov.iov_len = sizeof(received_data);
  struct msghdr received_msg = {};
  received_msg.msg_flags = -1;
  received_msg.msg_iov = &received_iov;
  received_msg.msg_iovlen = 1;

  // Next we can read the actual data.
  ASSERT_THAT(
      RetryEINTR(recvmsg)(sockets->second_fd(), &received_msg, MSG_TRUNC),
      SyscallSucceedsWithValue(sizeof(sent_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  // Check that MSG_TRUNC is not set on msghdr flags because we read the whole
  // message.
  EXPECT_EQ(received_msg.msg_flags & MSG_TRUNC, 0);
}

// This test tests reading from a socket with MSG_TRUNC | MSG_PEEK and a zero
// length receive buffer and MSG_DONTWAIT. The user should be able to get an
// EAGAIN or EWOULDBLOCK error response.
TEST_P(NonStreamSocketPairTest, RecvmsgTruncPeekDontwaitZeroLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // NOTE: We don't send any data on the socket.

  // The receive buffer is of zero length.
  char peek_data[0] = {};

  struct iovec peek_iov;
  peek_iov.iov_base = peek_data;
  peek_iov.iov_len = sizeof(peek_data);
  struct msghdr peek_msg = {};
  peek_msg.msg_flags = -1;
  peek_msg.msg_iov = &peek_iov;
  peek_msg.msg_iovlen = 1;

  // recvmsg fails with EAGAIN because no data is available on the socket.
  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &peek_msg,
                                  MSG_TRUNC | MSG_PEEK | MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

}  // namespace testing
}  // namespace gvisor
