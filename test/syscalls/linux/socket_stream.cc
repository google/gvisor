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

#include "test/syscalls/linux/socket_stream.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST_P(StreamSocketPairTest, SplitRecv) {
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
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data + sizeof(received_data), received_data,
                      sizeof(received_data)));
}

// Stream sockets allow data sent with multiple sends to be read in a single
// recv.
//
// CoalescedRecv checks that multiple messages are readable in a single recv.
TEST_P(StreamSocketPairTest, CoalescedRecv) {
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
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data + sizeof(sent_data1),
                      sizeof(sent_data2)));
}

TEST_P(StreamSocketPairTest, WriteOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  const char str[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), str, 3),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(StreamSocketPairTest, RecvmsgMsghdrFlagsNoMsgTrunc) {
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

  // Check that msghdr flags were cleared (MSG_TRUNC was not set).
  EXPECT_EQ(msg.msg_flags, 0);
}

TEST_P(StreamSocketPairTest, MsgTrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)];
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data) / 2, MSG_TRUNC),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));
}

}  // namespace testing
}  // namespace gvisor
