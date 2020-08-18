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

#include "test/syscalls/linux/socket_non_stream_blocking.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

TEST_P(BlockingNonStreamSocketPairTest, RecvLessThanBufferWaitAll) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data) * 2] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_WAITALL),
              SyscallSucceedsWithValue(sizeof(sent_data)));
}

// This test tests reading from a socket with MSG_TRUNC | MSG_PEEK and a zero
// length receive buffer and MSG_DONTWAIT. The recvmsg call should block on
// reading the data.
TEST_P(BlockingNonStreamSocketPairTest,
       RecvmsgTruncPeekDontwaitZeroLenBlocking) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // NOTE: We don't initially send any data on the socket.
  const int data_size = 10;
  char sent_data[data_size];
  RandomizeBuffer(sent_data, data_size);

  // The receive buffer is of zero length.
  char peek_data[0] = {};

  struct iovec peek_iov;
  peek_iov.iov_base = peek_data;
  peek_iov.iov_len = sizeof(peek_data);
  struct msghdr peek_msg = {};
  peek_msg.msg_flags = -1;
  peek_msg.msg_iov = &peek_iov;
  peek_msg.msg_iovlen = 1;

  ScopedThread t([&]() {
    // The syscall succeeds returning the full size of the message on the
    // socket. This should block until there is data on the socket.
    ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &peek_msg,
                                    MSG_TRUNC | MSG_PEEK),
                SyscallSucceedsWithValue(data_size));
  });

  absl::SleepFor(absl::Seconds(1));
  ASSERT_THAT(RetryEINTR(send)(sockets->first_fd(), sent_data, data_size, 0),
              SyscallSucceedsWithValue(data_size));
}

}  // namespace testing
}  // namespace gvisor
