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

#include "test/syscalls/linux/socket_non_blocking.h"

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST_P(NonBlockingSocketPairTest, ReadNothingAvailable) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char buf[20] = {};
  ASSERT_THAT(ReadFd(sockets->first_fd(), buf, sizeof(buf)),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(NonBlockingSocketPairTest, RecvNothingAvailable) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char buf[20] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(NonBlockingSocketPairTest, RecvMsgNothingAvailable) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct iovec iov;
  char buf[20] = {};
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg, 0),
              SyscallFailsWithErrno(EAGAIN));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
