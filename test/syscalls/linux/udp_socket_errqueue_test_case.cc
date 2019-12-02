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

#include "test/syscalls/linux/udp_socket_test_cases.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

TEST_P(UdpSocketTest, ErrorQueue) {
  char cmsgbuf[CMSG_SPACE(sizeof(sock_extended_err))];
  msghdr msg;
  memset(&msg, 0, sizeof(msg));
  iovec iov;
  memset(&iov, 0, sizeof(iov));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);

  // recv*(MSG_ERRQUEUE) never blocks, even without MSG_DONTWAIT.
  EXPECT_THAT(RetryEINTR(recvmsg)(s_, &msg, MSG_ERRQUEUE),
              SyscallFailsWithErrno(EAGAIN));
}

}  // namespace testing
}  // namespace gvisor
