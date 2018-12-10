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

#include "test/syscalls/linux/socket_stream_nonblock.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

using ::testing::Le;

TEST_P(NonBlockingStreamSocketPairTest, SendMsgTooLarge) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int sndbuf;
  socklen_t length = sizeof(sndbuf);
  ASSERT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF, &sndbuf, &length),
      SyscallSucceeds());

  // Make the call too large to fit in the send buffer.
  const int buffer_size = 3 * sndbuf;

  EXPECT_THAT(SendLargeSendMsg(sockets, buffer_size, false /* reader */),
              SyscallSucceedsWithValue(Le(buffer_size)));
}

}  // namespace testing
}  // namespace gvisor
