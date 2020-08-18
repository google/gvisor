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

#include "test/syscalls/linux/socket_unix_seqpacket.h"

#include <stdio.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(SeqpacketUnixSocketPairTest, WriteOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  constexpr char kStr[] = "abc";
  ASSERT_THAT(write(sockets->second_fd(), kStr, 3),
              SyscallFailsWithErrno(EPIPE));
}

TEST_P(SeqpacketUnixSocketPairTest, ReadOneSideClosed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(close(sockets->release_first_fd()), SyscallSucceeds());
  char data[10] = {};
  ASSERT_THAT(read(sockets->second_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(0));
}

TEST_P(SeqpacketUnixSocketPairTest, Sendto) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "\0nonexistent";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  constexpr char kStr[] = "abc";
  ASSERT_THAT(sendto(sockets->second_fd(), kStr, 3, 0, (struct sockaddr*)&addr,
                     sizeof(addr)),
              SyscallSucceedsWithValue(3));

  char data[10] = {};
  ASSERT_THAT(read(sockets->first_fd(), data, sizeof(data)),
              SyscallSucceedsWithValue(3));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
