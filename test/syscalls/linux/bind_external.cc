// Copyright 2019 The gVisor Authors.
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
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cstring>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// This file contains tests specific to binding to host UDS that will be
// connected to from outside the sandbox / test.
//
// A set of ultity sockets will be created externally in $TEST_UDS_TREE and
// $TEST_UDS_ATTACH_TREE for these tests to interact with.

namespace gvisor {
namespace testing {

namespace {

struct ProtocolSocket {
  int protocol;
  std::string name;
};

// Parameter is (socket root dir, ProtocolSocket).
using GoferStreamSeqpacketTest =
    ::testing::TestWithParam<std::tuple<std::string, ProtocolSocket>>;

// Bind to a socket, then Listen and Accept.
TEST_P(GoferStreamSeqpacketTest, BindListenAccept) {
  std::string env;
  ProtocolSocket proto;
  std::tie(env, proto) = GetParam();

  char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  std::string root(val);

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, proto.protocol, 0));

  std::string socket_path = JoinPath(root, proto.name, "created-in-sandbox");

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  ASSERT_THAT(
      bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
      SyscallSucceeds());
  ASSERT_THAT(listen(sock.get(), 1), SyscallSucceeds());

  // Bind again on that socket with a diff address should fail.
  std::string socket_path2 = socket_path + "-fail";
  struct sockaddr_un addr2 = {};
  addr2.sun_family = AF_UNIX;
  memcpy(addr2.sun_path, socket_path2.c_str(), socket_path2.length());
  ASSERT_THAT(bind(sock.get(), reinterpret_cast<struct sockaddr*>(&addr2),
                   sizeof(addr2)),
              SyscallFailsWithErrno(EINVAL));

  FileDescriptor accSock =
      ASSERT_NO_ERRNO_AND_VALUE(Accept(sock.get(), NULL, NULL));

  // Other socket should be echo server.
  constexpr int kBufferSize = 64;
  char send_buffer[kBufferSize];
  memset(send_buffer, 'a', sizeof(send_buffer));

  ASSERT_THAT(WriteFd(accSock.get(), send_buffer, sizeof(send_buffer)),
              SyscallSucceedsWithValue(sizeof(send_buffer)));

  char recv_buffer[kBufferSize];
  ASSERT_THAT(ReadFd(accSock.get(), recv_buffer, sizeof(recv_buffer)),
              SyscallSucceedsWithValue(sizeof(recv_buffer)));
  ASSERT_EQ(0, memcmp(send_buffer, recv_buffer, sizeof(send_buffer)));
}

INSTANTIATE_TEST_SUITE_P(
    StreamSeqpacket, GoferStreamSeqpacketTest,
    ::testing::Combine(::testing::Values("TEST_CONNECTOR_TREE"),
                       ::testing::Values(ProtocolSocket{SOCK_STREAM, "stream"},
                                         ProtocolSocket{SOCK_SEQPACKET,
                                                        "seqpacket"})));

}  // namespace

}  // namespace testing
}  // namespace gvisor
