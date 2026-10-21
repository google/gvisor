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
#include <grp.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

// This file contains tests specific to connecting to host UDS managed outside
// the sandbox / test.
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

// An unprivileged identity with no group of its own on the sockets, so that
// only a supplementary group can grant access.
constexpr uid_t kUnprivilegedUid = 65534;
constexpr gid_t kUnprivilegedGid = 65534;

// Parameter is (socket root dir, ProtocolSocket).
using GoferStreamSeqpacketTest =
    ::testing::TestWithParam<std::tuple<std::string, ProtocolSocket>>;

// Connect to a socket and verify that write/read work.
//
// An "echo" socket doesn't work for dgram sockets because our socket is
// unnamed. The server thus has no way to reply to us.
TEST_P(GoferStreamSeqpacketTest, Echo) {
  std::string env;
  ProtocolSocket proto;
  std::tie(env, proto) = GetParam();

  char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  std::string root(val);

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, proto.protocol, 0));

  std::string socket_path = JoinPath(root, proto.name, "echo");

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  ASSERT_THAT(connect(sock.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());

  constexpr int kBufferSize = 64;
  char send_buffer[kBufferSize];
  memset(send_buffer, 'a', sizeof(send_buffer));

  ASSERT_THAT(WriteFd(sock.get(), send_buffer, sizeof(send_buffer)),
              SyscallSucceedsWithValue(sizeof(send_buffer)));

  char recv_buffer[kBufferSize];
  ASSERT_THAT(ReadFd(sock.get(), recv_buffer, sizeof(recv_buffer)),
              SyscallSucceedsWithValue(sizeof(recv_buffer)));
  ASSERT_EQ(0, memcmp(send_buffer, recv_buffer, sizeof(send_buffer)));
}

// It is not possible to connect to a bound but non-listening socket.
TEST_P(GoferStreamSeqpacketTest, NonListening) {
  std::string env;
  ProtocolSocket proto;
  std::tie(env, proto) = GetParam();

  char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  std::string root(val);

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, proto.protocol, 0));

  std::string socket_path = JoinPath(root, proto.name, "nonlistening");

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  ASSERT_THAT(connect(sock.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallFailsWithErrno(ECONNREFUSED));
}

INSTANTIATE_TEST_SUITE_P(
    StreamSeqpacket, GoferStreamSeqpacketTest,
    ::testing::Combine(
        // Test access via standard path and attach point.
        ::testing::Values("TEST_UDS_TREE", "TEST_UDS_ATTACH_TREE"),
        ::testing::Values(ProtocolSocket{SOCK_STREAM, "stream"},
                          ProtocolSocket{SOCK_SEQPACKET, "seqpacket"})));

// Parameter is socket root dir.
using GoferDgramTest = ::testing::TestWithParam<std::string>;

// Connect to a socket and verify that write works.
//
// An "echo" socket doesn't work for dgram sockets because our socket is
// unnamed. The server thus has no way to reply to us.
TEST_P(GoferDgramTest, Null) {
  std::string env = GetParam();
  char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  std::string root(val);

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_DGRAM, 0));

  std::string socket_path = JoinPath(root, "dgram/null");

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  ASSERT_THAT(connect(sock.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());

  constexpr int kBufferSize = 64;
  char send_buffer[kBufferSize];
  memset(send_buffer, 'a', sizeof(send_buffer));

  ASSERT_THAT(WriteFd(sock.get(), send_buffer, sizeof(send_buffer)),
              SyscallSucceedsWithValue(sizeof(send_buffer)));
}

INSTANTIATE_TEST_SUITE_P(Dgram, GoferDgramTest,
                         // Test access via standard path and attach point.
                         ::testing::Values("TEST_UDS_TREE",
                                           "TEST_UDS_ATTACH_TREE"));

// Connect to a socket that only its group may reach, holding that group as a
// supplementary group, as a user in the docker group does for docker.sock.
TEST(GoferStreamTest, ConnectWithSupplementaryGroup) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETGID)));

  char* val = getenv("TEST_UDS_TREE");
  ASSERT_NE(val, nullptr);
  std::string socket_path = JoinPath(val, "stream", "echo-group");

  struct stat st;
  ASSERT_THAT(stat(socket_path.c_str(), &st), SyscallSucceeds());
  const gid_t group = st.st_gid;
  // Only the socket's group may reach it, and that group is one this test does
  // not hold as its gid.
  SKIP_IF((st.st_mode & 0777) != 0660 || group == kUnprivilegedGid);

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.length());

  // With the socket's group as a supplementary group, connect succeeds.
  EXPECT_THAT(
      InForkedProcess([&] {
        TEST_PCHECK(setgroups(1, &group) == 0);
        TEST_PCHECK(setresgid(kUnprivilegedGid, kUnprivilegedGid,
                              kUnprivilegedGid) == 0);
        TEST_PCHECK(setresuid(kUnprivilegedUid, kUnprivilegedUid,
                              kUnprivilegedUid) == 0);
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        TEST_PCHECK(sock >= 0);
        TEST_PCHECK(connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                            sizeof(addr)) == 0);
      }),
      IsPosixErrorOkAndHolds(0));

  // Without it, connect fails.
  EXPECT_THAT(InForkedProcess([&] {
                TEST_PCHECK(setgroups(0, nullptr) == 0);
                TEST_PCHECK(setresgid(kUnprivilegedGid, kUnprivilegedGid,
                                      kUnprivilegedGid) == 0);
                TEST_PCHECK(setresuid(kUnprivilegedUid, kUnprivilegedUid,
                                      kUnprivilegedUid) == 0);
                int sock = socket(AF_UNIX, SOCK_STREAM, 0);
                TEST_PCHECK(sock >= 0);
                TEST_CHECK_ERRNO(
                    connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                            sizeof(addr)),
                    EACCES);
              }),
              IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
