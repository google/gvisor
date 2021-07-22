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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <algorithm>
#include <vector>

#include "gtest/gtest.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST_P(AllSocketPairTest, Listen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenIncreaseBacklog) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
  ASSERT_THAT(listen(sockets->first_fd(), 10), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenDecreaseBacklog) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
  ASSERT_THAT(listen(sockets->first_fd(), 1), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ListenBacklogSizes) {
  DisableSave ds;
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  int type;
  socklen_t typelen = sizeof(type);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &typelen),
      SyscallSucceeds());

  std::array<int, 3> backlogs = {-1, 0, 1};
  for (auto& backlog : backlogs) {
    ASSERT_THAT(listen(sockets->first_fd(), backlog), SyscallSucceeds());

    int expected_accepts = backlog;
    if (backlog < 0) {
      expected_accepts = 1024;
    }
    for (int i = 0; i < expected_accepts; i++) {
      SCOPED_TRACE(absl::StrCat("i=", i));
      // Connect to the listening socket.
      const FileDescriptor client =
          ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));
      ASSERT_THAT(connect(client.get(), sockets->first_addr(),
                          sockets->first_addr_size()),
                  SyscallSucceeds());
      const FileDescriptor accepted = ASSERT_NO_ERRNO_AND_VALUE(
          Accept(sockets->first_fd(), nullptr, nullptr));
    }
  }
}

TEST_P(AllSocketPairTest, ListenWithoutBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  ASSERT_THAT(listen(sockets->first_fd(), 0), SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, DoubleBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, BindListenBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, DoubleListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, DoubleConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(EISCONN));
}

TEST_P(AllSocketPairTest, Connect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ConnectWithWrongType) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int type;
  socklen_t typelen = sizeof(type);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_TYPE, &type, &typelen),
      SyscallSucceeds());
  switch (type) {
    case SOCK_STREAM:
      type = SOCK_SEQPACKET;
      break;
    case SOCK_SEQPACKET:
      type = SOCK_STREAM;
      break;
  }

  const FileDescriptor another_socket =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, type, 0));

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  if (sockets->first_addr()->sa_data[0] != 0) {
    ASSERT_THAT(connect(another_socket.get(), sockets->first_addr(),
                        sockets->first_addr_size()),
                SyscallFailsWithErrno(EPROTOTYPE));
  } else {
    ASSERT_THAT(connect(another_socket.get(), sockets->first_addr(),
                        sockets->first_addr_size()),
                SyscallFailsWithErrno(ECONNREFUSED));
  }

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, ConnectNonListening) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, ConnectToFilePath) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "/tmp";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  ASSERT_THAT(
      connect(sockets->second_fd(),
              reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, ConnectToInvalidAbstractPath) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "\0nonexistent";
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  ASSERT_THAT(
      connect(sockets->second_fd(),
              reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, SelfConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->first_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, ConnectWithoutListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallFailsWithErrno(ECONNREFUSED));
}

TEST_P(AllSocketPairTest, Accept) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptValidAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  struct sockaddr_un addr = {};
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(
      accepted = accept(sockets->first_fd(), AsSockAddr(&addr), &addr_len),
      SyscallSucceeds());
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptNegativeAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // With a negative addr_len, accept returns EINVAL,
  struct sockaddr_un addr = {};
  socklen_t addr_len = -1;
  ASSERT_THAT(accept(sockets->first_fd(), AsSockAddr(&addr), &addr_len),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, AcceptLargePositiveAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // With a large (positive) addr_len, accept does not return EINVAL.
  int accepted = -1;
  char addr_buf[200];
  socklen_t addr_len = sizeof(addr_buf);
  ASSERT_THAT(accepted = accept(sockets->first_fd(),
                                reinterpret_cast<struct sockaddr*>(addr_buf),
                                &addr_len),
              SyscallSucceeds());
  // addr_len should have been updated by accept().
  EXPECT_LT(addr_len, sizeof(addr_buf));
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptVeryLargePositiveAddrLen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  // With a large (positive) addr_len, accept does not return EINVAL.
  int accepted = -1;
  char addr_buf[2000];
  socklen_t addr_len = sizeof(addr_buf);
  ASSERT_THAT(accepted = accept(sockets->first_fd(),
                                reinterpret_cast<struct sockaddr*>(addr_buf),
                                &addr_len),
              SyscallSucceeds());
  // addr_len should have been updated by accept().
  EXPECT_LT(addr_len, sizeof(addr_buf));
  ASSERT_THAT(close(accepted), SyscallSucceeds());
}

TEST_P(AllSocketPairTest, AcceptWithoutBind) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(accept(sockets->first_fd(), nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, AcceptWithoutListen) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());
  ASSERT_THAT(accept(sockets->first_fd(), nullptr, nullptr),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, GetRemoteAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addr_len = sockets->first_addr_size();
  struct sockaddr_storage addr = {};
  ASSERT_THAT(
      getpeername(sockets->second_fd(), (struct sockaddr*)(&addr), &addr_len),
      SyscallSucceeds());
  EXPECT_EQ(addr_len, sockets->first_addr_len());
  EXPECT_EQ(0, memcmp(&addr, sockets->first_addr(), sockets->first_addr_len()));
}

TEST_P(AllSocketPairTest, UnboundGetLocalAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addr_len = sockets->first_addr_size();
  struct sockaddr_storage addr = {};
  ASSERT_THAT(
      getsockname(sockets->second_fd(), (struct sockaddr*)(&addr), &addr_len),
      SyscallSucceeds());
  EXPECT_EQ(addr_len, 2);
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BoundGetLocalAddress) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  socklen_t addr_len = sockets->first_addr_size();
  struct sockaddr_storage addr = {};
  ASSERT_THAT(
      getsockname(sockets->second_fd(), (struct sockaddr*)(&addr), &addr_len),
      SyscallSucceeds());
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BoundConnector) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, UnboundSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, 0);
}

TEST_P(AllSocketPairTest, BoundSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BindAfterConnectSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

TEST_P(AllSocketPairTest, BindAfterAcceptSenderAddr) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  ASSERT_THAT(listen(sockets->first_fd(), 5), SyscallSucceeds());

  ASSERT_THAT(connect(sockets->second_fd(), sockets->first_addr(),
                      sockets->first_addr_size()),
              SyscallSucceeds());

  int accepted = -1;
  ASSERT_THAT(accepted = accept(sockets->first_fd(), nullptr, nullptr),
              SyscallSucceeds());
  FileDescriptor accepted_fd(accepted);

  ASSERT_THAT(bind(sockets->second_fd(), sockets->second_addr(),
                   sockets->second_addr_size()),
              SyscallSucceeds());

  int i = 0;
  ASSERT_THAT(RetryEINTR(send)(sockets->second_fd(), &i, sizeof(i), 0),
              SyscallSucceedsWithValue(sizeof(i)));

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  ASSERT_THAT(RetryEINTR(recvfrom)(accepted_fd.get(), &i, sizeof(i), 0,
                                   AsSockAddr(&addr), &addr_len),
              SyscallSucceedsWithValue(sizeof(i)));
  EXPECT_EQ(addr_len, sockets->second_addr_len());
  EXPECT_EQ(
      memcmp(&addr, sockets->second_addr(),
             std::min((size_t)addr_len, (size_t)sockets->second_addr_len())),
      0);
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, AllSocketPairTest,
    ::testing::ValuesIn(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(
            FilesystemUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM, SOCK_SEQPACKET},
                                   List<int>{0, SOCK_NONBLOCK})))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
