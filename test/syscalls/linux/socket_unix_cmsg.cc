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

#include "test/syscalls/linux/socket_unix_cmsg.h"

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <vector>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// This file contains tests for control message in Unix domain sockets.
//
// This file is a generic socket test file. It must be built with another file
// that provides the test types.

namespace gvisor {
namespace testing {

namespace {

TEST_P(UnixSocketPairCmsgTest, BasicFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char received_data[20];
  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvSingleFD(sockets->second_fd(), &fd, received_data,
                                       sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
}

TEST_P(UnixSocketPairCmsgTest, BasicTwoFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair1 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  auto pair2 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  int sent_fds[] = {pair1->second_fd(), pair2->second_fd()};

  ASSERT_NO_FATAL_FAILURE(
      SendFDs(sockets->first_fd(), sent_fds, 2, sent_data, sizeof(sent_data)));

  char received_data[20];
  int received_fds[] = {-1, -1};

  ASSERT_NO_FATAL_FAILURE(RecvFDs(sockets->second_fd(), received_fds, 2,
                                  received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  ASSERT_NO_FATAL_FAILURE(TransferTest(received_fds[0], pair1->first_fd()));
  ASSERT_NO_FATAL_FAILURE(TransferTest(received_fds[1], pair2->first_fd()));
}

TEST_P(UnixSocketPairCmsgTest, BasicThreeFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair1 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  auto pair2 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  auto pair3 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  int sent_fds[] = {pair1->second_fd(), pair2->second_fd(), pair3->second_fd()};

  ASSERT_NO_FATAL_FAILURE(
      SendFDs(sockets->first_fd(), sent_fds, 3, sent_data, sizeof(sent_data)));

  char received_data[20];
  int received_fds[] = {-1, -1, -1};

  ASSERT_NO_FATAL_FAILURE(RecvFDs(sockets->second_fd(), received_fds, 3,
                                  received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  ASSERT_NO_FATAL_FAILURE(TransferTest(received_fds[0], pair1->first_fd()));
  ASSERT_NO_FATAL_FAILURE(TransferTest(received_fds[1], pair2->first_fd()));
  ASSERT_NO_FATAL_FAILURE(TransferTest(received_fds[2], pair3->first_fd()));
}

TEST_P(UnixSocketPairCmsgTest, BadFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  int sent_fd = -1;

  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(sent_fd))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(sent_fd));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  memcpy(CMSG_DATA(cmsg), &sent_fd, sizeof(sent_fd));

  struct iovec iov;
  iov.iov_base = sent_data;
  iov.iov_len = sizeof(sent_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(sendmsg)(sockets->first_fd(), &msg, 0),
              SyscallFailsWithErrno(EBADF));
}

// BasicFDPassNoSpace starts off by sending a single FD just like BasicFDPass.
// The difference is that when calling recvmsg, no space for FDs is provided,
// only space for the cmsg header.
TEST_P(UnixSocketPairCmsgTest, BasicFDPassNoSpace) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char received_data[20];

  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(0));
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_controllen, 0);
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

// BasicFDPassNoSpaceMsgCtrunc sends an FD, but does not provide any space to
// receive it. It then verifies that the MSG_CTRUNC flag is set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, BasicFDPassNoSpaceMsgCtrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(0));
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  char received_data[sizeof(sent_data)];
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_controllen, 0);
  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);
}

// BasicFDPassNullControlMsgCtrunc sends an FD and sets contradictory values for
// msg_controllen and msg_control. msg_controllen is set to the correct size to
// accommodate the FD, but msg_control is set to NULL. In this case, msg_control
// should override msg_controllen.
TEST_P(UnixSocketPairCmsgTest, BasicFDPassNullControlMsgCtrunc) {
  // FIXME(gvisor.dev/issue/207): Fix handling of NULL msg_control.
  SKIP_IF(IsRunningOnGvisor());

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  msg.msg_controllen = CMSG_SPACE(1);

  char received_data[sizeof(sent_data)];
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_controllen, 0);
  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);
}

// BasicFDPassNotEnoughSpaceMsgCtrunc sends an FD, but does not provide enough
// space to receive it. It then verifies that the MSG_CTRUNC flag is set in the
// msghdr.
TEST_P(UnixSocketPairCmsgTest, BasicFDPassNotEnoughSpaceMsgCtrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(0) + 1);
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  char received_data[sizeof(sent_data)];
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_controllen, 0);
  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);
}

// BasicThreeFDPassTruncationMsgCtrunc sends three FDs, but only provides enough
// space to receive two of them. It then verifies that the MSG_CTRUNC flag is
// set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, BasicThreeFDPassTruncationMsgCtrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair1 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  auto pair2 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  auto pair3 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  int sent_fds[] = {pair1->second_fd(), pair2->second_fd(), pair3->second_fd()};

  ASSERT_NO_FATAL_FAILURE(
      SendFDs(sockets->first_fd(), sent_fds, 3, sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(2 * sizeof(int)));
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  char received_data[sizeof(sent_data)];
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(2 * sizeof(int)));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_RIGHTS);
}

// BasicFDPassUnalignedRecv starts off by sending a single FD just like
// BasicFDPass. The difference is that when calling recvmsg, the length of the
// receive data is only aligned on a 4 byte boundry instead of the normal 8.
TEST_P(UnixSocketPairCmsgTest, BasicFDPassUnalignedRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char received_data[20];
  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvSingleFDUnaligned(
      sockets->second_fd(), &fd, received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
}

// BasicFDPassUnalignedRecvNoMsgTrunc sends one FD and only provides enough
// space to receive just it. (Normally the minimum amount of space one would
// provide would be enough space for two FDs.) It then verifies that the
// MSG_CTRUNC flag is not set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, BasicFDPassUnalignedRecvNoMsgTrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int)) - sizeof(int)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[sizeof(sent_data)] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_flags, 0);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_RIGHTS);
}

// BasicTwoFDPassUnalignedRecvTruncationMsgTrunc sends two FDs, but only
// provides enough space to receive one of them. It then verifies that the
// MSG_CTRUNC flag is set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, BasicTwoFDPassUnalignedRecvTruncationMsgTrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  int sent_fds[] = {pair->first_fd(), pair->second_fd()};

  ASSERT_NO_FATAL_FAILURE(
      SendFDs(sockets->first_fd(), sent_fds, 2, sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  // CMSG_SPACE rounds up to two FDs, we only want one.
  char control[CMSG_SPACE(sizeof(int)) - sizeof(int)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[sizeof(sent_data)] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_RIGHTS);
}

TEST_P(UnixSocketPairCmsgTest, ConcurrentBasicFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  int sockfd1 = sockets->first_fd();
  auto recv_func = [sockfd1, sent_data]() {
    char received_data[20];
    int fd = -1;
    RecvSingleFD(sockfd1, &fd, received_data, sizeof(received_data));
    ASSERT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
    char buf[20];
    ASSERT_THAT(ReadFd(fd, buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
    ASSERT_THAT(WriteFd(fd, buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
  };

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->second_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  ScopedThread t(recv_func);

  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(WriteFd(pair->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[20];
  ASSERT_THAT(ReadFd(pair->first_fd(), received_data, sizeof(received_data)),
              SyscallSucceedsWithValue(sizeof(received_data)));

  t.Join();

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

// FDPassNoRecv checks that the control message can be safely ignored by using
// read(2) instead of recvmsg(2).
TEST_P(UnixSocketPairCmsgTest, FDPassNoRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  // Read while ignoring the passed FD.
  char received_data[20];
  ASSERT_THAT(
      ReadFd(sockets->second_fd(), received_data, sizeof(received_data)),
      SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  // Check that the socket still works for reads and writes.
  ASSERT_NO_FATAL_FAILURE(
      TransferTest(sockets->first_fd(), sockets->second_fd()));
}

// FDPassInterspersed1 checks that sent control messages cannot be read before
// their associated data has been read.
TEST_P(UnixSocketPairCmsgTest, FDPassInterspersed1) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char written_data[20];
  RandomizeBuffer(written_data, sizeof(written_data));

  ASSERT_THAT(WriteFd(sockets->first_fd(), written_data, sizeof(written_data)),
              SyscallSucceedsWithValue(sizeof(written_data)));

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  // Check that we don't get a control message, but do get the data.
  char received_data[20];
  RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data));
  EXPECT_EQ(0, memcmp(written_data, received_data, sizeof(written_data)));
}

// FDPassInterspersed2 checks that sent control messages cannot be read after
// their associated data has been read while ignoring the control message by
// using read(2) instead of recvmsg(2).
TEST_P(UnixSocketPairCmsgTest, FDPassInterspersed2) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char written_data[20];
  RandomizeBuffer(written_data, sizeof(written_data));
  ASSERT_THAT(WriteFd(sockets->first_fd(), written_data, sizeof(written_data)),
              SyscallSucceedsWithValue(sizeof(written_data)));

  char received_data[20];
  ASSERT_THAT(
      ReadFd(sockets->second_fd(), received_data, sizeof(received_data)),
      SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));
  EXPECT_EQ(0, memcmp(written_data, received_data, sizeof(written_data)));
}

TEST_P(UnixSocketPairCmsgTest, FDPassNotCoalesced) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  auto pair1 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair1->second_fd(),
                                       sent_data1, sizeof(sent_data1)));

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  auto pair2 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair2->second_fd(),
                                       sent_data2, sizeof(sent_data2)));

  char received_data1[sizeof(sent_data1) + sizeof(sent_data2)];
  int received_fd1 = -1;

  RecvSingleFD(sockets->second_fd(), &received_fd1, received_data1,
               sizeof(received_data1), sizeof(sent_data1));

  EXPECT_EQ(0, memcmp(sent_data1, received_data1, sizeof(sent_data1)));
  TransferTest(pair1->first_fd(), pair1->second_fd());

  char received_data2[sizeof(sent_data1) + sizeof(sent_data2)];
  int received_fd2 = -1;

  RecvSingleFD(sockets->second_fd(), &received_fd2, received_data2,
               sizeof(received_data2), sizeof(sent_data2));

  EXPECT_EQ(0, memcmp(sent_data2, received_data2, sizeof(sent_data2)));
  TransferTest(pair2->first_fd(), pair2->second_fd());
}

TEST_P(UnixSocketPairCmsgTest, FDPassPeek) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char peek_data[20];
  int peek_fd = -1;
  PeekSingleFD(sockets->second_fd(), &peek_fd, peek_data, sizeof(peek_data));
  EXPECT_EQ(0, memcmp(sent_data, peek_data, sizeof(sent_data)));
  TransferTest(peek_fd, pair->first_fd());
  EXPECT_THAT(close(peek_fd), SyscallSucceeds());

  char received_data[20];
  int received_fd = -1;
  RecvSingleFD(sockets->second_fd(), &received_fd, received_data,
               sizeof(received_data));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
  TransferTest(received_fd, pair->first_fd());
  EXPECT_THAT(close(received_fd), SyscallSucceeds());
}

TEST_P(UnixSocketPairCmsgTest, BasicCredPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];
  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
  EXPECT_EQ(sent_creds.pid, received_creds.pid);
  EXPECT_EQ(sent_creds.uid, received_creds.uid);
  EXPECT_EQ(sent_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, SendNullCredsBeforeSoPassCredRecvEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];
  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, SendNullCredsAfterSoPassCredRecvEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  SetSoPassCred(sockets->second_fd());

  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data, sizeof(sent_data)));

  char received_data[20];
  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, SendNullCredsBeforeSoPassCredSendEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->first_fd());

  char received_data[20];
  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(UnixSocketPairCmsgTest, SendNullCredsAfterSoPassCredSendEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  SetSoPassCred(sockets->first_fd());

  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data, sizeof(sent_data)));

  char received_data[20];
  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(UnixSocketPairCmsgTest,
       SendNullCredsBeforeSoPassCredRecvEndAfterSendEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  SetSoPassCred(sockets->first_fd());

  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];
  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, WriteBeforeSoPassCredRecvEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];

  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, WriteAfterSoPassCredRecvEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->second_fd());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[20];

  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, WriteBeforeSoPassCredSendEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  SetSoPassCred(sockets->first_fd());

  char received_data[20];
  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(UnixSocketPairCmsgTest, WriteAfterSoPassCredSendEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->first_fd());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[20];
  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(UnixSocketPairCmsgTest, WriteBeforeSoPassCredRecvEndAfterSendEnd) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  SetSoPassCred(sockets->first_fd());

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];

  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixSocketPairCmsgTest, CredPassTruncated) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  struct msghdr msg = {};
  char control[CMSG_SPACE(0) + sizeof(pid_t)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[sizeof(sent_data)] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  EXPECT_EQ(msg.msg_controllen, sizeof(control));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, sizeof(control));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);

  pid_t pid = 0;
  memcpy(&pid, CMSG_DATA(cmsg), sizeof(pid));
  EXPECT_EQ(pid, sent_creds.pid);
}

// CredPassNoMsgCtrunc passes a full set of credentials. It then verifies that
// receiving the full set does not result in MSG_CTRUNC being set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, CredPassNoMsgCtrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(struct ucred))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[sizeof(sent_data)] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  // The control message should not be truncated.
  EXPECT_EQ(msg.msg_flags, 0);
  EXPECT_EQ(msg.msg_controllen, sizeof(control));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(struct ucred)));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);
}

// CredPassNoSpaceMsgCtrunc passes a full set of credentials. It then receives
// the data without providing space for any credentials and verifies that
// MSG_CTRUNC is set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, CredPassNoSpaceMsgCtrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  struct msghdr msg = {};
  char control[CMSG_SPACE(0)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[sizeof(sent_data)] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  // The control message should be truncated.
  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);
  EXPECT_EQ(msg.msg_controllen, sizeof(control));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, sizeof(control));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);
}

// CredPassTruncatedMsgCtrunc passes a full set of credentials. It then receives
// the data while providing enough space for only the first field of the
// credentials and verifies that MSG_CTRUNC is set in the msghdr.
TEST_P(UnixSocketPairCmsgTest, CredPassTruncatedMsgCtrunc) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  struct msghdr msg = {};
  char control[CMSG_SPACE(0) + sizeof(pid_t)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[sizeof(sent_data)] = {};
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  // The control message should be truncated.
  EXPECT_EQ(msg.msg_flags, MSG_CTRUNC);
  EXPECT_EQ(msg.msg_controllen, sizeof(control));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, sizeof(control));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);
}

TEST_P(UnixSocketPairCmsgTest, SoPassCred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  int opt;
  socklen_t optLen = sizeof(opt);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_PASSCRED, &opt, &optLen),
      SyscallSucceeds());
  EXPECT_FALSE(opt);

  optLen = sizeof(opt);
  EXPECT_THAT(
      getsockopt(sockets->second_fd(), SOL_SOCKET, SO_PASSCRED, &opt, &optLen),
      SyscallSucceeds());
  EXPECT_FALSE(opt);

  SetSoPassCred(sockets->first_fd());

  optLen = sizeof(opt);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_PASSCRED, &opt, &optLen),
      SyscallSucceeds());
  EXPECT_TRUE(opt);

  optLen = sizeof(opt);
  EXPECT_THAT(
      getsockopt(sockets->second_fd(), SOL_SOCKET, SO_PASSCRED, &opt, &optLen),
      SyscallSucceeds());
  EXPECT_FALSE(opt);

  int zero = 0;
  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_PASSCRED, &zero,
                         sizeof(zero)),
              SyscallSucceeds());

  optLen = sizeof(opt);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_PASSCRED, &opt, &optLen),
      SyscallSucceeds());
  EXPECT_FALSE(opt);

  optLen = sizeof(opt);
  EXPECT_THAT(
      getsockopt(sockets->second_fd(), SOL_SOCKET, SO_PASSCRED, &opt, &optLen),
      SyscallSucceeds());
  EXPECT_FALSE(opt);
}

TEST_P(UnixSocketPairCmsgTest, NoDataCredPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct msghdr msg = {};

  struct iovec iov;
  iov.iov_base = sent_data;
  iov.iov_len = sizeof(sent_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  char control[CMSG_SPACE(0)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_CREDENTIALS;
  cmsg->cmsg_len = CMSG_LEN(0);

  ASSERT_THAT(RetryEINTR(sendmsg)(sockets->first_fd(), &msg, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(UnixSocketPairCmsgTest, NoPassCred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  char received_data[20];

  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(UnixSocketPairCmsgTest, CredAndFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendCredsAndFD(sockets->first_fd(), sent_creds,
                                         pair->second_fd(), sent_data,
                                         sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];
  struct ucred received_creds;
  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvCredsAndFD(sockets->second_fd(), &received_creds,
                                         &fd, received_data,
                                         sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  EXPECT_EQ(sent_creds.pid, received_creds.pid);
  EXPECT_EQ(sent_creds.uid, received_creds.uid);
  EXPECT_EQ(sent_creds.gid, received_creds.gid);

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
}

TEST_P(UnixSocketPairCmsgTest, FDPassBeforeSoPassCred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  SetSoPassCred(sockets->second_fd());

  char received_data[20];
  struct ucred received_creds;
  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvCredsAndFD(sockets->second_fd(), &received_creds,
                                         &fd, received_data,
                                         sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
}

TEST_P(UnixSocketPairCmsgTest, FDPassAfterSoPassCred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  SetSoPassCred(sockets->second_fd());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char received_data[20];
  struct ucred received_creds;
  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvCredsAndFD(sockets->second_fd(), &received_creds,
                                         &fd, received_data,
                                         sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
}

TEST_P(UnixSocketPairCmsgTest, CloexecDroppedWhenFDPassed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair = ASSERT_NO_ERRNO_AND_VALUE(
      UnixDomainSocketPair(SOCK_SEQPACKET | SOCK_CLOEXEC).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char received_data[20];
  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvSingleFD(sockets->second_fd(), &fd, received_data,
                                       sizeof(received_data)));

  EXPECT_THAT(fcntl(fd, F_GETFD), SyscallSucceedsWithValue(0));
}

TEST_P(UnixSocketPairCmsgTest, CloexecRecvFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  char received_data[20];
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, MSG_CMSG_CLOEXEC),
              SyscallSucceedsWithValue(sizeof(received_data)));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS);

  int fd = -1;
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

  EXPECT_THAT(fcntl(fd, F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
}

TEST_P(UnixSocketPairCmsgTest, FDPassAfterSoPassCredWithoutCredSpace) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  SetSoPassCred(sockets->second_fd());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  char control[CMSG_LEN(0)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[20];
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  EXPECT_EQ(msg.msg_controllen, sizeof(control));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  EXPECT_EQ(cmsg->cmsg_len, sizeof(control));
  EXPECT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  EXPECT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);
}

// This test will validate that MSG_CTRUNC as an input flag to recvmsg will
// not appear as an output flag on the control message when truncation doesn't
// happen.
TEST_P(UnixSocketPairCmsgTest, MsgCtruncInputIsNoop) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int)) /* we're passing a single fd */];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  char received_data[20];
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, MSG_CTRUNC),
              SyscallSucceedsWithValue(sizeof(received_data)));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS);

  // Now we should verify that MSG_CTRUNC wasn't set as an output flag.
  EXPECT_EQ(msg.msg_flags & MSG_CTRUNC, 0);
}

TEST_P(UnixSocketPairCmsgTest, FDPassAfterSoPassCredWithoutCredHeaderSpace) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  SetSoPassCred(sockets->second_fd());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  struct msghdr msg = {};
  char control[CMSG_LEN(0) / 2];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  char received_data[20];
  struct iovec iov;
  iov.iov_base = received_data;
  iov.iov_len = sizeof(received_data);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
  EXPECT_EQ(msg.msg_controllen, 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
