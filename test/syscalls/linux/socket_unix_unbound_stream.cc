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

#include <stdio.h>
#include <sys/un.h>
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for tests that apply to pairs of connected unix stream sockets.
using UnixStreamSocketPairTest = SocketPairTest;

// FDPassPartialRead checks that sent control messages cannot be read after
// any of their assocated data has been read while ignoring the control message
// by using read(2) instead of recvmsg(2).
TEST_P(UnixStreamSocketPairTest, FDPassPartialRead) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data)));

  char received_data[sizeof(sent_data) / 2];
  ASSERT_THAT(
      ReadFd(sockets->second_fd(), received_data, sizeof(received_data)),
      SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(received_data)));

  RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data));
  EXPECT_EQ(0, memcmp(sent_data + sizeof(received_data), received_data,
                      sizeof(received_data)));
}

TEST_P(UnixStreamSocketPairTest, FDPassCoalescedRead) {
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

  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];
  ASSERT_THAT(
      ReadFd(sockets->second_fd(), received_data, sizeof(received_data)),
      SyscallSucceedsWithValue(sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data + sizeof(sent_data1),
                      sizeof(sent_data2)));
}

// ZeroLengthMessageFDDiscarded checks that control messages associated with
// zero length messages are discarded.
TEST_P(UnixStreamSocketPairTest, ZeroLengthMessageFDDiscarded) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Zero length arrays are invalid in ISO C++, so allocate one of size 1 and
  // send a length of 0.
  char sent_data1[1] = {};

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(
      SendSingleFD(sockets->first_fd(), pair->second_fd(), sent_data1, 0));

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  char received_data[sizeof(sent_data2)] = {};

  RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data));
  EXPECT_EQ(0, memcmp(sent_data2, received_data, sizeof(received_data)));
}

// FDPassCoalescedRecv checks that control messages not in the first message are
// preserved in a coalesced recv.
TEST_P(UnixStreamSocketPairTest, FDPassCoalescedRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data) / 2),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data + sizeof(sent_data) / 2,
                                       sizeof(sent_data) / 2));

  char received_data[sizeof(sent_data)];

  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvSingleFD(sockets->second_fd(), &fd, received_data,
                                       sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
}

// ReadsNotCoalescedAfterFDPass checks that messages after a message containing
// an FD control message are not coalesced.
TEST_P(UnixStreamSocketPairTest, ReadsNotCoalescedAfterFDPass) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair->second_fd(),
                                       sent_data, sizeof(sent_data) / 2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data + sizeof(sent_data) / 2,
                      sizeof(sent_data) / 2),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));

  char received_data[sizeof(sent_data)];

  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvSingleFD(sockets->second_fd(), &fd, received_data,
                                       sizeof(received_data),
                                       sizeof(sent_data) / 2));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair->first_fd()));
  EXPECT_THAT(close(fd), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(sent_data) / 2));

  EXPECT_EQ(0, memcmp(sent_data + sizeof(sent_data) / 2, received_data,
                      sizeof(sent_data) / 2));
}

// FDPassNotCombined checks that FD control messages are not combined in a
// coalesced read.
TEST_P(UnixStreamSocketPairTest, FDPassNotCombined) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  auto pair1 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair1->second_fd(),
                                       sent_data, sizeof(sent_data) / 2));

  auto pair2 =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  ASSERT_NO_FATAL_FAILURE(SendSingleFD(sockets->first_fd(), pair2->second_fd(),
                                       sent_data + sizeof(sent_data) / 2,
                                       sizeof(sent_data) / 2));

  char received_data[sizeof(sent_data)];

  int fd = -1;
  ASSERT_NO_FATAL_FAILURE(RecvSingleFD(sockets->second_fd(), &fd, received_data,
                                       sizeof(received_data),
                                       sizeof(sent_data) / 2));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair1->first_fd()));

  EXPECT_THAT(close(fd), SyscallSucceeds());
  fd = -1;

  ASSERT_NO_FATAL_FAILURE(RecvSingleFD(sockets->second_fd(), &fd, received_data,
                                       sizeof(received_data),
                                       sizeof(sent_data) / 2));

  EXPECT_EQ(0, memcmp(sent_data + sizeof(sent_data) / 2, received_data,
                      sizeof(sent_data) / 2));

  ASSERT_NO_FATAL_FAILURE(TransferTest(fd, pair2->first_fd()));
  EXPECT_THAT(close(fd), SyscallSucceeds());
}

TEST_P(UnixStreamSocketPairTest, CredPassPartialRead) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[20];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  struct ucred sent_creds;

  ASSERT_THAT(sent_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(sent_creds.gid = getgid(), SyscallSucceeds());

  ASSERT_NO_FATAL_FAILURE(
      SendCreds(sockets->first_fd(), sent_creds, sent_data, sizeof(sent_data)));

  int one = 1;
  ASSERT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_PASSCRED, &one,
                         sizeof(one)),
              SyscallSucceeds());

  for (int i = 0; i < 2; i++) {
    char received_data[10];
    struct ucred received_creds;
    ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                      received_data, sizeof(received_data),
                                      sizeof(received_data)));

    EXPECT_EQ(0, memcmp(sent_data + i * sizeof(received_data), received_data,
                        sizeof(received_data)));
    EXPECT_EQ(sent_creds.pid, received_creds.pid);
    EXPECT_EQ(sent_creds.uid, received_creds.uid);
    EXPECT_EQ(sent_creds.gid, received_creds.gid);
  }
}

// Unix stream sockets peek in the same way as datagram sockets.
//
// SinglePeek checks that only a single message is peekable in a single recv.
TEST_P(UnixStreamSocketPairTest, SinglePeek) {
  if (!IsRunningOnGvisor()) {
    // Don't run this test on linux kernels newer than 4.3.x Linux kernel commit
    // 9f389e35674f5b086edd70ed524ca0f287259725 which changes this behavior. We
    // used to target 3.11 compatibility, so disable this test on newer kernels.
    //
    // NOTE: Bring this up to Linux 4.4 compatibility.
    auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major > 4 || (version.major == 4 && version.minor >= 3));
  }

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[40];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(RetryEINTR(send)(sockets->first_fd(), sent_data,
                               sizeof(sent_data) / 2, 0),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data + sizeof(sent_data) / 2,
                       sizeof(sent_data) / 2, 0),
      SyscallSucceedsWithValue(sizeof(sent_data) / 2));
  char received_data[sizeof(sent_data)];
  for (int i = 0; i < 3; i++) {
    memset(received_data, 0, sizeof(received_data));
    ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                                 sizeof(received_data), MSG_PEEK),
                SyscallSucceedsWithValue(sizeof(sent_data) / 2));
    EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));
  }
  memset(received_data, 0, sizeof(received_data));
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(sent_data) / 2, 0),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data) / 2));
  memset(received_data, 0, sizeof(received_data));
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(sent_data) / 2, 0),
              SyscallSucceedsWithValue(sizeof(sent_data) / 2));
  EXPECT_EQ(0, memcmp(sent_data + sizeof(sent_data) / 2, received_data,
                      sizeof(sent_data) / 2));
}

TEST_P(UnixStreamSocketPairTest, CredsNotCoalescedUp) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  SetSoPassCred(sockets->second_fd());

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];

  struct ucred received_creds;
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data),
                                    sizeof(sent_data1)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));

  struct ucred want_creds {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data),
                                    sizeof(sent_data2)));

  EXPECT_EQ(0, memcmp(sent_data2, received_data, sizeof(sent_data2)));

  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixStreamSocketPairTest, CredsNotCoalescedDown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->second_fd());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  UnsetSoPassCred(sockets->second_fd());

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  SetSoPassCred(sockets->second_fd());

  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data),
                                    sizeof(sent_data1)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data),
                                    sizeof(sent_data2)));

  EXPECT_EQ(0, memcmp(sent_data2, received_data, sizeof(sent_data2)));

  want_creds = {0, 65534, 65534};

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixStreamSocketPairTest, CoalescedCredsNoPasscred) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->second_fd());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  UnsetSoPassCred(sockets->second_fd());

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];

  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data + sizeof(sent_data1),
                      sizeof(sent_data2)));
}

TEST_P(UnixStreamSocketPairTest, CoalescedCreds1) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  SetSoPassCred(sockets->second_fd());

  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data + sizeof(sent_data1),
                      sizeof(sent_data2)));

  struct ucred want_creds {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixStreamSocketPairTest, CoalescedCreds2) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->second_fd());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  char received_data[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds,
                                    received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data + sizeof(sent_data1),
                      sizeof(sent_data2)));

  struct ucred want_creds;
  ASSERT_THAT(want_creds.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds.pid, received_creds.pid);
  EXPECT_EQ(want_creds.uid, received_creds.uid);
  EXPECT_EQ(want_creds.gid, received_creds.gid);
}

TEST_P(UnixStreamSocketPairTest, NonCoalescedDifferingCreds1) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  SetSoPassCred(sockets->second_fd());

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  char received_data1[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds1;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds1,
                                    received_data1, sizeof(sent_data1)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data1, sizeof(sent_data1)));

  struct ucred want_creds1 {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds1.pid, received_creds1.pid);
  EXPECT_EQ(want_creds1.uid, received_creds1.uid);
  EXPECT_EQ(want_creds1.gid, received_creds1.gid);

  char received_data2[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds2;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds2,
                                    received_data2, sizeof(sent_data2)));

  EXPECT_EQ(0, memcmp(sent_data2, received_data2, sizeof(sent_data2)));

  struct ucred want_creds2;
  ASSERT_THAT(want_creds2.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds2.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds2.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds2.pid, received_creds2.pid);
  EXPECT_EQ(want_creds2.uid, received_creds2.uid);
  EXPECT_EQ(want_creds2.gid, received_creds2.gid);
}

TEST_P(UnixStreamSocketPairTest, NonCoalescedDifferingCreds2) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->second_fd());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  UnsetSoPassCred(sockets->second_fd());

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  SetSoPassCred(sockets->second_fd());

  char received_data1[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds1;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds1,
                                    received_data1, sizeof(sent_data1)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data1, sizeof(sent_data1)));

  struct ucred want_creds1;
  ASSERT_THAT(want_creds1.pid = getpid(), SyscallSucceeds());
  ASSERT_THAT(want_creds1.uid = getuid(), SyscallSucceeds());
  ASSERT_THAT(want_creds1.gid = getgid(), SyscallSucceeds());

  EXPECT_EQ(want_creds1.pid, received_creds1.pid);
  EXPECT_EQ(want_creds1.uid, received_creds1.uid);
  EXPECT_EQ(want_creds1.gid, received_creds1.gid);

  char received_data2[sizeof(sent_data1) + sizeof(sent_data2)];
  struct ucred received_creds2;

  ASSERT_NO_FATAL_FAILURE(RecvCreds(sockets->second_fd(), &received_creds2,
                                    received_data2, sizeof(sent_data2)));

  EXPECT_EQ(0, memcmp(sent_data2, received_data2, sizeof(sent_data2)));

  struct ucred want_creds2 {
    0, 65534, 65534
  };

  EXPECT_EQ(want_creds2.pid, received_creds2.pid);
  EXPECT_EQ(want_creds2.uid, received_creds2.uid);
  EXPECT_EQ(want_creds2.gid, received_creds2.gid);
}

TEST_P(UnixStreamSocketPairTest, CoalescedDifferingCreds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  SetSoPassCred(sockets->second_fd());

  char sent_data1[20];
  RandomizeBuffer(sent_data1, sizeof(sent_data1));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data1, sizeof(sent_data1)),
              SyscallSucceedsWithValue(sizeof(sent_data1)));

  char sent_data2[20];
  RandomizeBuffer(sent_data2, sizeof(sent_data2));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data2, sizeof(sent_data2)),
              SyscallSucceedsWithValue(sizeof(sent_data2)));

  UnsetSoPassCred(sockets->second_fd());

  char sent_data3[20];
  RandomizeBuffer(sent_data3, sizeof(sent_data3));

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data3, sizeof(sent_data3)),
              SyscallSucceedsWithValue(sizeof(sent_data3)));

  char received_data[sizeof(sent_data1) + sizeof(sent_data2) +
                     sizeof(sent_data3)];

  ASSERT_NO_FATAL_FAILURE(
      RecvNoCmsg(sockets->second_fd(), received_data, sizeof(received_data)));

  EXPECT_EQ(0, memcmp(sent_data1, received_data, sizeof(sent_data1)));
  EXPECT_EQ(0, memcmp(sent_data2, received_data + sizeof(sent_data1),
                      sizeof(sent_data2)));
  EXPECT_EQ(0, memcmp(sent_data3,
                      received_data + sizeof(sent_data1) + sizeof(sent_data2),
                      sizeof(sent_data3)));
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, UnixStreamSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(UnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(FilesystemBoundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractBoundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                   List<int>{0, SOCK_NONBLOCK}))))));

// Test fixture for tests that apply to pairs of unbound unix stream sockets.
using UnboundUnixStreamSocketPairTest = SocketPairTest;

TEST_P(UnboundUnixStreamSocketPairTest, SendtoWithoutConnect) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  char data = 'a';
  ASSERT_THAT(sendto(sockets->second_fd(), &data, sizeof(data), 0,
                     sockets->first_addr(), sockets->first_addr_size()),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

TEST_P(UnboundUnixStreamSocketPairTest, SendtoWithoutConnectIgnoresAddr) {
  // FIXME: gVisor tries to find /foo/bar and thus returns ENOENT.
  if (IsRunningOnGvisor()) {
    return;
  }

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(bind(sockets->first_fd(), sockets->first_addr(),
                   sockets->first_addr_size()),
              SyscallSucceeds());

  // Even a bogus address is completely ignored.
  constexpr char kPath[] = "/foo/bar";

  // Sanity check that kPath doesn't exist.
  struct stat s;
  ASSERT_THAT(stat(kPath, &s), SyscallFailsWithErrno(ENOENT));

  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, kPath, sizeof(kPath));

  char data = 'a';
  ASSERT_THAT(
      sendto(sockets->second_fd(), &data, sizeof(data), 0,
             reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr)),
      SyscallFailsWithErrno(EOPNOTSUPP));
}

INSTANTIATE_TEST_SUITE_P(
    AllUnixDomainSockets, UnboundUnixStreamSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(VecCat<SocketPairKind>(
        ApplyVec<SocketPairKind>(FilesystemUnboundUnixDomainSocketPair,
                                 AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                                        List<int>{
                                                            0, SOCK_NONBLOCK})),
        ApplyVec<SocketPairKind>(
            AbstractUnboundUnixDomainSocketPair,
            AllBitwiseCombinations(List<int>{SOCK_STREAM},
                                   List<int>{0, SOCK_NONBLOCK}))))));

}  // namespace

}  // namespace testing
}  // namespace gvisor
