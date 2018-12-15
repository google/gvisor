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

#include "test/syscalls/linux/socket_generic.h"

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/test_util.h"

// This file is a generic socket test file. It must be built with another file
// that provides the test types.

namespace gvisor {
namespace testing {

TEST_P(AllSocketPairTest, BasicReadWrite) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char buf[20];
  const std::string data = "abc";
  ASSERT_THAT(WriteFd(sockets->first_fd(), data.c_str(), 3),
              SyscallSucceedsWithValue(3));
  ASSERT_THAT(ReadFd(sockets->second_fd(), buf, 3),
              SyscallSucceedsWithValue(3));
  EXPECT_EQ(data, absl::string_view(buf, 3));
}

TEST_P(AllSocketPairTest, BasicSendRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[512];
  RandomizeBuffer(sent_data, sizeof(sent_data));
  ASSERT_THAT(
      RetryEINTR(send)(sockets->first_fd(), sent_data, sizeof(sent_data), 0),
      SyscallSucceedsWithValue(sizeof(sent_data)));
  char received_data[sizeof(sent_data)];
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(AllSocketPairTest, BasicSendmmsg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[200];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  std::vector<struct mmsghdr> msgs(10);
  std::vector<struct iovec> iovs(msgs.size());
  const int chunk_size = sizeof(sent_data) / msgs.size();
  for (size_t i = 0; i < msgs.size(); i++) {
    iovs[i].iov_len = chunk_size;
    iovs[i].iov_base = &sent_data[i * chunk_size];
    msgs[i].msg_hdr.msg_iov = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  ASSERT_THAT(
      RetryEINTR(sendmmsg)(sockets->first_fd(), &msgs[0], msgs.size(), 0),
      SyscallSucceedsWithValue(msgs.size()));

  for (const struct mmsghdr& msg : msgs) {
    EXPECT_EQ(chunk_size, msg.msg_len);
  }

  char received_data[sizeof(sent_data)];
  for (size_t i = 0; i < msgs.size(); i++) {
    ASSERT_THAT(ReadFd(sockets->second_fd(), &received_data[i * chunk_size],
                       chunk_size),
                SyscallSucceedsWithValue(chunk_size));
  }
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(AllSocketPairTest, BasicRecvmmsg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[200];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  char received_data[sizeof(sent_data)];
  std::vector<struct mmsghdr> msgs(10);
  std::vector<struct iovec> iovs(msgs.size());
  const int chunk_size = sizeof(sent_data) / msgs.size();
  for (size_t i = 0; i < msgs.size(); i++) {
    iovs[i].iov_len = chunk_size;
    iovs[i].iov_base = &received_data[i * chunk_size];
    msgs[i].msg_hdr.msg_iov = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  for (size_t i = 0; i < msgs.size(); i++) {
    ASSERT_THAT(
        WriteFd(sockets->first_fd(), &sent_data[i * chunk_size], chunk_size),
        SyscallSucceedsWithValue(chunk_size));
  }

  ASSERT_THAT(RetryEINTR(recvmmsg)(sockets->second_fd(), &msgs[0], msgs.size(),
                                   0, nullptr),
              SyscallSucceedsWithValue(msgs.size()));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  for (const struct mmsghdr& msg : msgs) {
    EXPECT_EQ(chunk_size, msg.msg_len);
  }
}

TEST_P(AllSocketPairTest, SendmsgRecvmsg10KB) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  std::vector<char> sent_data(10 * 1024);
  RandomizeBuffer(sent_data.data(), sent_data.size());
  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data.data(), sent_data.size()));

  std::vector<char> received_data(sent_data.size());
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(sockets->second_fd(), received_data.data(),
                                     received_data.size()));

  EXPECT_EQ(0,
            memcmp(sent_data.data(), received_data.data(), sent_data.size()));
}

// This test validates that a sendmsg/recvmsg w/ MSG_CTRUNC is a no-op on
// input flags.
TEST_P(AllSocketPairTest, SendmsgRecvmsgMsgCtruncNoop) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  std::vector<char> sent_data(10 * 1024);
  RandomizeBuffer(sent_data.data(), sent_data.size());
  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data.data(), sent_data.size()));

  std::vector<char> received_data(sent_data.size());
  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  iov.iov_base = &received_data[0];
  iov.iov_len = received_data.size();
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // MSG_CTRUNC should be a no-op.
  ASSERT_THAT(RetryEINTR(recvmsg)(sockets->second_fd(), &msg, MSG_CTRUNC),
              SyscallSucceedsWithValue(received_data.size()));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  EXPECT_EQ(cmsg, nullptr);
  EXPECT_EQ(msg.msg_controllen, 0);
  EXPECT_EQ(0,
            memcmp(sent_data.data(), received_data.data(), sent_data.size()));
}

TEST_P(AllSocketPairTest, SendmsgRecvmsg16KB) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  std::vector<char> sent_data(16 * 1024);
  RandomizeBuffer(sent_data.data(), sent_data.size());
  ASSERT_NO_FATAL_FAILURE(
      SendNullCmsg(sockets->first_fd(), sent_data.data(), sent_data.size()));

  std::vector<char> received_data(sent_data.size());
  ASSERT_NO_FATAL_FAILURE(RecvNoCmsg(sockets->second_fd(), received_data.data(),
                                     received_data.size()));

  EXPECT_EQ(0,
            memcmp(sent_data.data(), received_data.data(), sent_data.size()));
}

TEST_P(AllSocketPairTest, RecvmmsgInvalidTimeout) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char buf[10];
  struct mmsghdr msg = {};
  struct iovec iov = {};
  iov.iov_len = sizeof(buf);
  iov.iov_base = buf;
  msg.msg_hdr.msg_iov = &iov;
  msg.msg_hdr.msg_iovlen = 1;
  struct timespec timeout = {-1, -1};
  ASSERT_THAT(RetryEINTR(recvmmsg)(sockets->first_fd(), &msg, 1, 0, &timeout),
              SyscallFailsWithErrno(EINVAL));
}

TEST_P(AllSocketPairTest, RecvmmsgTimeoutBeforeRecv) {
  // There is a known bug in the Linux recvmmsg(2) causing it to block forever
  // if the timeout expires while blocking for the first message.
  SKIP_IF(!IsRunningOnGvisor());

  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char buf[10];
  struct mmsghdr msg = {};
  struct iovec iov = {};
  iov.iov_len = sizeof(buf);
  iov.iov_base = buf;
  msg.msg_hdr.msg_iov = &iov;
  msg.msg_hdr.msg_iovlen = 1;
  struct timespec timeout = {};
  ASSERT_THAT(RetryEINTR(recvmmsg)(sockets->first_fd(), &msg, 1, 0, &timeout),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, MsgPeek) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[50];
  memset(&sent_data, 0, sizeof(sent_data));
  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data)];
  for (int i = 0; i < 3; i++) {
    memset(received_data, 0, sizeof(received_data));
    EXPECT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                                 sizeof(received_data), MSG_PEEK),
                SyscallSucceedsWithValue(sizeof(received_data)));
    EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(received_data)));
  }

  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(received_data)));
  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(received_data)));
}

TEST_P(AllSocketPairTest, LingerSocketOption) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  struct linger got_linger = {-1, -1};
  socklen_t length = sizeof(struct linger);
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_LINGER,
                         &got_linger, &length),
              SyscallSucceedsWithValue(0));
  struct linger want_linger = {};
  EXPECT_EQ(0, memcmp(&want_linger, &got_linger, sizeof(struct linger)));
  EXPECT_EQ(sizeof(struct linger), length);
}

TEST_P(AllSocketPairTest, KeepAliveSocketOption) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int keepalive = -1;
  socklen_t length = sizeof(int);
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, SO_KEEPALIVE,
                         &keepalive, &length),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(0, keepalive);
  EXPECT_EQ(sizeof(int), length);
}

TEST_P(AllSocketPairTest, RcvBufSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int size = 0;
  socklen_t size_size = sizeof(size);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVBUF, &size, &size_size),
      SyscallSucceeds());
  EXPECT_GT(size, 0);
}

TEST_P(AllSocketPairTest, SndBufSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int size = 0;
  socklen_t size_size = sizeof(size);
  EXPECT_THAT(
      getsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDBUF, &size, &size_size),
      SyscallSucceeds());
  EXPECT_GT(size, 0);
}

TEST_P(AllSocketPairTest, RecvTimeoutSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  char buf[20] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, RecvTimeoutOneSecondSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 1, .tv_usec = 0
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  char buf[20] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, RecvmsgTimeoutSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  struct msghdr msg = {};
  char buf[20] = {};
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  EXPECT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg, 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, SendTimeoutAllowsSend) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  char buf[20] = {};
  ASSERT_THAT(RetryEINTR(send)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallSucceedsWithValue(sizeof(buf)));
}

TEST_P(AllSocketPairTest, SendmsgTimeoutAllowsSend) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 10
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  char buf[20] = {};
  ASSERT_NO_FATAL_FAILURE(SendNullCmsg(sockets->first_fd(), buf, sizeof(buf)));
}

TEST_P(AllSocketPairTest, SoRcvTimeoIsSet) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 35
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());
}

TEST_P(AllSocketPairTest, SoRcvTimeoIsSetLargerArg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval_with_extra {
    struct timeval tv;
    int64_t extra_data;
  } ABSL_ATTRIBUTE_PACKED;

  timeval_with_extra tv_extra;
  tv_extra.tv.tv_sec = 0;
  tv_extra.tv.tv_usec = 25;

  EXPECT_THAT(setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO,
                         &tv_extra, sizeof(tv_extra)),
              SyscallSucceeds());
}

TEST_P(AllSocketPairTest, RecvmsgTimeoutOneSecondSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 1, .tv_usec = 0
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  struct msghdr msg = {};
  char buf[20] = {};
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  EXPECT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg, 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, RecvTimeoutUsecTooLarge) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 2000000  // 2 seconds.
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallFailsWithErrno(EDOM));
}

TEST_P(AllSocketPairTest, SendTimeoutUsecTooLarge) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 2000000  // 2 seconds.
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
      SyscallFailsWithErrno(EDOM));
}

TEST_P(AllSocketPairTest, RecvTimeoutUsecNeg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = -1
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallFailsWithErrno(EDOM));
}

TEST_P(AllSocketPairTest, SendTimeoutUsecNeg) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = -1
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)),
      SyscallFailsWithErrno(EDOM));
}

TEST_P(AllSocketPairTest, RecvTimeoutNegSec) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = -1, .tv_usec = 0
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  char buf[20] = {};
  EXPECT_THAT(RetryEINTR(recv)(sockets->first_fd(), buf, sizeof(buf), 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, RecvmsgTimeoutNegSec) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = -1, .tv_usec = 0
  };
  EXPECT_THAT(
      setsockopt(sockets->first_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)),
      SyscallSucceeds());

  struct msghdr msg = {};
  char buf[20] = {};
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  EXPECT_THAT(RetryEINTR(recvmsg)(sockets->first_fd(), &msg, 0),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, RecvWaitAll) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_WAITALL),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

TEST_P(AllSocketPairTest, RecvWaitAllDontWait) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char data[100] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), data, sizeof(data),
                               MSG_WAITALL | MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

TEST_P(AllSocketPairTest, RecvTimeoutWaitAll) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  struct timeval tv {
    .tv_sec = 0, .tv_usec = 200000  // 200ms
  };
  EXPECT_THAT(setsockopt(sockets->second_fd(), SOL_SOCKET, SO_RCVTIMEO, &tv,
                         sizeof(tv)),
              SyscallSucceeds());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  char received_data[sizeof(sent_data) * 2] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), MSG_WAITALL),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));
}

}  // namespace testing
}  // namespace gvisor
