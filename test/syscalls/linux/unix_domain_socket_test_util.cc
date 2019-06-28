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

#include "test/syscalls/linux/unix_domain_socket_test_util.h"

#include <sys/un.h>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

std::string DescribeUnixDomainSocketType(int type) {
  const char* type_str = nullptr;
  switch (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
    case SOCK_STREAM:
      type_str = "SOCK_STREAM";
      break;
    case SOCK_DGRAM:
      type_str = "SOCK_DGRAM";
      break;
    case SOCK_SEQPACKET:
      type_str = "SOCK_SEQPACKET";
      break;
  }
  if (!type_str) {
    return absl::StrCat("Unix domain socket with unknown type ", type);
  } else {
    return absl::StrCat(((type & SOCK_NONBLOCK) != 0) ? "non-blocking " : "",
                        ((type & SOCK_CLOEXEC) != 0) ? "close-on-exec " : "",
                        type_str, " Unix domain socket");
  }
}

SocketPairKind UnixDomainSocketPair(int type) {
  return SocketPairKind{DescribeUnixDomainSocketType(type), AF_UNIX, type, 0,
                        SyscallSocketPairCreator(AF_UNIX, type, 0)};
}

SocketPairKind FilesystemBoundUnixDomainSocketPair(int type) {
  std::string description = absl::StrCat(DescribeUnixDomainSocketType(type),
                                         " created with filesystem binding");
  if ((type & SOCK_DGRAM) == SOCK_DGRAM) {
    return SocketPairKind{
        description, AF_UNIX, type, 0,
        FilesystemBidirectionalBindSocketPairCreator(AF_UNIX, type, 0)};
  }
  return SocketPairKind{
      description, AF_UNIX, type, 0,
      FilesystemAcceptBindSocketPairCreator(AF_UNIX, type, 0)};
}

SocketPairKind AbstractBoundUnixDomainSocketPair(int type) {
  std::string description =
      absl::StrCat(DescribeUnixDomainSocketType(type),
                   " created with abstract namespace binding");
  if ((type & SOCK_DGRAM) == SOCK_DGRAM) {
    return SocketPairKind{
        description, AF_UNIX, type, 0,
        AbstractBidirectionalBindSocketPairCreator(AF_UNIX, type, 0)};
  }
  return SocketPairKind{description, AF_UNIX, type, 0,
                        AbstractAcceptBindSocketPairCreator(AF_UNIX, type, 0)};
}

SocketPairKind SocketpairGoferUnixDomainSocketPair(int type) {
  std::string description = absl::StrCat(DescribeUnixDomainSocketType(type),
                                         " created with the socketpair gofer");
  return SocketPairKind{description, AF_UNIX, type, 0,
                        SocketpairGoferSocketPairCreator(AF_UNIX, type, 0)};
}

SocketPairKind SocketpairGoferFileSocketPair(int type) {
  std::string description =
      absl::StrCat(((type & O_NONBLOCK) != 0) ? "non-blocking " : "",
                   ((type & O_CLOEXEC) != 0) ? "close-on-exec " : "",
                   "file socket created with the socketpair gofer");
  // The socketpair gofer always creates SOCK_STREAM sockets on open(2).
  return SocketPairKind{description, AF_UNIX, SOCK_STREAM, 0,
                        SocketpairGoferFileSocketPairCreator(type)};
}

SocketPairKind FilesystemUnboundUnixDomainSocketPair(int type) {
  return SocketPairKind{absl::StrCat(DescribeUnixDomainSocketType(type),
                                     " unbound with a filesystem address"),
                        AF_UNIX, type, 0,
                        FilesystemUnboundSocketPairCreator(AF_UNIX, type, 0)};
}

SocketPairKind AbstractUnboundUnixDomainSocketPair(int type) {
  return SocketPairKind{
      absl::StrCat(DescribeUnixDomainSocketType(type),
                   " unbound with an abstract namespace address"),
      AF_UNIX, type, 0, AbstractUnboundSocketPairCreator(AF_UNIX, type, 0)};
}

void SendSingleFD(int sock, int fd, char buf[], int buf_size) {
  ASSERT_NO_FATAL_FAILURE(SendFDs(sock, &fd, 1, buf, buf_size));
}

void SendFDs(int sock, int fds[], int fds_size, char buf[], int buf_size) {
  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(fds_size * sizeof(int)));
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(fds_size * sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  for (int i = 0; i < fds_size; i++) {
    memcpy(CMSG_DATA(cmsg) + i * sizeof(int), &fds[i], sizeof(int));
  }

  ASSERT_THAT(SendMsg(sock, &msg, buf, buf_size),
              IsPosixErrorOkAndHolds(buf_size));
}

void RecvSingleFD(int sock, int* fd, char buf[], int buf_size) {
  ASSERT_NO_FATAL_FAILURE(RecvFDs(sock, fd, 1, buf, buf_size, buf_size));
}

void RecvSingleFD(int sock, int* fd, char buf[], int buf_size,
                  int expected_size) {
  ASSERT_NO_FATAL_FAILURE(RecvFDs(sock, fd, 1, buf, buf_size, expected_size));
}

void RecvFDs(int sock, int fds[], int fds_size, char buf[], int buf_size) {
  ASSERT_NO_FATAL_FAILURE(
      RecvFDs(sock, fds, fds_size, buf, buf_size, buf_size));
}

void RecvFDs(int sock, int fds[], int fds_size, char buf[], int buf_size,
             int expected_size, bool peek) {
  struct msghdr msg = {};
  std::vector<char> control(CMSG_SPACE(fds_size * sizeof(int)));
  msg.msg_control = &control[0];
  msg.msg_controllen = control.size();

  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = buf_size;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  int flags = 0;
  if (peek) {
    flags |= MSG_PEEK;
  }

  ASSERT_THAT(RetryEINTR(recvmsg)(sock, &msg, flags),
              SyscallSucceedsWithValue(expected_size));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(fds_size * sizeof(int)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS);

  for (int i = 0; i < fds_size; i++) {
    memcpy(&fds[i], CMSG_DATA(cmsg) + i * sizeof(int), sizeof(int));
  }
}

void RecvFDs(int sock, int fds[], int fds_size, char buf[], int buf_size,
             int expected_size) {
  ASSERT_NO_FATAL_FAILURE(
      RecvFDs(sock, fds, fds_size, buf, buf_size, expected_size, false));
}

void PeekSingleFD(int sock, int* fd, char buf[], int buf_size) {
  ASSERT_NO_FATAL_FAILURE(RecvFDs(sock, fd, 1, buf, buf_size, buf_size, true));
}

void RecvNoCmsg(int sock, char buf[], int buf_size, int expected_size) {
  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = buf_size;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sock, &msg, 0),
              SyscallSucceedsWithValue(expected_size));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  EXPECT_EQ(cmsg, nullptr);
}

void SendNullCmsg(int sock, char buf[], int buf_size) {
  struct msghdr msg = {};
  msg.msg_control = nullptr;
  msg.msg_controllen = 0;

  ASSERT_THAT(SendMsg(sock, &msg, buf, buf_size),
              IsPosixErrorOkAndHolds(buf_size));
}

void SendCreds(int sock, ucred creds, char buf[], int buf_size) {
  struct msghdr msg = {};

  char control[CMSG_SPACE(sizeof(struct ucred))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_CREDENTIALS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
  memcpy(CMSG_DATA(cmsg), &creds, sizeof(struct ucred));

  ASSERT_THAT(SendMsg(sock, &msg, buf, buf_size),
              IsPosixErrorOkAndHolds(buf_size));
}

void SendCredsAndFD(int sock, ucred creds, int fd, char buf[], int buf_size) {
  struct msghdr msg = {};

  char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))] = {};
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr* cmsg1 = CMSG_FIRSTHDR(&msg);
  cmsg1->cmsg_level = SOL_SOCKET;
  cmsg1->cmsg_type = SCM_CREDENTIALS;
  cmsg1->cmsg_len = CMSG_LEN(sizeof(struct ucred));
  memcpy(CMSG_DATA(cmsg1), &creds, sizeof(struct ucred));

  struct cmsghdr* cmsg2 = CMSG_NXTHDR(&msg, cmsg1);
  cmsg2->cmsg_level = SOL_SOCKET;
  cmsg2->cmsg_type = SCM_RIGHTS;
  cmsg2->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg2), &fd, sizeof(int));

  ASSERT_THAT(SendMsg(sock, &msg, buf, buf_size),
              IsPosixErrorOkAndHolds(buf_size));
}

void RecvCreds(int sock, ucred* creds, char buf[], int buf_size) {
  ASSERT_NO_FATAL_FAILURE(RecvCreds(sock, creds, buf, buf_size, buf_size));
}

void RecvCreds(int sock, ucred* creds, char buf[], int buf_size,
               int expected_size) {
  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(struct ucred))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = buf_size;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sock, &msg, 0),
              SyscallSucceedsWithValue(expected_size));
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(struct ucred)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SCM_CREDENTIALS);

  memcpy(creds, CMSG_DATA(cmsg), sizeof(struct ucred));
}

void RecvCredsAndFD(int sock, ucred* creds, int* fd, char buf[], int buf_size) {
  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = buf_size;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sock, &msg, 0),
              SyscallSucceedsWithValue(buf_size));

  struct cmsghdr* cmsg1 = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg1, nullptr);
  ASSERT_EQ(cmsg1->cmsg_len, CMSG_LEN(sizeof(struct ucred)));
  ASSERT_EQ(cmsg1->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg1->cmsg_type, SCM_CREDENTIALS);
  memcpy(creds, CMSG_DATA(cmsg1), sizeof(struct ucred));

  struct cmsghdr* cmsg2 = CMSG_NXTHDR(&msg, cmsg1);
  ASSERT_NE(cmsg2, nullptr);
  ASSERT_EQ(cmsg2->cmsg_len, CMSG_LEN(sizeof(int)));
  ASSERT_EQ(cmsg2->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg2->cmsg_type, SCM_RIGHTS);
  memcpy(fd, CMSG_DATA(cmsg2), sizeof(int));
}

void RecvSingleFDUnaligned(int sock, int* fd, char buf[], int buf_size) {
  struct msghdr msg = {};
  char control[CMSG_SPACE(sizeof(int)) - sizeof(int)];
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = buf_size;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ASSERT_THAT(RetryEINTR(recvmsg)(sock, &msg, 0),
              SyscallSucceedsWithValue(buf_size));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ASSERT_NE(cmsg, nullptr);
  ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(int)));
  ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET);
  ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS);

  memcpy(fd, CMSG_DATA(cmsg), sizeof(int));
}

void SetSoPassCred(int sock) {
  int one = 1;
  EXPECT_THAT(setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)),
              SyscallSucceeds());
}

void UnsetSoPassCred(int sock) {
  int zero = 0;
  EXPECT_THAT(setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &zero, sizeof(zero)),
              SyscallSucceeds());
}

}  // namespace testing
}  // namespace gvisor
