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

#include "test/syscalls/linux/socket_unix.h"

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// This file contains tests specific to Unix domain sockets. It does not contain
// tests for UDS control messages. Those belong in socket_unix_cmsg.cc.
//
// This file is a generic socket test file. It must be built with another file
// that provides the test types.

namespace gvisor {
namespace testing {

namespace {

TEST_P(UnixSocketPairTest, InvalidGetSockOpt) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int opt;
  socklen_t optlen = sizeof(opt);
  EXPECT_THAT(getsockopt(sockets->first_fd(), SOL_SOCKET, -1, &opt, &optlen),
              SyscallFailsWithErrno(ENOPROTOOPT));
}

TEST_P(UnixSocketPairTest, BindToBadName) {
  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  constexpr char kBadName[] = "/some/path/that/does/not/exist";
  sockaddr_un sockaddr;
  sockaddr.sun_family = AF_LOCAL;
  memcpy(sockaddr.sun_path, kBadName, sizeof(kBadName));

  EXPECT_THAT(
      bind(pair->first_fd(), reinterpret_cast<struct sockaddr*>(&sockaddr),
           sizeof(sockaddr)),
      SyscallFailsWithErrno(ENOENT));
}

TEST_P(UnixSocketPairTest, BindToBadFamily) {
  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  constexpr char kBadName[] = "/some/path/that/does/not/exist";
  sockaddr_un sockaddr;
  sockaddr.sun_family = AF_INET;
  memcpy(sockaddr.sun_path, kBadName, sizeof(kBadName));

  EXPECT_THAT(
      bind(pair->first_fd(), reinterpret_cast<struct sockaddr*>(&sockaddr),
           sizeof(sockaddr)),
      SyscallFailsWithErrno(EINVAL));
}

TEST_P(UnixSocketPairTest, RecvmmsgTimeoutAfterRecv) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  char sent_data[10];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  char received_data[sizeof(sent_data) * 2];
  std::vector<struct mmsghdr> msgs(2);
  std::vector<struct iovec> iovs(msgs.size());
  const int chunk_size = sizeof(received_data) / msgs.size();
  for (size_t i = 0; i < msgs.size(); i++) {
    iovs[i].iov_len = chunk_size;
    iovs[i].iov_base = &received_data[i * chunk_size];
    msgs[i].msg_hdr.msg_iov = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
  }

  ASSERT_THAT(WriteFd(sockets->first_fd(), sent_data, sizeof(sent_data)),
              SyscallSucceedsWithValue(sizeof(sent_data)));

  struct timespec timeout = {0, 1};
  ASSERT_THAT(RetryEINTR(recvmmsg)(sockets->second_fd(), &msgs[0], msgs.size(),
                                   0, &timeout),
              SyscallSucceedsWithValue(1));

  EXPECT_EQ(0, memcmp(sent_data, received_data, sizeof(sent_data)));

  EXPECT_EQ(chunk_size, msgs[0].msg_len);
}

TEST_P(UnixSocketPairTest, TIOCINQSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  if (IsRunningOnGvisor()) {
    // TODO(gvisor.dev/issue/273): Inherited host UDS don't support TIOCINQ.
    // Skip the test.
    int size = -1;
    int ret = ioctl(sockets->first_fd(), TIOCINQ, &size);
    SKIP_IF(ret == -1 && errno == ENOTTY);
  }

  int size = -1;
  EXPECT_THAT(ioctl(sockets->first_fd(), TIOCINQ, &size), SyscallSucceeds());
  EXPECT_EQ(size, 0);

  const char some_data[] = "dangerzone";
  ASSERT_THAT(
      RetryEINTR(send)(sockets->second_fd(), &some_data, sizeof(some_data), 0),
      SyscallSucceeds());
  EXPECT_THAT(ioctl(sockets->first_fd(), TIOCINQ, &size), SyscallSucceeds());
  EXPECT_EQ(size, sizeof(some_data));

  // Linux only reports the first message's size, which is wrong. We test for
  // the behavior described in the man page.
  SKIP_IF(!IsRunningOnGvisor());

  ASSERT_THAT(
      RetryEINTR(send)(sockets->second_fd(), &some_data, sizeof(some_data), 0),
      SyscallSucceeds());
  EXPECT_THAT(ioctl(sockets->first_fd(), TIOCINQ, &size), SyscallSucceeds());
  EXPECT_EQ(size, sizeof(some_data) * 2);
}

TEST_P(UnixSocketPairTest, TIOCOUTQSucceeds) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  if (IsRunningOnGvisor()) {
    // TODO(gvisor.dev/issue/273): Inherited host UDS don't support TIOCOUTQ.
    // Skip the test.
    int size = -1;
    int ret = ioctl(sockets->second_fd(), TIOCOUTQ, &size);
    SKIP_IF(ret == -1 && errno == ENOTTY);
  }

  int size = -1;
  EXPECT_THAT(ioctl(sockets->second_fd(), TIOCOUTQ, &size), SyscallSucceeds());
  EXPECT_EQ(size, 0);

  // Linux reports bogus numbers which are related to its internal allocations.
  // We test for the behavior described in the man page.
  SKIP_IF(!IsRunningOnGvisor());

  const char some_data[] = "dangerzone";
  ASSERT_THAT(
      RetryEINTR(send)(sockets->second_fd(), &some_data, sizeof(some_data), 0),
      SyscallSucceeds());
  EXPECT_THAT(ioctl(sockets->second_fd(), TIOCOUTQ, &size), SyscallSucceeds());
  EXPECT_EQ(size, sizeof(some_data));

  ASSERT_THAT(
      RetryEINTR(send)(sockets->second_fd(), &some_data, sizeof(some_data), 0),
      SyscallSucceeds());
  EXPECT_THAT(ioctl(sockets->second_fd(), TIOCOUTQ, &size), SyscallSucceeds());
  EXPECT_EQ(size, sizeof(some_data) * 2);
}

TEST_P(UnixSocketPairTest, NetdeviceIoctlsSucceed) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Prepare the request.
  struct ifreq ifr;
  snprintf(ifr.ifr_name, IFNAMSIZ, "lo");

  // Check that the ioctl either succeeds or fails with ENODEV.
  int err = ioctl(sockets->first_fd(), SIOCGIFINDEX, &ifr);
  if (err < 0) {
    ASSERT_EQ(errno, ENODEV);
  }
}

TEST_P(UnixSocketPairTest, Shutdown) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  const std::string data = "abc";
  ASSERT_THAT(WriteFd(sockets->first_fd(), data.c_str(), data.size()),
              SyscallSucceedsWithValue(data.size()));

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RDWR), SyscallSucceeds());
  ASSERT_THAT(shutdown(sockets->second_fd(), SHUT_RDWR), SyscallSucceeds());

  // Shutting down a socket does not clear the buffer.
  char buf[3];
  ASSERT_THAT(ReadFd(sockets->second_fd(), buf, data.size()),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(data, absl::string_view(buf, data.size()));
}

TEST_P(UnixSocketPairTest, ShutdownRead) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_RD), SyscallSucceeds());

  // When the socket is shutdown for read, read behavior varies between
  // different socket types. This is covered by the various ReadOneSideClosed
  // test cases.

  // ... and the peer cannot write.
  const std::string data = "abc";
  EXPECT_THAT(WriteFd(sockets->second_fd(), data.c_str(), data.size()),
              SyscallFailsWithErrno(EPIPE));

  // ... but the socket can still write.
  ASSERT_THAT(WriteFd(sockets->first_fd(), data.c_str(), data.size()),
              SyscallSucceedsWithValue(data.size()));

  // ... and the peer can still read.
  char buf[3];
  EXPECT_THAT(ReadFd(sockets->second_fd(), buf, data.size()),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(data, absl::string_view(buf, data.size()));
}

TEST_P(UnixSocketPairTest, ShutdownWrite) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  ASSERT_THAT(shutdown(sockets->first_fd(), SHUT_WR), SyscallSucceeds());

  // When the socket is shutdown for write, it cannot write.
  const std::string data = "abc";
  EXPECT_THAT(WriteFd(sockets->first_fd(), data.c_str(), data.size()),
              SyscallFailsWithErrno(EPIPE));

  // ... and the peer read behavior varies between different socket types. This
  // is covered by the various ReadOneSideClosed test cases.

  // ... but the peer can still write.
  char buf[3];
  ASSERT_THAT(WriteFd(sockets->second_fd(), data.c_str(), data.size()),
              SyscallSucceedsWithValue(data.size()));

  // ... and the socket can still read.
  EXPECT_THAT(ReadFd(sockets->first_fd(), buf, data.size()),
              SyscallSucceedsWithValue(data.size()));
  EXPECT_EQ(data, absl::string_view(buf, data.size()));
}

TEST_P(UnixSocketPairTest, SocketReopenFromProcfs) {
  // TODO(gvisor.dev/issue/1624): In VFS1, we return EIO instead of ENXIO (see
  // b/122310852). Remove this skip once VFS1 is deleted.
  SKIP_IF(IsRunningWithVFS1());
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  // Opening a socket pair via /proc/self/fd/X is a ENXIO.
  for (const int fd : {sockets->first_fd(), sockets->second_fd()}) {
    ASSERT_THAT(Open(absl::StrCat("/proc/self/fd/", fd), O_WRONLY),
                PosixErrorIs(ENXIO, ::testing::_));
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
