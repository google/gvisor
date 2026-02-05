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

#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Test fixture for Unix stream socket listener close tests.
// Sets up a listener, connects a client, then closes the listener
// while the connection is pending (not accepted).
class UnixStreamListenerCloseTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Use abstract socket namespace to avoid file system issues.
    addr_.sun_family = AF_UNIX;
    addr_.sun_path[0] = '\0';  // Abstract namespace.
    snprintf(&addr_.sun_path[1], sizeof(addr_.sun_path) - 1,
             "test_listener_close_%d_%p", getpid(), this);

    addr_len_ = offsetof(struct sockaddr_un, sun_path) + 1 +
                strlen(&addr_.sun_path[1]);

    // Create and setup the listener socket.
    listener_ = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));

    ASSERT_THAT(bind(listener_.get(), reinterpret_cast<struct sockaddr*>(&addr_),
                     addr_len_),
                SyscallSucceeds());
    ASSERT_THAT(listen(listener_.get(), 5), SyscallSucceeds());

    // Create a client and connect (but don't accept on the listener).
    client_ = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, 0));
    ASSERT_THAT(connect(client_.get(), reinterpret_cast<struct sockaddr*>(&addr_),
                        addr_len_),
                SyscallSucceeds());

    // Close the listener while the connection is pending (not accepted).
    listener_.reset();
  }

  struct sockaddr_un addr_;
  socklen_t addr_len_;
  FileDescriptor listener_;
  FileDescriptor client_;
};

// Test that when a Unix stream socket listener is closed while there are
// pending (connected but not accepted) connections, the client receives
// ECONNRESET instead of EOF.
//
// This matches Linux kernel behavior where closing the listener sends RST
// to pending connections rather than FIN.
TEST_F(UnixStreamListenerCloseTest, PendingConnectionGetsECONNRESET) {
  // Check epoll events - should include EPOLLERR.
  int epoll_fd = epoll_create1(0);
  ASSERT_GE(epoll_fd, 0);
  FileDescriptor epfd_wrapper(epoll_fd);

  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
  ev.data.fd = client_.get();
  ASSERT_THAT(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_.get(), &ev),
              SyscallSucceeds());

  struct epoll_event events[1];
  ASSERT_THAT(epoll_wait(epoll_fd, events, 1, 1000), SyscallSucceedsWithValue(1));

  // Verify EPOLLERR is set (in addition to EPOLLHUP).
  EXPECT_TRUE(events[0].events & EPOLLHUP) << "Expected EPOLLHUP to be set";
  EXPECT_TRUE(events[0].events & EPOLLERR) << "Expected EPOLLERR to be set";

  // The first read should return ECONNRESET.
  char buf[10];
  EXPECT_THAT(read(client_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));

  // After the error is consumed, subsequent reads should return EOF (0).
  EXPECT_THAT(read(client_.get(), buf, sizeof(buf)), SyscallSucceedsWithValue(0));
}

// Test that getsockopt(SO_ERROR) returns ECONNRESET for pending connections
// when the listener is closed.
TEST_F(UnixStreamListenerCloseTest, SOErrorReturnsECONNRESET) {
  // getsockopt(SO_ERROR) should return ECONNRESET.
  int err = 0;
  socklen_t len = sizeof(err);
  ASSERT_THAT(getsockopt(client_.get(), SOL_SOCKET, SO_ERROR, &err, &len),
              SyscallSucceeds());
  EXPECT_EQ(err, ECONNRESET);

  // Second call to getsockopt(SO_ERROR) should return 0 (error cleared).
  err = -1;
  ASSERT_THAT(getsockopt(client_.get(), SOL_SOCKET, SO_ERROR, &err, &len),
              SyscallSucceeds());
  EXPECT_EQ(err, 0);
}

// Test read returns ECONNRESET for pending connections when the listener is closed.
TEST_F(UnixStreamListenerCloseTest, ReadReturnsECONNRESET) {
  // The first read should return ECONNRESET.
  char buf[10];
  EXPECT_THAT(read(client_.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ECONNRESET));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
