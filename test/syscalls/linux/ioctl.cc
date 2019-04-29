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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

bool CheckNonBlocking(int fd) {
  int ret = fcntl(fd, F_GETFL, 0);
  TEST_CHECK(ret != -1);
  return (ret & O_NONBLOCK) == O_NONBLOCK;
}

bool CheckCloExec(int fd) {
  int ret = fcntl(fd, F_GETFD, 0);
  TEST_CHECK(ret != -1);
  return (ret & FD_CLOEXEC) == FD_CLOEXEC;
}

class IoctlTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(fd_ = open("/dev/null", O_RDONLY), SyscallSucceeds());
  }

  void TearDown() override {
    if (fd_ >= 0) {
      ASSERT_THAT(close(fd_), SyscallSucceeds());
      fd_ = -1;
    }
  }

  int fd() const { return fd_; }

 private:
  int fd_ = -1;
};

TEST_F(IoctlTest, BadFileDescriptor) {
  EXPECT_THAT(ioctl(-1 /* fd */, 0), SyscallFailsWithErrno(EBADF));
}

TEST_F(IoctlTest, InvalidControlNumber) {
  EXPECT_THAT(ioctl(STDOUT_FILENO, 0), SyscallFailsWithErrno(ENOTTY));
}

TEST_F(IoctlTest, FIONBIOSucceeds) {
  EXPECT_FALSE(CheckNonBlocking(fd()));
  int set = 1;
  EXPECT_THAT(ioctl(fd(), FIONBIO, &set), SyscallSucceeds());
  EXPECT_TRUE(CheckNonBlocking(fd()));
  set = 0;
  EXPECT_THAT(ioctl(fd(), FIONBIO, &set), SyscallSucceeds());
  EXPECT_FALSE(CheckNonBlocking(fd()));
}

TEST_F(IoctlTest, FIONBIOFails) {
  EXPECT_THAT(ioctl(fd(), FIONBIO, nullptr), SyscallFailsWithErrno(EFAULT));
}

TEST_F(IoctlTest, FIONCLEXSucceeds) {
  EXPECT_THAT(ioctl(fd(), FIONCLEX), SyscallSucceeds());
  EXPECT_FALSE(CheckCloExec(fd()));
}

TEST_F(IoctlTest, FIOCLEXSucceeds) {
  EXPECT_THAT(ioctl(fd(), FIOCLEX), SyscallSucceeds());
  EXPECT_TRUE(CheckCloExec(fd()));
}

TEST_F(IoctlTest, FIOASYNCFails) {
  EXPECT_THAT(ioctl(fd(), FIOASYNC, nullptr), SyscallFailsWithErrno(EFAULT));
}

TEST_F(IoctlTest, FIOASYNCSucceeds) {
  // Not all FDs support FIOASYNC.
  const FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int before = -1;
  ASSERT_THAT(before = fcntl(s.get(), F_GETFL), SyscallSucceeds());

  int set = 1;
  EXPECT_THAT(ioctl(s.get(), FIOASYNC, &set), SyscallSucceeds());

  int after_set = -1;
  ASSERT_THAT(after_set = fcntl(s.get(), F_GETFL), SyscallSucceeds());
  EXPECT_EQ(after_set, before | O_ASYNC) << "before was " << before;

  set = 0;
  EXPECT_THAT(ioctl(s.get(), FIOASYNC, &set), SyscallSucceeds());

  ASSERT_THAT(fcntl(s.get(), F_GETFL), SyscallSucceedsWithValue(before));
}

/* Count of the number of SIGIOs handled. */
static volatile int io_received = 0;

void inc_io_handler(int sig, siginfo_t* siginfo, void* arg) { io_received++; }

TEST_F(IoctlTest, FIOASYNCNoTarget) {
  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  // Count SIGIOs received.
  io_received = 0;
  struct sigaction sa;
  sa.sa_sigaction = inc_io_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGIO, sa));

  // Actually allow SIGIO delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGIO));

  int set = 1;
  EXPECT_THAT(ioctl(pair->second_fd(), FIOASYNC, &set), SyscallSucceeds());

  constexpr char kData[] = "abc";
  ASSERT_THAT(WriteFd(pair->first_fd(), kData, sizeof(kData)),
              SyscallSucceedsWithValue(sizeof(kData)));

  EXPECT_EQ(io_received, 0);
}

TEST_F(IoctlTest, FIOASYNCSelfTarget) {
  // FIXME(b/120624367): gVisor erroneously sends SIGIO on close(2), which would
  // kill the test when pair goes out of scope. Temporarily ignore SIGIO so that
  // that the close signal is ignored.
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  auto early_sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGIO, sa));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  // Count SIGIOs received.
  io_received = 0;
  sa.sa_sigaction = inc_io_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGIO, sa));

  // Actually allow SIGIO delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGIO));

  int set = 1;
  EXPECT_THAT(ioctl(pair->second_fd(), FIOASYNC, &set), SyscallSucceeds());

  pid_t pid = getpid();
  EXPECT_THAT(ioctl(pair->second_fd(), FIOSETOWN, &pid), SyscallSucceeds());

  constexpr char kData[] = "abc";
  ASSERT_THAT(WriteFd(pair->first_fd(), kData, sizeof(kData)),
              SyscallSucceedsWithValue(sizeof(kData)));

  EXPECT_EQ(io_received, 1);
}

// Equivalent to FIOASYNCSelfTarget except that FIOSETOWN is called before
// FIOASYNC.
TEST_F(IoctlTest, FIOASYNCSelfTarget2) {
  // FIXME(b/120624367): gVisor erroneously sends SIGIO on close(2), which would
  // kill the test when pair goes out of scope. Temporarily ignore SIGIO so that
  // that the close signal is ignored.
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  auto early_sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGIO, sa));

  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  // Count SIGIOs received.
  io_received = 0;
  sa.sa_sigaction = inc_io_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGIO, sa));

  // Actually allow SIGIO delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGIO));

  pid_t pid = getpid();
  EXPECT_THAT(ioctl(pair->second_fd(), FIOSETOWN, &pid), SyscallSucceeds());

  int set = 1;
  EXPECT_THAT(ioctl(pair->second_fd(), FIOASYNC, &set), SyscallSucceeds());

  constexpr char kData[] = "abc";
  ASSERT_THAT(WriteFd(pair->first_fd(), kData, sizeof(kData)),
              SyscallSucceedsWithValue(sizeof(kData)));

  EXPECT_EQ(io_received, 1);
}

TEST_F(IoctlTest, FIOASYNCInvalidPID) {
  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());
  int set = 1;
  ASSERT_THAT(ioctl(pair->second_fd(), FIOASYNC, &set), SyscallSucceeds());
  pid_t pid = INT_MAX;
  // This succeeds (with behavior equivalent to a pid of 0) in Linux prior to
  // f73127356f34 "fs/fcntl: return -ESRCH in f_setown when pid/pgid can't be
  // found", and fails with EPERM after that commit.
  EXPECT_THAT(ioctl(pair->second_fd(), FIOSETOWN, &pid),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ESRCH)));
}

TEST_F(IoctlTest, FIOASYNCUnsetTarget) {
  auto pair =
      ASSERT_NO_ERRNO_AND_VALUE(UnixDomainSocketPair(SOCK_SEQPACKET).Create());

  // Count SIGIOs received.
  io_received = 0;
  struct sigaction sa;
  sa.sa_sigaction = inc_io_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGIO, sa));

  // Actually allow SIGIO delivery.
  auto mask_cleanup =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSignalMask(SIG_UNBLOCK, SIGIO));

  int set = 1;
  EXPECT_THAT(ioctl(pair->second_fd(), FIOASYNC, &set), SyscallSucceeds());

  pid_t pid = getpid();
  EXPECT_THAT(ioctl(pair->second_fd(), FIOSETOWN, &pid), SyscallSucceeds());

  // Passing a PID of 0 unsets the target.
  pid = 0;
  EXPECT_THAT(ioctl(pair->second_fd(), FIOSETOWN, &pid), SyscallSucceeds());

  constexpr char kData[] = "abc";
  ASSERT_THAT(WriteFd(pair->first_fd(), kData, sizeof(kData)),
              SyscallSucceedsWithValue(sizeof(kData)));

  EXPECT_EQ(io_received, 0);
}

using IoctlTestSIOCGIFCONF = SimpleSocketTest;

TEST_P(IoctlTestSIOCGIFCONF, ValidateNoArrayGetsLength) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  // Validate that no array can be used to get the length required.
  struct ifconf ifconf = {};
  ASSERT_THAT(ioctl(fd->get(), SIOCGIFCONF, &ifconf), SyscallSucceeds());
  ASSERT_GT(ifconf.ifc_len, 0);
}

// This test validates that we will only return a partial array list and not
// partial ifrreq structs.
TEST_P(IoctlTestSIOCGIFCONF, ValidateNoPartialIfrsReturned) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  struct ifreq ifr = {};
  struct ifconf ifconf = {};
  ifconf.ifc_len = sizeof(ifr) - 1;  // One byte too few.
  ifconf.ifc_ifcu.ifcu_req = &ifr;

  ASSERT_THAT(ioctl(fd->get(), SIOCGIFCONF, &ifconf), SyscallSucceeds());
  ASSERT_EQ(ifconf.ifc_len, 0);
  ASSERT_EQ(ifr.ifr_name[0], '\0');  // Nothing is returned.

  ifconf.ifc_len = sizeof(ifreq);
  ASSERT_THAT(ioctl(fd->get(), SIOCGIFCONF, &ifconf), SyscallSucceeds());
  ASSERT_GT(ifconf.ifc_len, 0);
  ASSERT_NE(ifr.ifr_name[0], '\0');  // An interface can now be returned.
}

TEST_P(IoctlTestSIOCGIFCONF, ValidateLoopbackIsPresent) {
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(NewSocket());

  struct ifconf ifconf = {};
  struct ifreq ifr[10] = {};  // Storage for up to 10 interfaces.

  ifconf.ifc_req = ifr;
  ifconf.ifc_len = sizeof(ifr);

  ASSERT_THAT(ioctl(fd->get(), SIOCGIFCONF, &ifconf), SyscallSucceeds());
  size_t num_if = ifconf.ifc_len / sizeof(struct ifreq);

  // We should have at least one interface.
  ASSERT_GE(num_if, 1);

  // One of the interfaces should be a loopback.
  bool found_loopback = false;
  for (size_t i = 0; i < num_if; ++i) {
    if (strcmp(ifr[i].ifr_name, "lo") == 0) {
      // SIOCGIFCONF returns the ipv4 address of the interface, let's check it.
      ASSERT_EQ(ifr[i].ifr_addr.sa_family, AF_INET);

      // Validate the address is correct for loopback.
      sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ifr[i].ifr_addr);
      ASSERT_EQ(htonl(sin->sin_addr.s_addr), INADDR_LOOPBACK);

      found_loopback = true;
      break;
    }
  }
  ASSERT_TRUE(found_loopback);
}

std::vector<SocketKind> IoctlSocketTypes() {
  return {SimpleSocket(AF_UNIX, SOCK_STREAM, 0),
          SimpleSocket(AF_UNIX, SOCK_DGRAM, 0),
          SimpleSocket(AF_INET, SOCK_STREAM, 0),
          SimpleSocket(AF_INET6, SOCK_STREAM, 0),
          SimpleSocket(AF_INET, SOCK_DGRAM, 0),
          SimpleSocket(AF_INET6, SOCK_DGRAM, 0)};
}

INSTANTIATE_TEST_SUITE_P(IoctlTest, IoctlTestSIOCGIFCONF,
                         ::testing::ValuesIn(IoctlSocketTypes()));

}  // namespace

TEST_F(IoctlTest, FIOGETOWNSucceeds) {
  const FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int get = -1;
  ASSERT_THAT(ioctl(s.get(), FIOGETOWN, &get), SyscallSucceeds());
  EXPECT_EQ(get, 0);
}

TEST_F(IoctlTest, SIOCGPGRPSucceeds) {
  const FileDescriptor s = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));

  int get = -1;
  ASSERT_THAT(ioctl(s.get(), SIOCGPGRP, &get), SyscallSucceeds());
  EXPECT_EQ(get, 0);
}

}  // namespace testing
}  // namespace gvisor
