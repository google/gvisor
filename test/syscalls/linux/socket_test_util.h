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

#ifndef GVISOR_TEST_SYSCALLS_SOCKET_TEST_UTIL_H_
#define GVISOR_TEST_SYSCALLS_SOCKET_TEST_UTIL_H_

#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// Wrapper for socket(2) that returns a FileDescriptor.
inline PosixErrorOr<FileDescriptor> Socket(int family, int type, int protocol) {
  int fd = socket(family, type, protocol);
  MaybeSave();
  if (fd < 0) {
    return PosixError(
        errno, absl::StrFormat("socket(%d, %d, %d)", family, type, protocol));
  }
  return FileDescriptor(fd);
}

// Wrapper for accept(2) that returns a FileDescriptor.
inline PosixErrorOr<FileDescriptor> Accept(int sockfd, sockaddr* addr,
                                           socklen_t* addrlen) {
  int fd = RetryEINTR(accept)(sockfd, addr, addrlen);
  MaybeSave();
  if (fd < 0) {
    return PosixError(
        errno, absl::StrFormat("accept(%d, %p, %p)", sockfd, addr, addrlen));
  }
  return FileDescriptor(fd);
}

// Wrapper for accept4(2) that returns a FileDescriptor.
inline PosixErrorOr<FileDescriptor> Accept4(int sockfd, sockaddr* addr,
                                            socklen_t* addrlen, int flags) {
  int fd = RetryEINTR(accept4)(sockfd, addr, addrlen, flags);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, absl::StrFormat("accept4(%d, %p, %p, %#x)", sockfd,
                                             addr, addrlen, flags));
  }
  return FileDescriptor(fd);
}

inline ssize_t SendFd(int fd, void* buf, size_t count, int flags) {
  return internal::ApplyFileIoSyscall(
      [&](size_t completed) {
        return sendto(fd, static_cast<char*>(buf) + completed,
                      count - completed, flags, nullptr, 0);
      },
      count);
}

PosixErrorOr<struct sockaddr_un> UniqueUnixAddr(bool abstract, int domain);

// A Creator<T> is a function that attempts to create and return a new T. (This
// is copy/pasted from cloud/gvisor/api/sandbox_util.h and is just duplicated
// here for clarity.)
template <typename T>
using Creator = std::function<PosixErrorOr<std::unique_ptr<T>>()>;

// A SocketPair represents a pair of socket file descriptors owned by the
// SocketPair.
class SocketPair {
 public:
  virtual ~SocketPair() = default;

  virtual int first_fd() const = 0;
  virtual int second_fd() const = 0;
  virtual int release_first_fd() = 0;
  virtual int release_second_fd() = 0;
  virtual const struct sockaddr* first_addr() const = 0;
  virtual const struct sockaddr* second_addr() const = 0;
  virtual size_t first_addr_size() const = 0;
  virtual size_t second_addr_size() const = 0;
  virtual size_t first_addr_len() const = 0;
  virtual size_t second_addr_len() const = 0;
};

// A FDSocketPair is a SocketPair that consists of only a pair of file
// descriptors.
class FDSocketPair : public SocketPair {
 public:
  FDSocketPair(int first_fd, int second_fd)
      : first_(first_fd), second_(second_fd) {}
  FDSocketPair(std::unique_ptr<FileDescriptor> first_fd,
               std::unique_ptr<FileDescriptor> second_fd)
      : first_(first_fd->release()), second_(second_fd->release()) {}

  int first_fd() const override { return first_.get(); }
  int second_fd() const override { return second_.get(); }
  int release_first_fd() override { return first_.release(); }
  int release_second_fd() override { return second_.release(); }
  const struct sockaddr* first_addr() const override { return nullptr; }
  const struct sockaddr* second_addr() const override { return nullptr; }
  size_t first_addr_size() const override { return 0; }
  size_t second_addr_size() const override { return 0; }
  size_t first_addr_len() const override { return 0; }
  size_t second_addr_len() const override { return 0; }

 private:
  FileDescriptor first_;
  FileDescriptor second_;
};

// CalculateUnixSockAddrLen calculates the length returned by recvfrom(2) and
// recvmsg(2) for Unix sockets.
size_t CalculateUnixSockAddrLen(const char* sun_path);

// A AddrFDSocketPair is a SocketPair that consists of a pair of file
// descriptors in addition to a pair of socket addresses.
class AddrFDSocketPair : public SocketPair {
 public:
  AddrFDSocketPair(int first_fd, int second_fd,
                   const struct sockaddr_un& first_address,
                   const struct sockaddr_un& second_address)
      : first_(first_fd),
        second_(second_fd),
        first_addr_(to_storage(first_address)),
        second_addr_(to_storage(second_address)),
        first_len_(CalculateUnixSockAddrLen(first_address.sun_path)),
        second_len_(CalculateUnixSockAddrLen(second_address.sun_path)),
        first_size_(sizeof(first_address)),
        second_size_(sizeof(second_address)) {}

  AddrFDSocketPair(int first_fd, int second_fd,
                   const struct sockaddr_in& first_address,
                   const struct sockaddr_in& second_address)
      : first_(first_fd),
        second_(second_fd),
        first_addr_(to_storage(first_address)),
        second_addr_(to_storage(second_address)),
        first_len_(sizeof(first_address)),
        second_len_(sizeof(second_address)),
        first_size_(sizeof(first_address)),
        second_size_(sizeof(second_address)) {}

  AddrFDSocketPair(int first_fd, int second_fd,
                   const struct sockaddr_in6& first_address,
                   const struct sockaddr_in6& second_address)
      : first_(first_fd),
        second_(second_fd),
        first_addr_(to_storage(first_address)),
        second_addr_(to_storage(second_address)),
        first_len_(sizeof(first_address)),
        second_len_(sizeof(second_address)),
        first_size_(sizeof(first_address)),
        second_size_(sizeof(second_address)) {}

  int first_fd() const override { return first_.get(); }
  int second_fd() const override { return second_.get(); }
  int release_first_fd() override { return first_.release(); }
  int release_second_fd() override { return second_.release(); }
  const struct sockaddr* first_addr() const override {
    return reinterpret_cast<const struct sockaddr*>(&first_addr_);
  }
  const struct sockaddr* second_addr() const override {
    return reinterpret_cast<const struct sockaddr*>(&second_addr_);
  }
  size_t first_addr_size() const override { return first_size_; }
  size_t second_addr_size() const override { return second_size_; }
  size_t first_addr_len() const override { return first_len_; }
  size_t second_addr_len() const override { return second_len_; }

 private:
  // to_storage coverts a sockaddr_* to a sockaddr_storage.
  static struct sockaddr_storage to_storage(const sockaddr_un& addr);
  static struct sockaddr_storage to_storage(const sockaddr_in& addr);
  static struct sockaddr_storage to_storage(const sockaddr_in6& addr);

  FileDescriptor first_;
  FileDescriptor second_;
  const struct sockaddr_storage first_addr_;
  const struct sockaddr_storage second_addr_;
  const size_t first_len_;
  const size_t second_len_;
  const size_t first_size_;
  const size_t second_size_;
};

// SyscallSocketPairCreator returns a Creator<SocketPair> that obtains file
// descriptors by invoking the socketpair() syscall.
Creator<SocketPair> SyscallSocketPairCreator(int domain, int type,
                                             int protocol);

// SyscallSocketCreator returns a Creator<FileDescriptor> that obtains a file
// descriptor by invoking the socket() syscall.
Creator<FileDescriptor> SyscallSocketCreator(int domain, int type,
                                             int protocol);

// FilesystemBidirectionalBindSocketPairCreator returns a Creator<SocketPair>
// that obtains file descriptors by invoking the bind() and connect() syscalls
// on filesystem paths. Only works for DGRAM sockets.
Creator<SocketPair> FilesystemBidirectionalBindSocketPairCreator(int domain,
                                                                 int type,
                                                                 int protocol);

// AbstractBidirectionalBindSocketPairCreator returns a Creator<SocketPair> that
// obtains file descriptors by invoking the bind() and connect() syscalls on
// abstract namespace paths. Only works for DGRAM sockets.
Creator<SocketPair> AbstractBidirectionalBindSocketPairCreator(int domain,
                                                               int type,
                                                               int protocol);

// SocketpairGoferSocketPairCreator returns a Creator<SocketPair> that
// obtains file descriptors by connect() syscalls on two sockets with socketpair
// gofer paths.
Creator<SocketPair> SocketpairGoferSocketPairCreator(int domain, int type,
                                                     int protocol);

// SocketpairGoferFileSocketPairCreator returns a Creator<SocketPair> that
// obtains file descriptors by open() syscalls on socketpair gofer paths.
Creator<SocketPair> SocketpairGoferFileSocketPairCreator(int flags);

// FilesystemAcceptBindSocketPairCreator returns a Creator<SocketPair> that
// obtains file descriptors by invoking the accept() and bind() syscalls on
// a filesystem path. Only works for STREAM and SEQPACKET sockets.
Creator<SocketPair> FilesystemAcceptBindSocketPairCreator(int domain, int type,
                                                          int protocol);

// AbstractAcceptBindSocketPairCreator returns a Creator<SocketPair> that
// obtains file descriptors by invoking the accept() and bind() syscalls on a
// abstract namespace path. Only works for STREAM and SEQPACKET sockets.
Creator<SocketPair> AbstractAcceptBindSocketPairCreator(int domain, int type,
                                                        int protocol);

// FilesystemUnboundSocketPairCreator returns a Creator<SocketPair> that obtains
// file descriptors by invoking the socket() syscall and generates a filesystem
// path for binding.
Creator<SocketPair> FilesystemUnboundSocketPairCreator(int domain, int type,
                                                       int protocol);

// AbstractUnboundSocketPairCreator returns a Creator<SocketPair> that obtains
// file descriptors by invoking the socket() syscall and generates an abstract
// path for binding.
Creator<SocketPair> AbstractUnboundSocketPairCreator(int domain, int type,
                                                     int protocol);

// TCPAcceptBindSocketPairCreator returns a Creator<SocketPair> that obtains
// file descriptors by invoking the accept() and bind() syscalls on TCP sockets.
Creator<SocketPair> TCPAcceptBindSocketPairCreator(int domain, int type,
                                                   int protocol,
                                                   bool dual_stack);

// UDPBidirectionalBindSocketPairCreator returns a Creator<SocketPair> that
// obtains file descriptors by invoking the bind() and connect() syscalls on UDP
// sockets.
Creator<SocketPair> UDPBidirectionalBindSocketPairCreator(int domain, int type,
                                                          int protocol,
                                                          bool dual_stack);

// UDPUnboundSocketPairCreator returns a Creator<SocketPair> that obtains file
// descriptors by creating UDP sockets.
Creator<SocketPair> UDPUnboundSocketPairCreator(int domain, int type,
                                                int protocol, bool dual_stack);

// UnboundSocketCreator returns a Creator<FileDescriptor> that obtains a file
// descriptor by creating a socket.
Creator<FileDescriptor> UnboundSocketCreator(int domain, int type,
                                             int protocol);

// A SocketPairKind couples a human-readable description of a socket pair with
// a function that creates such a socket pair.
struct SocketPairKind {
  std::string description;
  int domain;
  int type;
  int protocol;
  Creator<SocketPair> creator;

  // Create creates a socket pair of this kind.
  PosixErrorOr<std::unique_ptr<SocketPair>> Create() const { return creator(); }
};

// A SocketKind couples a human-readable description of a socket with
// a function that creates such a socket.
struct SocketKind {
  std::string description;
  int domain;
  int type;
  int protocol;
  Creator<FileDescriptor> creator;

  // Create creates a socket pair of this kind.
  PosixErrorOr<std::unique_ptr<FileDescriptor>> Create() const {
    return creator();
  }
};

// A ReversedSocketPair wraps another SocketPair but flips the first and second
// file descriptors. ReversedSocketPair is used to test socket pairs that
// should be symmetric.
class ReversedSocketPair : public SocketPair {
 public:
  explicit ReversedSocketPair(std::unique_ptr<SocketPair> base)
      : base_(std::move(base)) {}

  int first_fd() const override { return base_->second_fd(); }
  int second_fd() const override { return base_->first_fd(); }
  int release_first_fd() override { return base_->release_second_fd(); }
  int release_second_fd() override { return base_->release_first_fd(); }
  const struct sockaddr* first_addr() const override {
    return base_->second_addr();
  }
  const struct sockaddr* second_addr() const override {
    return base_->first_addr();
  }
  size_t first_addr_size() const override { return base_->second_addr_size(); }
  size_t second_addr_size() const override { return base_->first_addr_size(); }
  size_t first_addr_len() const override { return base_->second_addr_len(); }
  size_t second_addr_len() const override { return base_->first_addr_len(); }

 private:
  std::unique_ptr<SocketPair> base_;
};

// Reversed returns a SocketPairKind that represents SocketPairs created by
// flipping the file descriptors provided by another SocketPair.
SocketPairKind Reversed(SocketPairKind const& base);

// IncludeReversals returns a vector<SocketPairKind> that returns all
// SocketPairKinds in `vec` as well as all SocketPairKinds obtained by flipping
// the file descriptors provided by the kinds in `vec`.
std::vector<SocketPairKind> IncludeReversals(std::vector<SocketPairKind> vec);

// A Middleware is a function wraps a SocketPairKind.
using Middleware = std::function<SocketPairKind(SocketPairKind)>;

// Reversed returns a SocketPairKind that represents SocketPairs created by
// flipping the file descriptors provided by another SocketPair.
template <typename T>
Middleware SetSockOpt(int level, int optname, T* value) {
  return [=](SocketPairKind const& base) {
    auto const& creator = base.creator;
    return SocketPairKind{
        absl::StrCat("setsockopt(", level, ", ", optname, ", ", *value, ") ",
                     base.description),
        base.domain, base.type, base.protocol,
        [creator, level, optname,
         value]() -> PosixErrorOr<std::unique_ptr<SocketPair>> {
          ASSIGN_OR_RETURN_ERRNO(auto creator_value, creator());
          if (creator_value->first_fd() >= 0) {
            RETURN_ERROR_IF_SYSCALL_FAIL(setsockopt(
                creator_value->first_fd(), level, optname, value, sizeof(T)));
          }
          if (creator_value->second_fd() >= 0) {
            RETURN_ERROR_IF_SYSCALL_FAIL(setsockopt(
                creator_value->second_fd(), level, optname, value, sizeof(T)));
          }
          return creator_value;
        }};
  };
}

constexpr int kSockOptOn = 1;
constexpr int kSockOptOff = 0;

// NoOp returns the same SocketPairKind that it is passed.
SocketPairKind NoOp(SocketPairKind const& base);

// TransferTest tests that data can be send back and fourth between two
// specified FDs. Note that calls to this function should be wrapped in
// ASSERT_NO_FATAL_FAILURE().
void TransferTest(int fd1, int fd2);

// Fills [buf, buf+len) with random bytes.
void RandomizeBuffer(char* buf, size_t len);

// Base test fixture for tests that operate on pairs of connected sockets.
class SocketPairTest : public ::testing::TestWithParam<SocketPairKind> {
 protected:
  SocketPairTest() {
    // gUnit uses printf, so so will we.
    printf("Testing with %s\n", GetParam().description.c_str());
    fflush(stdout);
  }

  PosixErrorOr<std::unique_ptr<SocketPair>> NewSocketPair() const {
    return GetParam().Create();
  }
};

// Base test fixture for tests that operate on simple Sockets.
class SimpleSocketTest : public ::testing::TestWithParam<SocketKind> {
 protected:
  SimpleSocketTest() {
    // gUnit uses printf, so so will we.
    printf("Testing with %s\n", GetParam().description.c_str());
  }

  PosixErrorOr<std::unique_ptr<FileDescriptor>> NewSocket() const {
    return GetParam().Create();
  }
};

SocketKind SimpleSocket(int fam, int type, int proto);

// Send a buffer of size 'size' to sockets->first_fd(), returning the result of
// sendmsg.
//
// If reader, read from second_fd() until size bytes have been read.
ssize_t SendLargeSendMsg(const std::unique_ptr<SocketPair>& sockets,
                         size_t size, bool reader);

// Initializes the given buffer with random data.
void RandomizeBuffer(char* ptr, size_t len);

enum class AddressFamily { kIpv4 = 1, kIpv6 = 2, kDualStack = 3 };
enum class SocketType { kUdp = 1, kTcp = 2 };

// Returns a PosixError or a port that is available. If 0 is specified as the
// port it will bind port 0 (and allow the kernel to select any free port).
// Otherwise, it will try to bind the specified port and validate that it can be
// used for the requested family and socket type. The final option is
// reuse_addr. This specifies whether SO_REUSEADDR should be applied before a
// bind(2) attempt. SO_REUSEADDR means that sockets in TIME_WAIT states or other
// bound UDP sockets would not cause an error on bind(2). This option should be
// set if subsequent calls to bind on the returned port will also use
// SO_REUSEADDR.
//
// Note: That this test will attempt to bind the ANY address for the respective
// protocol.
PosixErrorOr<int> PortAvailable(int port, AddressFamily family, SocketType type,
                                bool reuse_addr);

// FreeAvailablePort is used to return a port that was obtained by using
// the PortAvailable helper with port 0.
PosixError FreeAvailablePort(int port);

// SendMsg converts a buffer to an iovec and adds it to msg before sending it.
PosixErrorOr<int> SendMsg(int sock, msghdr* msg, char buf[], int buf_size);

// RecvNoData checks that no data is receivable on sock.
void RecvNoData(int sock);

// Base test fixture for tests that apply to all kinds of pairs of connected
// sockets.
using AllSocketPairTest = SocketPairTest;

struct TestAddress {
  std::string description;
  sockaddr_storage addr;
  socklen_t addr_len;

  int family() const { return addr.ss_family; }
  explicit TestAddress(std::string description = "")
      : description(std::move(description)), addr(), addr_len() {}
};

TestAddress V4Any();
TestAddress V4Loopback();
TestAddress V4MappedAny();
TestAddress V4MappedLoopback();
TestAddress V6Any();
TestAddress V6Loopback();

// Compute the internet checksum of an IP header.
uint16_t IPChecksum(struct iphdr ip);

// Compute the internet checksum of a UDP header.
uint16_t UDPChecksum(struct iphdr iphdr, struct udphdr udphdr,
                     const char* payload, ssize_t payload_len);

// Compute the internet checksum of an ICMP header.
uint16_t ICMPChecksum(struct icmphdr icmphdr, const char* payload,
                      ssize_t payload_len);

namespace internal {
PosixErrorOr<int> TryPortAvailable(int port, AddressFamily family,
                                   SocketType type, bool reuse_addr);
}  // namespace internal

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_SOCKET_TEST_UTIL_H_
