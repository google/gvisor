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

#include "test/syscalls/linux/socket_test_util.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

#include <memory>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/types/optional.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

Creator<SocketPair> SyscallSocketPairCreator(int domain, int type,
                                             int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FDSocketPair>> {
    int pair[2];
    RETURN_ERROR_IF_SYSCALL_FAIL(socketpair(domain, type, protocol, pair));
    MaybeSave();  // Save on successful creation.
    return absl::make_unique<FDSocketPair>(pair[0], pair[1]);
  };
}

Creator<FileDescriptor> SyscallSocketCreator(int domain, int type,
                                             int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FileDescriptor>> {
    int fd = 0;
    RETURN_ERROR_IF_SYSCALL_FAIL(fd = socket(domain, type, protocol));
    MaybeSave();  // Save on successful creation.
    return absl::make_unique<FileDescriptor>(fd);
  };
}

PosixErrorOr<struct sockaddr_un> UniqueUnixAddr(bool abstract, int domain) {
  struct sockaddr_un addr = {};
  std::string path = NewTempAbsPathInDir("/tmp");
  if (path.size() >= sizeof(addr.sun_path)) {
    return PosixError(EINVAL,
                      "Unable to generate a temp path of appropriate length");
  }

  if (abstract) {
    // Indicate that the path is in the abstract namespace.
    path[0] = 0;
  }
  memcpy(addr.sun_path, path.c_str(), path.length());
  addr.sun_family = domain;
  return addr;
}

Creator<SocketPair> AcceptBindSocketPairCreator(bool abstract, int domain,
                                                int type, int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> {
    ASSIGN_OR_RETURN_ERRNO(struct sockaddr_un bind_addr,
                           UniqueUnixAddr(abstract, domain));
    ASSIGN_OR_RETURN_ERRNO(struct sockaddr_un extra_addr,
                           UniqueUnixAddr(abstract, domain));

    int bound;
    RETURN_ERROR_IF_SYSCALL_FAIL(bound = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    RETURN_ERROR_IF_SYSCALL_FAIL(
        bind(bound, reinterpret_cast<struct sockaddr*>(&bind_addr),
             sizeof(bind_addr)));
    MaybeSave();  // Successful bind.
    RETURN_ERROR_IF_SYSCALL_FAIL(listen(bound, /* backlog = */ 5));
    MaybeSave();  // Successful listen.

    int connected;
    RETURN_ERROR_IF_SYSCALL_FAIL(connected = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    RETURN_ERROR_IF_SYSCALL_FAIL(
        connect(connected, reinterpret_cast<struct sockaddr*>(&bind_addr),
                sizeof(bind_addr)));
    MaybeSave();  // Successful connect.

    int accepted;
    RETURN_ERROR_IF_SYSCALL_FAIL(
        accepted = accept4(bound, nullptr, nullptr,
                           type & (SOCK_NONBLOCK | SOCK_CLOEXEC)));
    MaybeSave();  // Successful connect.

    // Cleanup no longer needed resources.
    RETURN_ERROR_IF_SYSCALL_FAIL(close(bound));
    MaybeSave();  // Dropped original socket.

    // Only unlink if path is not in abstract namespace.
    if (bind_addr.sun_path[0] != 0) {
      RETURN_ERROR_IF_SYSCALL_FAIL(unlink(bind_addr.sun_path));
      MaybeSave();  // Unlinked path.
    }

    // accepted is before connected to destruct connected before accepted.
    // Destructors for nonstatic member objects are called in the reverse order
    // in which they appear in the class declaration.
    return absl::make_unique<AddrFDSocketPair>(accepted, connected, bind_addr,
                                               extra_addr);
  };
}

Creator<SocketPair> FilesystemAcceptBindSocketPairCreator(int domain, int type,
                                                          int protocol) {
  return AcceptBindSocketPairCreator(/* abstract= */ false, domain, type,
                                     protocol);
}

Creator<SocketPair> AbstractAcceptBindSocketPairCreator(int domain, int type,
                                                        int protocol) {
  return AcceptBindSocketPairCreator(/* abstract= */ true, domain, type,
                                     protocol);
}

Creator<SocketPair> BidirectionalBindSocketPairCreator(bool abstract,
                                                       int domain, int type,
                                                       int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FDSocketPair>> {
    ASSIGN_OR_RETURN_ERRNO(struct sockaddr_un addr1,
                           UniqueUnixAddr(abstract, domain));
    ASSIGN_OR_RETURN_ERRNO(struct sockaddr_un addr2,
                           UniqueUnixAddr(abstract, domain));

    int sock1;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock1 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    RETURN_ERROR_IF_SYSCALL_FAIL(
        bind(sock1, reinterpret_cast<struct sockaddr*>(&addr1), sizeof(addr1)));
    MaybeSave();  // Successful bind.

    int sock2;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock2 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    RETURN_ERROR_IF_SYSCALL_FAIL(
        bind(sock2, reinterpret_cast<struct sockaddr*>(&addr2), sizeof(addr2)));
    MaybeSave();  // Successful bind.

    RETURN_ERROR_IF_SYSCALL_FAIL(connect(
        sock1, reinterpret_cast<struct sockaddr*>(&addr2), sizeof(addr2)));
    MaybeSave();  // Successful connect.

    RETURN_ERROR_IF_SYSCALL_FAIL(connect(
        sock2, reinterpret_cast<struct sockaddr*>(&addr1), sizeof(addr1)));
    MaybeSave();  // Successful connect.

    // Cleanup no longer needed resources.

    // Only unlink if path is not in abstract namespace.
    if (addr1.sun_path[0] != 0) {
      RETURN_ERROR_IF_SYSCALL_FAIL(unlink(addr1.sun_path));
      MaybeSave();  // Successful unlink.
    }

    // Only unlink if path is not in abstract namespace.
    if (addr2.sun_path[0] != 0) {
      RETURN_ERROR_IF_SYSCALL_FAIL(unlink(addr2.sun_path));
      MaybeSave();  // Successful unlink.
    }

    return absl::make_unique<FDSocketPair>(sock1, sock2);
  };
}

Creator<SocketPair> FilesystemBidirectionalBindSocketPairCreator(int domain,
                                                                 int type,
                                                                 int protocol) {
  return BidirectionalBindSocketPairCreator(/* abstract= */ false, domain, type,
                                            protocol);
}

Creator<SocketPair> AbstractBidirectionalBindSocketPairCreator(int domain,
                                                               int type,
                                                               int protocol) {
  return BidirectionalBindSocketPairCreator(/* abstract= */ true, domain, type,
                                            protocol);
}

Creator<SocketPair> SocketpairGoferSocketPairCreator(int domain, int type,
                                                     int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FDSocketPair>> {
    struct sockaddr_un addr = {};
    constexpr char kSocketGoferPath[] = "/socket";
    memcpy(addr.sun_path, kSocketGoferPath, sizeof(kSocketGoferPath));
    addr.sun_family = domain;

    int sock1;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock1 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    RETURN_ERROR_IF_SYSCALL_FAIL(connect(
        sock1, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)));
    MaybeSave();  // Successful connect.

    int sock2;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock2 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    RETURN_ERROR_IF_SYSCALL_FAIL(connect(
        sock2, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)));
    MaybeSave();  // Successful connect.

    // Make and close another socketpair to ensure that the duped ends of the
    // first socketpair get closed.
    //
    // The problem is that there is no way to atomically send and close an FD.
    // The closest that we can do is send and then immediately close the FD,
    // which is what we do in the gofer. The gofer won't respond to another
    // request until the reply is sent and the FD is closed, so forcing the
    // gofer to handle another request will ensure that this has happened.
    for (int i = 0; i < 2; i++) {
      int sock;
      RETURN_ERROR_IF_SYSCALL_FAIL(sock = socket(domain, type, protocol));
      RETURN_ERROR_IF_SYSCALL_FAIL(connect(
          sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)));
      RETURN_ERROR_IF_SYSCALL_FAIL(close(sock));
    }

    return absl::make_unique<FDSocketPair>(sock1, sock2);
  };
}

Creator<SocketPair> SocketpairGoferFileSocketPairCreator(int flags) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FDSocketPair>> {
    constexpr char kSocketGoferPath[] = "/socket";

    int sock1;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock1 =
                                     open(kSocketGoferPath, O_RDWR | flags));
    MaybeSave();  // Successful socket creation.

    int sock2;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock2 =
                                     open(kSocketGoferPath, O_RDWR | flags));
    MaybeSave();  // Successful socket creation.

    return absl::make_unique<FDSocketPair>(sock1, sock2);
  };
}

Creator<SocketPair> UnboundSocketPairCreator(bool abstract, int domain,
                                             int type, int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> {
    ASSIGN_OR_RETURN_ERRNO(struct sockaddr_un addr1,
                           UniqueUnixAddr(abstract, domain));
    ASSIGN_OR_RETURN_ERRNO(struct sockaddr_un addr2,
                           UniqueUnixAddr(abstract, domain));

    int sock1;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock1 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    int sock2;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock2 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.
    return absl::make_unique<AddrFDSocketPair>(sock1, sock2, addr1, addr2);
  };
}

Creator<SocketPair> FilesystemUnboundSocketPairCreator(int domain, int type,
                                                       int protocol) {
  return UnboundSocketPairCreator(/* abstract= */ false, domain, type,
                                  protocol);
}

Creator<SocketPair> AbstractUnboundSocketPairCreator(int domain, int type,
                                                     int protocol) {
  return UnboundSocketPairCreator(/* abstract= */ true, domain, type, protocol);
}

void LocalhostAddr(struct sockaddr_in* addr, bool dual_stack) {
  addr->sin_family = AF_INET;
  addr->sin_port = htons(0);
  inet_pton(AF_INET, "127.0.0.1",
            reinterpret_cast<void*>(&addr->sin_addr.s_addr));
}

void LocalhostAddr(struct sockaddr_in6* addr, bool dual_stack) {
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons(0);
  if (dual_stack) {
    inet_pton(AF_INET6, "::ffff:127.0.0.1",
              reinterpret_cast<void*>(&addr->sin6_addr.s6_addr));
  } else {
    inet_pton(AF_INET6, "::1",
              reinterpret_cast<void*>(&addr->sin6_addr.s6_addr));
  }
  addr->sin6_scope_id = 0;
}

template <typename T>
PosixErrorOr<T> BindIP(int fd, bool dual_stack) {
  T addr = {};
  LocalhostAddr(&addr, dual_stack);
  RETURN_ERROR_IF_SYSCALL_FAIL(
      bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)));
  socklen_t addrlen = sizeof(addr);
  RETURN_ERROR_IF_SYSCALL_FAIL(
      getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrlen));
  return addr;
}

template <typename T>
PosixErrorOr<T> TCPBindAndListen(int fd, bool dual_stack) {
  ASSIGN_OR_RETURN_ERRNO(T addr, BindIP<T>(fd, dual_stack));
  RETURN_ERROR_IF_SYSCALL_FAIL(listen(fd, /* backlog = */ 5));
  return addr;
}

template <typename T>
PosixErrorOr<std::unique_ptr<AddrFDSocketPair>>
CreateTCPConnectAcceptSocketPair(int bound, int connected, int type,
                                 bool dual_stack, T bind_addr) {
  int connect_result = 0;
  RETURN_ERROR_IF_SYSCALL_FAIL(
      (connect_result = RetryEINTR(connect)(
           connected, reinterpret_cast<struct sockaddr*>(&bind_addr),
           sizeof(bind_addr))) == -1 &&
              errno == EINPROGRESS
          ? 0
          : connect_result);
  MaybeSave();  // Successful connect.

  if (connect_result == -1) {
    struct pollfd connect_poll = {connected, POLLOUT | POLLERR | POLLHUP, 0};
    RETURN_ERROR_IF_SYSCALL_FAIL(RetryEINTR(poll)(&connect_poll, 1, 0));
    int error = 0;
    socklen_t errorlen = sizeof(error);
    RETURN_ERROR_IF_SYSCALL_FAIL(
        getsockopt(connected, SOL_SOCKET, SO_ERROR, &error, &errorlen));
    errno = error;
    RETURN_ERROR_IF_SYSCALL_FAIL(
        /* connect */ error == 0 ? 0 : -1);
  }

  int accepted = -1;
  struct pollfd accept_poll = {bound, POLLIN, 0};
  while (accepted == -1) {
    RETURN_ERROR_IF_SYSCALL_FAIL(RetryEINTR(poll)(&accept_poll, 1, 0));

    RETURN_ERROR_IF_SYSCALL_FAIL(
        (accepted = RetryEINTR(accept4)(
             bound, nullptr, nullptr, type & (SOCK_NONBLOCK | SOCK_CLOEXEC))) ==
                    -1 &&
                errno == EAGAIN
            ? 0
            : accepted);
  }
  MaybeSave();  // Successful accept.

  T extra_addr = {};
  LocalhostAddr(&extra_addr, dual_stack);
  return absl::make_unique<AddrFDSocketPair>(connected, accepted, bind_addr,
                                             extra_addr);
}

template <typename T>
PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> CreateTCPAcceptBindSocketPair(
    int bound, int connected, int type, bool dual_stack) {
  ASSIGN_OR_RETURN_ERRNO(T bind_addr, TCPBindAndListen<T>(bound, dual_stack));

  auto result = CreateTCPConnectAcceptSocketPair(bound, connected, type,
                                                 dual_stack, bind_addr);

  // Cleanup no longer needed resources.
  RETURN_ERROR_IF_SYSCALL_FAIL(close(bound));
  MaybeSave();  // Successful close.

  return result;
}

Creator<SocketPair> TCPAcceptBindSocketPairCreator(int domain, int type,
                                                   int protocol,
                                                   bool dual_stack) {
  return [=]() -> PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> {
    int bound;
    RETURN_ERROR_IF_SYSCALL_FAIL(bound = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    int connected;
    RETURN_ERROR_IF_SYSCALL_FAIL(connected = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    if (domain == AF_INET) {
      return CreateTCPAcceptBindSocketPair<sockaddr_in>(bound, connected, type,
                                                        dual_stack);
    }
    return CreateTCPAcceptBindSocketPair<sockaddr_in6>(bound, connected, type,
                                                       dual_stack);
  };
}

Creator<SocketPair> TCPAcceptBindPersistentListenerSocketPairCreator(
    int domain, int type, int protocol, bool dual_stack) {
  // These are lazily initialized below, on the first call to the returned
  // lambda. These values are private to each returned lambda, but shared across
  // invocations of a specific lambda.
  //
  // The sharing allows pairs created with the same parameters to share a
  // listener. This prevents future connects from failing if the connecting
  // socket selects a port which had previously been used by a listening socket
  // that still has some connections in TIME-WAIT.
  //
  // The lazy initialization is to avoid creating sockets during parameter
  // enumeration. This is important because parameters are enumerated during the
  // build process where networking may not be available.
  auto listener = std::make_shared<absl::optional<int>>(absl::optional<int>());
  auto addr4 = std::make_shared<absl::optional<sockaddr_in>>(
      absl::optional<sockaddr_in>());
  auto addr6 = std::make_shared<absl::optional<sockaddr_in6>>(
      absl::optional<sockaddr_in6>());

  return [=]() -> PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> {
    int connected;
    RETURN_ERROR_IF_SYSCALL_FAIL(connected = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    // Share the listener across invocations.
    if (!listener->has_value()) {
      int fd = socket(domain, type, protocol);
      if (fd < 0) {
        return PosixError(errno, absl::StrCat("socket(", domain, ", ", type,
                                              ", ", protocol, ")"));
      }
      listener->emplace(fd);
      MaybeSave();  // Successful socket creation.
    }

    // Bind the listener once, but create a new connect/accept pair each
    // time.
    if (domain == AF_INET) {
      if (!addr4->has_value()) {
        addr4->emplace(
            TCPBindAndListen<sockaddr_in>(listener->value(), dual_stack)
                .ValueOrDie());
      }
      return CreateTCPConnectAcceptSocketPair(listener->value(), connected,
                                              type, dual_stack, addr4->value());
    }
    if (!addr6->has_value()) {
      addr6->emplace(
          TCPBindAndListen<sockaddr_in6>(listener->value(), dual_stack)
              .ValueOrDie());
    }
    return CreateTCPConnectAcceptSocketPair(listener->value(), connected, type,
                                            dual_stack, addr6->value());
  };
}

template <typename T>
PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> CreateUDPBoundSocketPair(
    int sock1, int sock2, int type, bool dual_stack) {
  ASSIGN_OR_RETURN_ERRNO(T addr1, BindIP<T>(sock1, dual_stack));
  ASSIGN_OR_RETURN_ERRNO(T addr2, BindIP<T>(sock2, dual_stack));

  return absl::make_unique<AddrFDSocketPair>(sock1, sock2, addr1, addr2);
}

template <typename T>
PosixErrorOr<std::unique_ptr<AddrFDSocketPair>>
CreateUDPBidirectionalBindSocketPair(int sock1, int sock2, int type,
                                     bool dual_stack) {
  ASSIGN_OR_RETURN_ERRNO(
      auto socks, CreateUDPBoundSocketPair<T>(sock1, sock2, type, dual_stack));

  // Connect sock1 to sock2.
  RETURN_ERROR_IF_SYSCALL_FAIL(connect(socks->first_fd(), socks->second_addr(),
                                       socks->second_addr_size()));
  MaybeSave();  // Successful connection.

  // Connect sock2 to sock1.
  RETURN_ERROR_IF_SYSCALL_FAIL(connect(socks->second_fd(), socks->first_addr(),
                                       socks->first_addr_size()));
  MaybeSave();  // Successful connection.

  return socks;
}

Creator<SocketPair> UDPBidirectionalBindSocketPairCreator(int domain, int type,
                                                          int protocol,
                                                          bool dual_stack) {
  return [=]() -> PosixErrorOr<std::unique_ptr<AddrFDSocketPair>> {
    int sock1;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock1 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    int sock2;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock2 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    if (domain == AF_INET) {
      return CreateUDPBidirectionalBindSocketPair<sockaddr_in>(
          sock1, sock2, type, dual_stack);
    }
    return CreateUDPBidirectionalBindSocketPair<sockaddr_in6>(sock1, sock2,
                                                              type, dual_stack);
  };
}

Creator<SocketPair> UDPUnboundSocketPairCreator(int domain, int type,
                                                int protocol, bool dual_stack) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FDSocketPair>> {
    int sock1;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock1 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    int sock2;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock2 = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    return absl::make_unique<FDSocketPair>(sock1, sock2);
  };
}

SocketPairKind Reversed(SocketPairKind const& base) {
  auto const& creator = base.creator;
  return SocketPairKind{
      absl::StrCat("reversed ", base.description), base.domain, base.type,
      base.protocol,
      [creator]() -> PosixErrorOr<std::unique_ptr<ReversedSocketPair>> {
        ASSIGN_OR_RETURN_ERRNO(auto creator_value, creator());
        return absl::make_unique<ReversedSocketPair>(std::move(creator_value));
      }};
}

Creator<FileDescriptor> UnboundSocketCreator(int domain, int type,
                                             int protocol) {
  return [=]() -> PosixErrorOr<std::unique_ptr<FileDescriptor>> {
    int sock;
    RETURN_ERROR_IF_SYSCALL_FAIL(sock = socket(domain, type, protocol));
    MaybeSave();  // Successful socket creation.

    return absl::make_unique<FileDescriptor>(sock);
  };
}

std::vector<SocketPairKind> IncludeReversals(std::vector<SocketPairKind> vec) {
  return ApplyVecToVec<SocketPairKind>(std::vector<Middleware>{NoOp, Reversed},
                                       vec);
}

SocketPairKind NoOp(SocketPairKind const& base) { return base; }

void TransferTest(int fd1, int fd2) {
  char buf1[20];
  RandomizeBuffer(buf1, sizeof(buf1));
  ASSERT_THAT(WriteFd(fd1, buf1, sizeof(buf1)),
              SyscallSucceedsWithValue(sizeof(buf1)));

  char buf2[20];
  ASSERT_THAT(ReadFd(fd2, buf2, sizeof(buf2)),
              SyscallSucceedsWithValue(sizeof(buf2)));

  EXPECT_EQ(0, memcmp(buf1, buf2, sizeof(buf1)));

  RandomizeBuffer(buf1, sizeof(buf1));
  ASSERT_THAT(WriteFd(fd2, buf1, sizeof(buf1)),
              SyscallSucceedsWithValue(sizeof(buf1)));

  ASSERT_THAT(ReadFd(fd1, buf2, sizeof(buf2)),
              SyscallSucceedsWithValue(sizeof(buf2)));

  EXPECT_EQ(0, memcmp(buf1, buf2, sizeof(buf1)));
}

// Initializes the given buffer with random data.
void RandomizeBuffer(char* ptr, size_t len) {
  uint32_t seed = time(nullptr);
  for (size_t i = 0; i < len; ++i) {
    ptr[i] = static_cast<char>(rand_r(&seed));
  }
}

size_t CalculateUnixSockAddrLen(const char* sun_path) {
  // Abstract addresses always return the full length.
  if (sun_path[0] == 0) {
    return sizeof(sockaddr_un);
  }
  // Filesystem addresses use the address length plus the 2 byte sun_family
  // and null terminator.
  return strlen(sun_path) + 3;
}

struct sockaddr_storage AddrFDSocketPair::to_storage(const sockaddr_un& addr) {
  struct sockaddr_storage addr_storage = {};
  memcpy(&addr_storage, &addr, sizeof(addr));
  return addr_storage;
}

struct sockaddr_storage AddrFDSocketPair::to_storage(const sockaddr_in& addr) {
  struct sockaddr_storage addr_storage = {};
  memcpy(&addr_storage, &addr, sizeof(addr));
  return addr_storage;
}

struct sockaddr_storage AddrFDSocketPair::to_storage(const sockaddr_in6& addr) {
  struct sockaddr_storage addr_storage = {};
  memcpy(&addr_storage, &addr, sizeof(addr));
  return addr_storage;
}

SocketKind SimpleSocket(int fam, int type, int proto) {
  return SocketKind{
      absl::StrCat("Family ", fam, ", type ", type, ", proto ", proto), fam,
      type, proto, SyscallSocketCreator(fam, type, proto)};
}

ssize_t SendLargeSendMsg(const std::unique_ptr<SocketPair>& sockets,
                         size_t size, bool reader) {
  const int rfd = sockets->second_fd();
  ScopedThread t([rfd, size, reader] {
    if (!reader) {
      return;
    }

    // Potentially too many syscalls in the loop.
    const DisableSave ds;

    std::vector<char> buf(size);
    size_t total = 0;

    while (total < size) {
      int ret = read(rfd, buf.data(), buf.size());
      if (ret == -1 && errno == EAGAIN) {
        continue;
      }
      if (ret > 0) {
        total += ret;
      }

      // Assert to return on first failure.
      ASSERT_THAT(ret, SyscallSucceeds());
    }
  });

  std::vector<char> buf(size);

  struct iovec iov = {};
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  return RetryEINTR(sendmsg)(sockets->first_fd(), &msg, 0);
}

namespace internal {
PosixErrorOr<int> TryPortAvailable(int port, AddressFamily family,
                                   SocketType type, bool reuse_addr) {
  if (port < 0) {
    return PosixError(EINVAL, "Invalid port");
  }

  // Both Ipv6 and Dualstack are AF_INET6.
  int sock_fam = (family == AddressFamily::kIpv4 ? AF_INET : AF_INET6);
  int sock_type = (type == SocketType::kTcp ? SOCK_STREAM : SOCK_DGRAM);
  ASSIGN_OR_RETURN_ERRNO(auto fd, Socket(sock_fam, sock_type, 0));

  if (reuse_addr) {
    int one = 1;
    RETURN_ERROR_IF_SYSCALL_FAIL(
        setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
  }

  // Try to bind.
  sockaddr_storage storage = {};
  int storage_size = 0;
  if (family == AddressFamily::kIpv4) {
    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&storage);
    storage_size = sizeof(*addr);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
  } else {
    sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(&storage);
    storage_size = sizeof(*addr);
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(port);
    if (family == AddressFamily::kDualStack) {
      inet_pton(AF_INET6, "::ffff:0.0.0.0",
                reinterpret_cast<void*>(&addr->sin6_addr.s6_addr));
    } else {
      addr->sin6_addr = in6addr_any;
    }
  }

  RETURN_ERROR_IF_SYSCALL_FAIL(
      bind(fd.get(), reinterpret_cast<sockaddr*>(&storage), storage_size));

  // If the user specified 0 as the port, we will return the port that the
  // kernel gave us, otherwise we will validate that this socket bound to the
  // requested port.
  sockaddr_storage bound_storage = {};
  socklen_t bound_storage_size = sizeof(bound_storage);
  RETURN_ERROR_IF_SYSCALL_FAIL(
      getsockname(fd.get(), reinterpret_cast<sockaddr*>(&bound_storage),
                  &bound_storage_size));

  int available_port = -1;
  if (bound_storage.ss_family == AF_INET) {
    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&bound_storage);
    available_port = ntohs(addr->sin_port);
  } else if (bound_storage.ss_family == AF_INET6) {
    sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(&bound_storage);
    available_port = ntohs(addr->sin6_port);
  } else {
    return PosixError(EPROTOTYPE, "Getsockname returned invalid family");
  }

  // If we requested a specific port make sure our bound port is that port.
  if (port != 0 && available_port != port) {
    return PosixError(EINVAL,
                      absl::StrCat("Bound port ", available_port,
                                   " was not equal to requested port ", port));
  }

  // If we're trying to do a TCP socket, let's also try to listen.
  if (type == SocketType::kTcp) {
    RETURN_ERROR_IF_SYSCALL_FAIL(listen(fd.get(), 1));
  }

  return available_port;
}
}  // namespace internal

PosixErrorOr<int> SendMsg(int sock, msghdr* msg, char buf[], int buf_size) {
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = buf_size;
  msg->msg_iov = &iov;
  msg->msg_iovlen = 1;

  int ret;
  RETURN_ERROR_IF_SYSCALL_FAIL(ret = RetryEINTR(sendmsg)(sock, msg, 0));
  return ret;
}

void RecvNoData(int sock) {
  char data = 0;
  struct iovec iov;
  iov.iov_base = &data;
  iov.iov_len = 1;
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  ASSERT_THAT(RetryEINTR(recvmsg)(sock, &msg, MSG_DONTWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

TestAddress V4Any() {
  TestAddress t("V4Any");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr = htonl(INADDR_ANY);
  return t;
}

TestAddress V4Loopback() {
  TestAddress t("V4Loopback");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      htonl(INADDR_LOOPBACK);
  return t;
}

TestAddress V4MappedAny() {
  TestAddress t("V4MappedAny");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  inet_pton(AF_INET6, "::ffff:0.0.0.0",
            reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr.s6_addr);
  return t;
}

TestAddress V4MappedLoopback() {
  TestAddress t("V4MappedLoopback");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  inet_pton(AF_INET6, "::ffff:127.0.0.1",
            reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr.s6_addr);
  return t;
}

TestAddress V4Multicast() {
  TestAddress t("V4Multicast");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      inet_addr(kMulticastAddress);
  return t;
}

TestAddress V4Broadcast() {
  TestAddress t("V4Broadcast");
  t.addr.ss_family = AF_INET;
  t.addr_len = sizeof(sockaddr_in);
  reinterpret_cast<sockaddr_in*>(&t.addr)->sin_addr.s_addr =
      htonl(INADDR_BROADCAST);
  return t;
}

TestAddress V6Any() {
  TestAddress t("V6Any");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr = in6addr_any;
  return t;
}

TestAddress V6Loopback() {
  TestAddress t("V6Loopback");
  t.addr.ss_family = AF_INET6;
  t.addr_len = sizeof(sockaddr_in6);
  reinterpret_cast<sockaddr_in6*>(&t.addr)->sin6_addr = in6addr_loopback;
  return t;
}

// Checksum computes the internet checksum of a buffer.
uint16_t Checksum(uint16_t* buf, ssize_t buf_size) {
  // Add up the 16-bit values in the buffer.
  uint32_t total = 0;
  for (unsigned int i = 0; i < buf_size; i += sizeof(*buf)) {
    total += *buf;
    buf++;
  }

  // If buf has an odd size, add the remaining byte.
  if (buf_size % 2) {
    total += *(reinterpret_cast<unsigned char*>(buf) - 1);
  }

  // This carries any bits past the lower 16 until everything fits in 16 bits.
  while (total >> 16) {
    uint16_t lower = total & 0xffff;
    uint16_t upper = total >> 16;
    total = lower + upper;
  }

  return ~total;
}

uint16_t IPChecksum(struct iphdr ip) {
  return Checksum(reinterpret_cast<uint16_t*>(&ip), sizeof(ip));
}

// The pseudo-header defined in RFC 768 for calculating the UDP checksum.
struct udp_pseudo_hdr {
  uint32_t srcip;
  uint32_t destip;
  char zero;
  char protocol;
  uint16_t udplen;
};

uint16_t UDPChecksum(struct iphdr iphdr, struct udphdr udphdr,
                     const char* payload, ssize_t payload_len) {
  struct udp_pseudo_hdr phdr = {};
  phdr.srcip = iphdr.saddr;
  phdr.destip = iphdr.daddr;
  phdr.zero = 0;
  phdr.protocol = IPPROTO_UDP;
  phdr.udplen = udphdr.len;

  ssize_t buf_size = sizeof(phdr) + sizeof(udphdr) + payload_len;
  char* buf = static_cast<char*>(malloc(buf_size));
  memcpy(buf, &phdr, sizeof(phdr));
  memcpy(buf + sizeof(phdr), &udphdr, sizeof(udphdr));
  memcpy(buf + sizeof(phdr) + sizeof(udphdr), payload, payload_len);

  uint16_t csum = Checksum(reinterpret_cast<uint16_t*>(buf), buf_size);
  free(buf);
  return csum;
}

uint16_t ICMPChecksum(struct icmphdr icmphdr, const char* payload,
                      ssize_t payload_len) {
  ssize_t buf_size = sizeof(icmphdr) + payload_len;
  char* buf = static_cast<char*>(malloc(buf_size));
  memcpy(buf, &icmphdr, sizeof(icmphdr));
  memcpy(buf + sizeof(icmphdr), payload, payload_len);

  uint16_t csum = Checksum(reinterpret_cast<uint16_t*>(buf), buf_size);
  free(buf);
  return csum;
}

}  // namespace testing
}  // namespace gvisor
