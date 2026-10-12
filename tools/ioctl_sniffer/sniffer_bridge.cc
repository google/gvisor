// Copyright 2024 The gVisor Authors.
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

#include "tools/ioctl_sniffer/sniffer_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

#include "tools/ioctl_sniffer/ioctl.pb.h"

namespace {

void WriteAll(int fd, std::string_view bytes) {
  while (!bytes.empty()) {
    const ssize_t n = send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    if (n < 0) {
      const int send_errno = errno;
      if (send_errno == EINTR) {
        continue;
      }
      std::cerr << "Failed to write ioctl message: " << strerror(send_errno)
                << "\n";
      exit(1);
    }
    if (n == 0) {
      std::cerr << "Failed to write ioctl message: no progress\n";
      exit(1);
    }
    bytes.remove_prefix(static_cast<size_t>(n));
  }
}

class Connection {
 public:
  Connection() = default;
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;

  ~Connection() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  void Write(const gvisor::Ioctl& ioctl) {
    const pid_t tid = syscall(SYS_gettid);
    if (owner_tid_ != tid) {
      // A fork inherits the calling thread's connection. The child needs its
      // own stream so frames from the two processes cannot interleave.
      if (fd_ >= 0) {
        close(fd_);
      }
      Connect();
      owner_tid_ = tid;
    }

    buffer_.resize(sizeof(uint64_t));
    if (!ioctl.AppendToString(&buffer_)) {
      std::cerr << "Failed to serialize ioctl message\n";
      exit(1);
    }
    const uint64_t size = buffer_.size() - sizeof(uint64_t);
    memcpy(buffer_.data(), &size, sizeof(size));
    WriteAll(fd_, buffer_);
  }

 private:
  void Connect() {
    fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
      const int socket_errno = errno;
      std::cerr << "Failed to create socket: " << strerror(socket_errno)
                << "\n";
      exit(1);
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    const char* path = std::getenv("GVISOR_IOCTL_SNIFFER_SOCKET_PATH");
    if (path == nullptr || strlen(path) >= sizeof(addr.sun_path)) {
      std::cerr << "Missing or overlong GVISOR_IOCTL_SNIFFER_SOCKET_PATH\n";
      exit(1);
    }
    memcpy(addr.sun_path, path, strlen(path) + 1);
    if (connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      const int connect_errno = errno;
      std::cerr << "Failed to connect to socket " << addr.sun_path << ": "
                << strerror(connect_errno) << "\n";
      exit(1);
    }
  }

  pid_t owner_tid_ = -1;
  int fd_ = -1;
  std::string buffer_;
};

}  // namespace

void WriteIoctlProto(const gvisor::Ioctl& ioctl) {
  static thread_local Connection connection;
  connection.Write(ioctl);
}
