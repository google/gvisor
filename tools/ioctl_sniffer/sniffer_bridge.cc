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
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "tools/ioctl_sniffer/ioctl.pb.h"

thread_local pid_t socket_owner_tid = -1;
thread_local int socket_fd = -1;

void InitializeSocket() {
  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sfd < 0) {
    std::cerr << "Failed to create socket: " << strerror(errno) << "\n";
    exit(1);
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, std::getenv("GVISOR_IOCTL_SNIFFER_SOCKET_PATH"),
          sizeof(addr.sun_path));

  // Ensure the path is null terminated.
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

  if (connect(sfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    std::cerr << "Failed to connect to socket " << addr.sun_path << ": "
              << strerror(errno) << "\n";
    exit(1);
  }

  socket_owner_tid = gettid();
  socket_fd = sfd;
}

void WriteIoctlProto(gvisor::Ioctl &ioctl) {
  if (socket_owner_tid != gettid()) {
    InitializeSocket();
  }

  static thread_local std::vector<char> buffer;
  uint64_t size = ioctl.ByteSizeLong();
  buffer.resize(size + sizeof(size));

  // Write size of the proto message first.
  memcpy(buffer.data(), &size, sizeof(size));
  ioctl.SerializeToArray(buffer.data() + sizeof(size), size);

  write(socket_fd, buffer.data(), buffer.size());
}
