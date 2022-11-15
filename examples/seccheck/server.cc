// Copyright 2021 The gVisor Authors.
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

#include <err.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <string>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/string_view.h"
#include "pkg/sentry/seccheck/points/common.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"

typedef std::function<void(absl::string_view buf)> Callback;

constexpr size_t maxEventSize = 300 * 1024;

bool quiet = false;

#pragma pack(push, 1)
struct header {
  uint16_t header_size;
  uint16_t message_type;
  uint32_t dropped_count;
};
#pragma pack(pop)

void log(const char* fmt, ...) {
  if (!quiet) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
  }
}

template <class T>
void unpackSyscall(absl::string_view buf) {
  T evt;
  if (!evt.ParseFromArray(buf.data(), buf.size())) {
    err(1, "ParseFromString(): %.*s", static_cast<int>(buf.size()), buf.data());
  }
  log("%s %s %s\n", evt.has_exit() ? "X" : "E",
      evt.GetMetadata().descriptor->name().c_str(),
      evt.ShortDebugString().c_str());
}

template <class T>
void unpack(absl::string_view buf) {
  T evt;
  if (!evt.ParseFromArray(buf.data(), buf.size())) {
    err(1, "ParseFromString(): %.*s", static_cast<int>(buf.size()), buf.data());
  }
  log("%s => %s\n", evt.GetMetadata().descriptor->name().c_str(),
      evt.ShortDebugString().c_str());
}

// List of dispatchers indexed based on MessageType enum values.
std::vector<Callback> dispatchers = {
    nullptr,
    unpack<::gvisor::container::Start>,
    unpack<::gvisor::sentry::CloneInfo>,
    unpack<::gvisor::sentry::ExecveInfo>,
    unpack<::gvisor::sentry::ExitNotifyParentInfo>,
    unpack<::gvisor::sentry::TaskExit>,
    unpackSyscall<::gvisor::syscall::Syscall>,
    unpackSyscall<::gvisor::syscall::Open>,
    unpackSyscall<::gvisor::syscall::Close>,
    unpackSyscall<::gvisor::syscall::Read>,
    unpackSyscall<::gvisor::syscall::Connect>,
    unpackSyscall<::gvisor::syscall::Execve>,
    unpackSyscall<::gvisor::syscall::Socket>,
    unpackSyscall<::gvisor::syscall::Chdir>,
    unpackSyscall<::gvisor::syscall::Setid>,
    unpackSyscall<::gvisor::syscall::Setresid>,
    unpackSyscall<::gvisor::syscall::Dup>,
    unpackSyscall<::gvisor::syscall::Prlimit>,
    unpackSyscall<::gvisor::syscall::Pipe>,
    unpackSyscall<::gvisor::syscall::Fcntl>,
    unpackSyscall<::gvisor::syscall::Signalfd>,
    unpackSyscall<::gvisor::syscall::Eventfd>,
    unpackSyscall<::gvisor::syscall::Chroot>,
    unpackSyscall<::gvisor::syscall::Clone>,
    unpackSyscall<::gvisor::syscall::Bind>,
    unpackSyscall<::gvisor::syscall::Accept>,
    unpackSyscall<::gvisor::syscall::TimerfdCreate>,
    unpackSyscall<::gvisor::syscall::TimerfdSetTime>,
    unpackSyscall<::gvisor::syscall::TimerfdGetTime>,
    unpackSyscall<::gvisor::syscall::Fork>,
    unpackSyscall<::gvisor::syscall::InotifyInit>,
    unpackSyscall<::gvisor::syscall::InotifyAddWatch>,
    unpackSyscall<::gvisor::syscall::InotifyRmWatch>,
    unpackSyscall<::gvisor::syscall::SocketPair>,
    unpackSyscall<::gvisor::syscall::Write>,
};

void unpack(absl::string_view buf) {
  const header* hdr = reinterpret_cast<const header*>(&buf[0]);

  // Payload size can be zero when proto object contains only defaults values.
  size_t payload_size = buf.size() - hdr->header_size;
  if (payload_size < 0) {
    printf("Header size (%u) is larger than message %lu\n", hdr->header_size,
           buf.size());
    return;
  }

  auto proto = buf.substr(hdr->header_size);
  if (proto.size() < payload_size) {
    printf("Message was truncated, size: %lu, expected: %zu\n", proto.size(),
           payload_size);
    return;
  }

  if (hdr->message_type == 0 || hdr->message_type >= dispatchers.size()) {
    printf("Invalid message type: %u\n", hdr->message_type);
    return;
  }
  Callback cb = dispatchers[hdr->message_type];
  cb(proto);
}

bool readAndUnpack(int client) {
  std::array<char, maxEventSize> buf;
  int bytes = read(client, buf.data(), buf.size());
  if (bytes < 0) {
    err(1, "read");
  }
  if (bytes == 0) {
    return false;
  }
  unpack(absl::string_view(buf.data(), bytes));
  return true;
}

void* pollLoop(void* ptr) {
  const int poll_fd = *reinterpret_cast<int*>(&ptr);
  for (;;) {
    epoll_event evts[64];
    int nfds = epoll_wait(poll_fd, evts, 64, -1);
    if (nfds < 0) {
      if (errno == EINTR) {
        continue;
      }
      err(1, "epoll_wait");
    }

    for (int i = 0; i < nfds; ++i) {
      if (evts[i].events & EPOLLIN) {
        int client = evts[i].data.fd;
        readAndUnpack(client);
      }
      if ((evts[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0) {
        int client = evts[i].data.fd;
        // Drain any remaining messages before closing the socket.
        while (readAndUnpack(client)) {
        }
        close(client);
        printf("Connection closed\n");
      }
      if (evts[i].events & EPOLLERR) {
        printf("error\n");
      }
    }
  }
}

void startPollThread(int poll_fd) {
  pthread_t thread;
  if (pthread_create(&thread, nullptr, pollLoop,
                     reinterpret_cast<void*>(poll_fd)) != 0) {
    err(1, "pthread_create");
  }
  pthread_detach(thread);
}

// handshake performs version exchange with client. See common.proto for details
// about the protocol.
bool handshake(int client_fd) {
  std::vector<char> buf(10240);
  int bytes = read(client_fd, buf.data(), buf.size());
  if (bytes < 0) {
    printf("Error receiving handshake message: %d\n", errno);
    return false;
  } else if (bytes == buf.size()) {
    // Protect against the handshake becoming larger than the buffer allocated
    // for it.
    printf("handshake message too big\n");
    return false;
  }
  ::gvisor::common::Handshake in = {};
  if (!in.ParseFromArray(buf.data(), bytes)) {
    printf("Error parsing handshake message\n");
    return false;
  }

  constexpr uint32_t minSupportedVersion = 1;
  if (in.version() < minSupportedVersion) {
    printf("Client has unsupported version %u\n", in.version());
    return false;
  }

  ::gvisor::common::Handshake out;
  out.set_version(1);
  if (!out.SerializeToFileDescriptor(client_fd)) {
    printf("Error sending handshake message: %d\n", errno);
    return false;
  }
  return true;
}

extern "C" int main(int argc, char** argv) {
  for (int c = 0; (c = getopt(argc, argv, "q")) != -1;) {
    switch (c) {
      case 'q':
        quiet = true;
        break;
      default:
        exit(1);
    }
  }

  if (!quiet) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
  }
  std::string path("/tmp/gvisor_events.sock");
  if (optind < argc) {
    path = argv[optind];
  }
  if (path.empty()) {
    err(1, "empty file name");
  }
  printf("Socket address %s\n", path.c_str());
  unlink(path.c_str());

  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (sock < 0) {
    err(1, "socket");
  }
  auto sock_closer = absl::MakeCleanup([sock] { close(sock); });

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr))) {
    err(1, "bind");
  }
  if (listen(sock, 5) < 0) {
    err(1, "listen");
  }

  int epoll_fd = epoll_create(1);
  if (epoll_fd < 0) {
    err(1, "epoll_create");
  }
  auto epoll_closer = absl::MakeCleanup([epoll_fd] { close(epoll_fd); });
  startPollThread(epoll_fd);

  for (;;) {
    int client = accept(sock, nullptr, nullptr);
    if (client < 0) {
      if (errno == EINTR) {
        continue;
      }
      err(1, "accept");
    }
    printf("Connection accepted\n");

    if (!handshake(client)) {
      close(client);
      continue;
    }

    struct epoll_event evt;
    evt.data.fd = client;
    evt.events = EPOLLIN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &evt) < 0) {
      err(1, "epoll_ctl(ADD)");
    }
  }
}
