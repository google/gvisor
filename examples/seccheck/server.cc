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

#include "google/protobuf/any.pb.h"
#include "absl/cleanup/cleanup.h"
#include "absl/strings/string_view.h"
#include "pkg/sentry/seccheck/points/container.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"

typedef std::function<void(const google::protobuf::Any& any)> Callback;

constexpr size_t prefixLen = sizeof("type.googleapis.com/") - 1;
constexpr size_t maxEventSize = 300 * 1024;

bool quiet = false;

#pragma pack(push, 1)
struct header {
  uint16_t header_size;
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
void unpackSyscall(const google::protobuf::Any& any) {
  T evt;
  if (!any.UnpackTo(&evt)) {
    err(1, "UnpackTo(): %s", any.DebugString().c_str());
  }
  auto last_dot = any.type_url().find_last_of('.');
  if (last_dot == std::string::npos) {
    err(1, "invalid name: %.*s", static_cast<int>(any.type_url().size()),
        any.type_url().data());
  }
  auto name = any.type_url().substr(last_dot + 1);
  log("%s %.*s %s\n", evt.has_exit() ? "X" : "E", static_cast<int>(name.size()),
      name.data(), evt.ShortDebugString().c_str());
}

template <class T>
void unpack(const google::protobuf::Any& any) {
  T evt;
  if (!any.UnpackTo(&evt)) {
    err(1, "UnpackTo(): %s", any.DebugString().c_str());
  }
  auto name = any.type_url().substr(prefixLen);
  log("%.*s => %s\n", static_cast<int>(name.size()), name.data(),
      evt.ShortDebugString().c_str());
}

std::map<std::string, Callback> dispatchers = {
    {"gvisor.syscall.Syscall", unpackSyscall<::gvisor::syscall::Syscall>},
    {"gvisor.syscall.Read", unpackSyscall<::gvisor::syscall::Read>},
    {"gvisor.syscall.Open", unpackSyscall<::gvisor::syscall::Open>},
    {"gvisor.syscall.Connect", unpackSyscall<::gvisor::syscall::Connect>},
    {"gvisor.syscall.Execve", unpackSyscall<::gvisor::syscall::Execve>},
    {"gvisor.syscall.Close", unpackSyscall<::gvisor::syscall::Close>},
    {"gvisor.syscall.Socket", unpackSyscall<::gvisor::syscall::Socket>},
    {"gvisor.container.Start", unpack<::gvisor::container::Start>},
    {"gvisor.sentry.CloneInfo", unpack<::gvisor::sentry::CloneInfo>},
    {"gvisor.sentry.ExecveInfo", unpack<::gvisor::sentry::ExecveInfo>},
    {"gvisor.sentry.ExitNotifyParentInfo",
     unpack<::gvisor::sentry::ExitNotifyParentInfo>},
    {"gvisor.sentry.TaskExit", unpack<::gvisor::sentry::TaskExit>},
};

void unpack(const absl::string_view buf) {
  const header* hdr = reinterpret_cast<const header*>(&buf[0]);
  size_t payload_size = buf.size() - hdr->header_size;
  if (payload_size <= 0) {
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

  google::protobuf::Any any;
  if (!any.ParseFromArray(proto.data(), proto.size())) {
    err(1, "invalid proto message");
  }

  auto url = any.type_url();
  if (url.size() <= prefixLen) {
    printf("Invalid URL %s\n", any.type_url().data());
    return;
  }
  const std::string name(url.substr(prefixLen));
  Callback cb = dispatchers[name];
  if (cb == nullptr) {
    printf("No callback registered for %s. Skipping it...\n", name.c_str());
  } else {
    cb(any);
  }
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
        std::array<char, maxEventSize> buf;
        int bytes = read(client, buf.data(), buf.size());
        if (bytes < 0) {
          err(1, "read");
        } else if (bytes > 0) {
          unpack(absl::string_view(buf.data(), bytes));
        }
      }
      if ((evts[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0) {
        int client = evts[i].data.fd;
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

    struct epoll_event evt;
    evt.data.fd = client;
    evt.events = EPOLLIN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &evt) < 0) {
      err(1, "epoll_ctl(ADD)");
    }
  }
}
