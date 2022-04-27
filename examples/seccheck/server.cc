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
#include "net/proto2/public/text_format.h"
#include "absl/strings/string_view.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"

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

std::string printShortTextProto(const proto2::Message& message) {
  std::string message_text;

  proto2::TextFormat::Printer printer;
  printer.SetSingleLineMode(true);
  printer.SetExpandAny(true);

  printer.PrintToString(message, &message_text);
  // Single line mode currently might have an extra space at the end.
  if (!message_text.empty() && message_text.back() == ' ') {
    message_text.pop_back();
  }

  return message_text;
}

template <class T>
void unpack(const google::protobuf::Any& any) {
  T evt;
  if (!any.UnpackTo(&evt)) {
    std::string any_textproto;
    proto2::TextFormat::PrintToString(any, &any_textproto);
    err(1, "UnpackTo(): %s", any_textproto.c_str());
  }
  auto name = any.type_url().substr(prefixLen);
  log("%.*s => %s\n", static_cast<int>(name.size()), name.data(),
      printShortTextProto(evt).c_str());
}

std::map<std::string, Callback> dispatchers = {
    {"gvisor.sentry.CloneInfo", unpack<::gvisor::sentry::CloneInfo>},
    {"gvisor.sentry.ExecveInfo", unpack<::gvisor::sentry::ExecveInfo>},
    {"gvisor.sentry.ExitNotifyParentInfo",
     unpack<::gvisor::sentry::ExitNotifyParentInfo>},
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

  close(sock);
  unlink(path.c_str());

  return 0;
}
