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
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "pkg/sentry/seccheck/points/common.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "google/protobuf/text_format.h"

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
std::string shortfmt(T msg) {
  std::string short_text_msg;
  google::protobuf::TextFormat::PrintToString(msg, &short_text_msg);
  return absl::StrReplaceAll(short_text_msg,
                             {{"\r\n", " "}, {"\n", " "}, {"\r", " "}});
}

template <class T>
void unpackSyscall(absl::string_view buf) {
  T evt;
  if (!evt.ParseFromArray(buf.data(), buf.size())) {
    err(1, "ParseFromString(): %.*s", static_cast<int>(buf.size()), buf.data());
  }
  absl::string_view name = evt.GetDescriptor()->name();
  log("%s %.*s %s\n", evt.has_exit() ? "X" : "E", static_cast<int>(name.size()),
      name.data(), shortfmt(evt).c_str());
}

template <class T>
void unpack(absl::string_view buf) {
  T evt;
  if (!evt.ParseFromArray(buf.data(), buf.size())) {
    err(1, "ParseFromString(): %.*s", static_cast<int>(buf.size()), buf.data());
  }
  absl::string_view name = evt.GetDescriptor()->name();
  log("%.*s => %s\n", static_cast<int>(name.size()), name.data(),
      shortfmt(evt).c_str());
}

// List of dispatchers indexed based on MessageType enum values.
// LINT.IfChange
const std::vector<Callback> dispatchers = [] {
  std::vector<Callback> result(::gvisor::common::MessageType_MAX + 1, nullptr);
  result[::gvisor::common::MESSAGE_CONTAINER_START] =
      unpack<::gvisor::container::Start>;
  result[::gvisor::common::MESSAGE_SENTRY_CLONE] =
      unpack<::gvisor::sentry::CloneInfo>;
  result[::gvisor::common::MESSAGE_SENTRY_EXEC] =
      unpack<::gvisor::sentry::ExecveInfo>;
  result[::gvisor::common::MESSAGE_SENTRY_EXIT_NOTIFY_PARENT] =
      unpack<::gvisor::sentry::ExitNotifyParentInfo>;
  result[::gvisor::common::MESSAGE_SENTRY_TASK_EXIT] =
      unpack<::gvisor::sentry::TaskExit>;
  result[::gvisor::common::MESSAGE_SYSCALL_RAW] =
      unpackSyscall<::gvisor::syscall::Syscall>;
  result[::gvisor::common::MESSAGE_SYSCALL_OPEN] =
      unpackSyscall<::gvisor::syscall::Open>;
  result[::gvisor::common::MESSAGE_SYSCALL_CLOSE] =
      unpackSyscall<::gvisor::syscall::Close>;
  result[::gvisor::common::MESSAGE_SYSCALL_READ] =
      unpackSyscall<::gvisor::syscall::Read>;
  result[::gvisor::common::MESSAGE_SYSCALL_CONNECT] =
      unpackSyscall<::gvisor::syscall::Connect>;
  result[::gvisor::common::MESSAGE_SYSCALL_EXECVE] =
      unpackSyscall<::gvisor::syscall::Execve>;
  result[::gvisor::common::MESSAGE_SYSCALL_SOCKET] =
      unpackSyscall<::gvisor::syscall::Socket>;
  result[::gvisor::common::MESSAGE_SYSCALL_CHDIR] =
      unpackSyscall<::gvisor::syscall::Chdir>;
  result[::gvisor::common::MESSAGE_SYSCALL_SETID] =
      unpackSyscall<::gvisor::syscall::Setid>;
  result[::gvisor::common::MESSAGE_SYSCALL_SETRESID] =
      unpackSyscall<::gvisor::syscall::Setresid>;
  result[::gvisor::common::MESSAGE_SYSCALL_DUP] =
      unpackSyscall<::gvisor::syscall::Dup>;
  result[::gvisor::common::MESSAGE_SYSCALL_PRLIMIT64] =
      unpackSyscall<::gvisor::syscall::Prlimit>;
  result[::gvisor::common::MESSAGE_SYSCALL_PIPE] =
      unpackSyscall<::gvisor::syscall::Pipe>;
  result[::gvisor::common::MESSAGE_SYSCALL_FCNTL] =
      unpackSyscall<::gvisor::syscall::Fcntl>;
  result[::gvisor::common::MESSAGE_SYSCALL_SIGNALFD] =
      unpackSyscall<::gvisor::syscall::Signalfd>;
  result[::gvisor::common::MESSAGE_SYSCALL_EVENTFD] =
      unpackSyscall<::gvisor::syscall::Eventfd>;
  result[::gvisor::common::MESSAGE_SYSCALL_CHROOT] =
      unpackSyscall<::gvisor::syscall::Chroot>;
  result[::gvisor::common::MESSAGE_SYSCALL_CLONE] =
      unpackSyscall<::gvisor::syscall::Clone>;
  result[::gvisor::common::MESSAGE_SYSCALL_BIND] =
      unpackSyscall<::gvisor::syscall::Bind>;
  result[::gvisor::common::MESSAGE_SYSCALL_ACCEPT] =
      unpackSyscall<::gvisor::syscall::Accept>;
  result[::gvisor::common::MESSAGE_SYSCALL_TIMERFD_CREATE] =
      unpackSyscall<::gvisor::syscall::TimerfdCreate>;
  result[::gvisor::common::MESSAGE_SYSCALL_TIMERFD_SETTIME] =
      unpackSyscall<::gvisor::syscall::TimerfdSetTime>;
  result[::gvisor::common::MESSAGE_SYSCALL_TIMERFD_GETTIME] =
      unpackSyscall<::gvisor::syscall::TimerfdGetTime>;
  result[::gvisor::common::MESSAGE_SYSCALL_FORK] =
      unpackSyscall<::gvisor::syscall::Fork>;
  result[::gvisor::common::MESSAGE_SYSCALL_INOTIFY_INIT] =
      unpackSyscall<::gvisor::syscall::InotifyInit>;
  result[::gvisor::common::MESSAGE_SYSCALL_INOTIFY_ADD_WATCH] =
      unpackSyscall<::gvisor::syscall::InotifyAddWatch>;
  result[::gvisor::common::MESSAGE_SYSCALL_INOTIFY_RM_WATCH] =
      unpackSyscall<::gvisor::syscall::InotifyRmWatch>;
  result[::gvisor::common::MESSAGE_SYSCALL_SOCKETPAIR] =
      unpackSyscall<::gvisor::syscall::SocketPair>;
  result[::gvisor::common::MESSAGE_SYSCALL_WRITE] =
      unpackSyscall<::gvisor::syscall::Write>;
  result[::gvisor::common::MESSAGE_SENTRY_MMAP] =
      unpack<::gvisor::sentry::MmapInfo>;
  result[::gvisor::common::MESSAGE_SYSCALL_MMAP] =
      unpackSyscall<::gvisor::syscall::Mmap>;
  result[::gvisor::common::MESSAGE_SYSCALL_LISTEN] =
      unpackSyscall<::gvisor::syscall::Listen>;
  result[::gvisor::common::MESSAGE_SYSCALL_PTRACE] =
      unpackSyscall<::gvisor::syscall::Ptrace>;
  return result;
}();
// LINT.ThenChange(../../pkg/sentry/seccheck/points/common.proto)

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
  if (cb) {
    cb(proto);
  } else {
    printf("No dispatcher configured for message type: %u\n",
           hdr->message_type);
  }
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
  } else if (bytes == (int)buf.size()) {
    // Protect against the handshake becoming larger than the buffer allocated
    // for it.
    printf("handshake message too big\n");
    return false;
  }
  ::gvisor::common::Handshake in = {};
  if (!in.ParseFromString(absl::string_view(buf.data(), bytes))) {
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

int main(int argc, char** argv) {
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
