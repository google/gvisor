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
#include <errno.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

// Tests that FIONREAD is supported with host FD.
void testFionread() {
  int size = 0;
  if (ioctl(STDOUT_FILENO, FIONREAD, &size) < 0) {
    err(1, "ioctl(stdin, FIONREAD)");
  }
  if (size != 0) {
    err(1, "FIONREAD wrong size, want: 0, got: %d", size);
  }
}

// Docker maps stdin to /dev/null which doesn't support epoll. Check that error
// is correctly propagated.
void testEpoll() {
  int fd = epoll_create(1);
  if (fd < 0) {
    err(1, "epoll_create");
  }

  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.u64 = 123;
  int res = epoll_ctl(fd, EPOLL_CTL_ADD, 0, &event);
  if (res != -1) {
    err(1, "epoll_ctl(EPOLL_CTL_ADD, stdin) should have failed");
  }
  if (errno != EPERM) {
    err(1, "epoll_ctl(EPOLL_CTL_ADD, stdin) should have returned EPERM");
  }
}

int main(int argc, char** argv) {
  testFionread();
  testEpoll();
  return 0;
}
