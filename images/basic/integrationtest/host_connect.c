// Copyright 2022 The gVisor Authors.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char** argv) {
  int fd;
  struct sockaddr_un addr;
  char buff[10];

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    exit(1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, argv[1]);
  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("connect");
    exit(1);
  }

  strcpy(buff, "Hello");
  if (send(fd, buff, strlen(buff) + 1, 0) == -1) {
    perror("send");
    exit(1);
  }

  close(fd);
  exit(0);
}
