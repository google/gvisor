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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
  if (argc <= 2) {
    fprintf(stderr, "error: must provide a namespace file.\n");
    fprintf(stderr, "usage: %s <file> [arguments...]\n", argv[0]);
    return 1;
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "error opening %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  if (setns(fd, 0) < 0) {
    fprintf(stderr, "error joining %s: %s\n", argv[1], strerror(errno));
    return 1;
  }

  execvp(argv[2], &argv[2]);
  return 1;
}
