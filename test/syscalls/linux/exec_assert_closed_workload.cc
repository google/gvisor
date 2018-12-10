// Copyright 2018 Google LLC
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

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>

#include "absl/strings/numbers.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "need two arguments, got " << argc;
    exit(1);
  }
  int fd;
  if (!absl::SimpleAtoi(argv[1], &fd)) {
    std::cerr << "fd: " << argv[1] << " could not be parsed" << std::endl;
    exit(1);
  }
  struct stat s;
  if (fstat(fd, &s) == 0) {
    std::cerr << "fd: " << argv[1] << " should not be valid" << std::endl;
    exit(2);
  }
  if (errno != EBADF) {
    std::cerr << "fstat fd: " << argv[1] << " got errno: " << errno
              << " wanted: " << EBADF << std::endl;
    exit(1);
  }
  return 0;
}
