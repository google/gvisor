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
#include <sys/ioctl.h>
#include <unistd.h>

// Tests that FIONREAD is supported with host FD.
int main(int argc, char** argv) {
  int size = 0;
  if (ioctl(STDOUT_FILENO, FIONREAD, &size) < 0) {
    err(1, "ioctl(stdin, FIONREAD)");
  }
  if (size != 0) {
    err(1, "FIONREAD wrong size, want: 0, got: %d", size);
  }
  return 0;
}
