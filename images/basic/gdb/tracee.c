// Copyright 2026 The gVisor Authors.
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
#include <unistd.h>

static volatile int attached;

extern pid_t check_pid(void);

// Use a fixed mov/syscall sequence so systrap can patch this site.
__asm__(
    ".text\n"
    ".globl check_pid\n"
    ".type check_pid,@function\n"
    "check_pid:\n"
    "mov $39,%eax\n"
    ".globl check_pid_syscall\n"
    "check_pid_syscall:\n"
    "syscall\n"
    "ret\n"
    ".size check_pid,.-check_pid\n");

static pid_t check_after_attach(void) { return check_pid(); }

int main(int argc, char* argv[]) {
  if (argc > 1) {
    return check_pid() != getpid();
  }
  const pid_t expected = getpid();
  // Warm the syscall site before attaching so systrap can patch it.
  for (int i = 0; i < 100; ++i) {
    if (check_pid() != expected) {
      return 1;
    }
  }
  puts("ready");
  fflush(stdout);
  while (!attached) {
    if (check_pid() != expected) {
      return 1;
    }
  }
  if (check_after_attach() != expected) {
    return 1;
  }
  execl(argv[0], argv[0], "after-exec", NULL);
  return 1;
}
