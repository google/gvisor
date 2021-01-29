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

#include "test/util/logging.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

namespace gvisor {
namespace testing {

namespace {

// We implement this here instead of using test_util to avoid cyclic
// dependencies.
int Write(int fd, const char* buf, size_t size) {
  size_t written = 0;
  while (written < size) {
    int res = write(fd, buf + written, size - written);
    if (res < 0 && errno == EINTR) {
      continue;
    } else if (res <= 0) {
      break;
    }

    written += res;
  }
  return static_cast<int>(written);
}

// Write 32-bit decimal number to fd.
int WriteNumber(int fd, uint32_t val) {
  constexpr char kDigits[] = "0123456789";
  constexpr int kBase = 10;

  // 10 chars for 32-bit number in decimal, 1 char for the NUL-terminator.
  constexpr int kBufferSize = 11;
  char buf[kBufferSize];

  // Convert the number to string.
  char* s = buf + sizeof(buf) - 1;
  size_t size = 0;

  *s = '\0';
  do {
    s--;
    size++;

    *s = kDigits[val % kBase];
    val /= kBase;
  } while (val);

  return Write(fd, s, size);
}

}  // namespace

void CheckFailure(const char* cond, size_t cond_size, const char* msg,
                  size_t msg_size, int errno_value) {
  constexpr char kCheckFailure[] = "Check failed: ";
  Write(2, kCheckFailure, sizeof(kCheckFailure) - 1);
  Write(2, cond, cond_size);

  if (msg != nullptr) {
    Write(2, ": ", 2);
    Write(2, msg, msg_size);
  }

  if (errno_value != 0) {
    constexpr char kErrnoMessage[] = " (errno ";
    Write(2, kErrnoMessage, sizeof(kErrnoMessage) - 1);
    WriteNumber(2, errno_value);
    Write(2, ")", 1);
  }

  Write(2, "\n", 1);

  abort();
}

}  // namespace testing
}  // namespace gvisor
