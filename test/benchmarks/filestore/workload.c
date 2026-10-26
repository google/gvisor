// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A static workload for the filestore checkpoint benchmark. The complete
// payload is verified after every restore, outside the measured interval.
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Noreturn void fail(const char* what) {
  perror(what);
  exit(1);
}

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  if (!strcmp(argv[1], "ready")) return access("/ready", F_OK) != 0;
  if (!strcmp(argv[1], "mark")) {
    int fd = open("/clone-marker", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) fail("marker");
    if (write(fd, "clone", 5) != 5) fail("write marker");
    return close(fd) != 0;
  }
  if (!strcmp(argv[1], "unmarked")) return access("/clone-marker", F_OK) == 0;
  if (argc != 3) return 2;
  uint64_t size = strtoull(argv[2], NULL, 10);
  int verify = !strcmp(argv[1], "verify");
  int fd =
      open("/payload", verify ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) fail("payload");
  unsigned char expected[65536], actual[65536];
  uint64_t state = 0x9e3779b97f4a7c15ULL;
  for (uint64_t off = 0; off < size;) {
    size_t n = size - off < sizeof(expected) ? size - off : sizeof(expected);
    for (size_t i = 0; i < n; i++) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      expected[i] = state;
    }
    size_t left = n;
    while (left) {
      size_t done = n - left;
      ssize_t got = verify ? read(fd, actual + done, left)
                           : write(fd, expected + done, left);
      if (got <= 0 || (size_t)got > left) fail(verify ? "read" : "write");
      left -= (size_t)got;
    }
    if (verify && memcmp(expected, actual, n)) {
      fprintf(stderr, "payload differs at offset %llu\n",
              (unsigned long long)off);
      return 1;
    }
    off += n;
  }
  if (verify) {
    if (read(fd, actual, 1) != 0) return 1;
    return close(fd) != 0;
  }
  if (fsync(fd)) fail("fsync");
  if (close(fd)) fail("close");
  fd = open("/ready", O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) fail("ready");
  if (close(fd)) fail("close ready");
  for (;;) pause();
}
