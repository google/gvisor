// Copyright 2020 The gVisor Authors.
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
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Basic test for linkat(2). Syscall tests requires CAP_DAC_READ_SEARCH and it
// cannot use tricks like userns as root. For this reason, run a basic link test
// to ensure some coverage.
int main(int argc, char** argv) {
  const char kOldPath[] = "old.txt";
  int fd = open(kOldPath, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    errx(1, "open(%s) failed", kOldPath);
  }
  const char kData[] = "some random content";
  if (write(fd, kData, sizeof(kData)) < 0) {
    err(1, "write failed");
  }
  close(fd);

  struct stat old_stat;
  if (stat(kOldPath, &old_stat)) {
    errx(1, "stat(%s) failed", kOldPath);
  }

  const char kNewPath[] = "new.txt";
  if (link(kOldPath, kNewPath)) {
    errx(1, "link(%s, %s) failed", kOldPath, kNewPath);
  }

  struct stat new_stat;
  if (stat(kNewPath, &new_stat)) {
    errx(1, "stat(%s) failed", kNewPath);
  }

  // Check that files are the same.
  if (old_stat.st_dev != new_stat.st_dev) {
    errx(1, "files st_dev is different, want: %lu, got: %lu", old_stat.st_dev,
         new_stat.st_dev);
  }
  if (old_stat.st_ino != new_stat.st_ino) {
    errx(1, "files st_ino is different, want: %lu, got: %lu", old_stat.st_ino,
         new_stat.st_ino);
  }

  // Check that link count is correct.
  if (new_stat.st_nlink != old_stat.st_nlink + 1) {
    errx(1, "wrong nlink, want: %lu, got: %lu", old_stat.st_nlink + 1,
         new_stat.st_nlink);
  }

  // Check taht contents are the same.
  fd = open(kNewPath, O_RDONLY);
  if (fd < 0) {
    errx(1, "open(%s) failed", kNewPath);
  }
  char buf[sizeof(kData)] = {};
  if (read(fd, buf, sizeof(buf)) < 0) {
    err(1, "read failed");
  }
  close(fd);

  if (strcmp(buf, kData) != 0) {
    errx(1, "file content mismatch: %s", buf);
  }

  // Cleanup.
  if (unlink(kNewPath)) {
    errx(1, "unlink(%s) failed", kNewPath);
  }
  if (unlink(kOldPath)) {
    errx(1, "unlink(%s) failed", kOldPath);
  }

  // Success!
  return 0;
}
