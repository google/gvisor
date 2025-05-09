// Copyright 2024 The gVisor Authors.
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

#include <fcntl.h>
#include <sys/ioctl.h>

// This test makes a non-existing ioctl call to the nvidia driver.
//  It's used to test that ioctl_sniffer is catching unsupported ioctls.
int main() {
  int fd = open("/dev/nvidiactl", O_RDWR);
  if (fd < 0) {
    return 1;
  }

  ioctl(fd, 0, nullptr);
  return 0;
}
