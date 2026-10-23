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

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>

// Keep only the MM descriptor alive. NVIDIA retains the original UVM file
// through this descriptor even after the application's original FD is closed.
int main() {
  int uvm = open("/dev/nvidia-uvm", O_RDWR | O_CLOEXEC);
  int mm = open("/dev/nvidia-uvm", O_RDWR | O_CLOEXEC);
  struct {
    uint64_t flags;
    uint32_t status;
    uint32_t padding;
  } init{};
  if (uvm < 0 || mm < 0 || ioctl(uvm, 0x30000001, &init) != 0 || init.status) {
    std::fprintf(stderr, "FAIL: UVM_INITIALIZE: status=%#x\n", init.status);
    return 1;
  }
  struct {
    int32_t fd;
    uint32_t status;
  } mm_init{uvm, 0};
  if (ioctl(mm, 75, &mm_init) != 0) {
    std::perror("FAIL: UVM_MM_INITIALIZE");
    return 1;
  }
  // UVM_MM_INITIALIZE returns NV_WARN_NOTHING_TO_DO when the primary file
  // does not track an mm. Detect that mode without opening extra CUDA UVM FDs.
  constexpr uint32_t kNvWarnNothingToDo = 0x00010006;
  if (mm_init.status == kNvWarnNothingToDo) {
    std::puts("SKIP: UVM does not retain the application host mm");
    return 0;
  }
  if (mm_init.status) {
    std::fprintf(stderr, "FAIL: UVM_MM_INITIALIZE: status=%#x\n",
                 mm_init.status);
    return 1;
  }
  if (close(uvm) != 0) {
    std::perror("FAIL: close original UVM FD");
    return 1;
  }
  std::puts("READY: only the UVM MM descriptor remains open");
  std::fflush(stdout);
  for (;;) pause();
}
