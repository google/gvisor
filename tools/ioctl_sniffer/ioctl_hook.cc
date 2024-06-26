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

#define _GNU_SOURCE 1  // Needed for access to RTLD_NEXT
#include "tools/ioctl_sniffer/ioctl_hook.h"

#include <asm/ioctl.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "tools/ioctl_sniffer/ioctl.pb.h"
#include "tools/ioctl_sniffer/sniffer_bridge.h"

using gvisor::Ioctl;

libc_ioctl libc_ioctl_handle = nullptr;

void init_libc_ioctl_handle() {
  if (libc_ioctl_handle) {
    return;
  }

  libc_ioctl_handle = (libc_ioctl)dlsym(RTLD_NEXT, "ioctl");
  if (!libc_ioctl_handle) {
    std::cerr << "Failed to hook ioctl: " << dlerror() << "\n";
    exit(1);
  }
}

extern "C" {

int ioctl(int fd, uint64_t request, void *argp) {
  if (!libc_ioctl_handle) {
    init_libc_ioctl_handle();
  }

  // Forward the ioctl call.
  int ret = libc_ioctl_handle(fd, request, argp);

  // Check the file name to see if this is an Nvidia ioctl.
  // We only want to do protobuf logging for these ioctls.
  char file_name[PATH_MAX + 1];
  int n = readlink(absl::StrCat("/proc/self/fd/", fd).c_str(), file_name,
                   sizeof(file_name) - 1);
  if (n < 0) {
    return ret;
  }

  file_name[n] = '\0';
  if (!absl::StartsWith(file_name, "/dev/nvidia")) {
    return ret;
  }

  // Prepare ioctl proto for logging.
  Ioctl info;
  info.set_fd_path(file_name);
  info.set_request(request);
  info.set_ret(ret);

  // ioctl calls to uvm don't encode their size in the request.
  uint32_t arg_size =
      strcmp(file_name, "/dev/nvidia-uvm") == 0 ? 0 : _IOC_SIZE(request);
  info.set_arg_data(argp, arg_size);

  WriteIoctlProto(info);

  return ret;
}

}  // extern "C"
