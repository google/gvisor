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

#ifndef TOOLS_IOCTL_SNIFFER_IOCTL_HOOK_H_
#define TOOLS_IOCTL_SNIFFER_IOCTL_HOOK_H_

#include <stdint.h>

typedef int (*libc_ioctl)(int fd, uint64_t request, void *argp);

void init_libc_ioctl_handle();

#endif  // TOOLS_IOCTL_SNIFFER_IOCTL_HOOK_H_
