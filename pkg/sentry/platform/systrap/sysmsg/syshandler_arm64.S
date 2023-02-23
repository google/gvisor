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

#include "sysmsg_offsets.h"

.globl __export_syshandler;
.type __export_syshandler, @function;
.align 4, 0x00;
// syshandler is not implemented for ARM64 yet.
__export_syshandler:
  // BRK will generate an Debug Exception which cannot be masked.
  // See: https://developer.arm.com/documentation/102120/0100/Debug-exceptions
  // The immediate unsigned operand needs to be <= 0xffff.
  // See: https://developer.arm.com/documentation/dui0802/b/A64-General-Instructions/BRK
  BRK #0xdead

.size __export_syshandler, . - __export_syshandler
