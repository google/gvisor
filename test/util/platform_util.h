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

#ifndef GVISOR_TEST_UTIL_PLATFORM_UTIL_H_
#define GVISOR_TEST_UTIL_PLATFORM_UTIL_H_

namespace gvisor {
namespace testing {

// PlatformSupport is a generic enumeration of classes of support.
//
// It is up to the individual functions and callers to agree on the precise
// definition for each case. The document here generally refers to 32-bit
// as an example. Many cases will use only NotSupported and Allowed.
enum class PlatformSupport {
  // The feature is not supported on the current platform.
  //
  // In the case of 32-bit, this means that calls will generally be interpreted
  // as 64-bit calls, and there is no support for 32-bit binaries, long calls,
  // etc. This usually means that the underlying implementation just pretends
  // that 32-bit doesn't exist.
  NotSupported,

  // Calls will be ignored by the kernel with a fixed error.
  Ignored,

  // Calls will result in a SIGSEGV or similar fault.
  Segfault,

  // The feature is supported as expected.
  //
  // In the case of 32-bit, this means that the system call or far call will be
  // handled properly.
  Allowed,
};

PlatformSupport PlatformSupport32Bit();
PlatformSupport PlatformSupportAlignmentCheck();
PlatformSupport PlatformSupportMultiProcess();
PlatformSupport PlatformSupportInt3();
PlatformSupport PlatformSupportVsyscall();

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_PLATFORM_UTIL_H_
