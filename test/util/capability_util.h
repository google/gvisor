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

// Utilities for testing capabilities.

#ifndef GVISOR_TEST_UTIL_CAPABILITY_UTIL_H_
#define GVISOR_TEST_UTIL_CAPABILITY_UTIL_H_

#include "test/util/posix_error.h"

#if defined(__Fuchsia__)
// Nothing to include.
#elif defined(__linux__)
#include "test/util/linux_capability_util.h"
#else
#error "Unhandled platform"
#endif

namespace gvisor {
namespace testing {

// HaveRawIPSocketCapability returns whether or not the process has access to
// raw IP sockets.
//
// Returns an error when raw IP socket access cannot be determined.
PosixErrorOr<bool> HaveRawIPSocketCapability();

// HavePacketSocketCapability returns whether or not the process has access to
// packet sockets.
//
// Returns an error when packet socket access cannot be determined.
PosixErrorOr<bool> HavePacketSocketCapability();

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_CAPABILITY_UTIL_H_
