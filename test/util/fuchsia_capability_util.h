// Copyright 2021 The gVisor Authors.
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

// Utilities for testing capabilities on Fuchsia.

#ifndef GVISOR_TEST_UTIL_FUCHSIA_CAPABILITY_UTIL_H_
#define GVISOR_TEST_UTIL_FUCHSIA_CAPABILITY_UTIL_H_

#ifdef __Fuchsia__

#include "test/util/posix_error.h"

#ifdef CAP_NET_RAW
#error "Fuchsia should not define CAP_NET_RAW"
#endif  // CAP_NET_RAW
#define CAP_NET_RAW 0

namespace gvisor {
namespace testing {

// HaveCapability returns true if the process has the specified EFFECTIVE
// capability.
PosixErrorOr<bool> HaveCapability(int cap);

}  // namespace testing
}  // namespace gvisor

#endif  // __Fuchsia__

#endif  // GVISOR_TEST_UTIL_FUCHSIA_CAPABILITY_UTIL_H_
