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

#include "test/util/platform_util.h"

#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PlatformSupport PlatformSupport32Bit() {
  if (GvisorPlatform() == Platform::kPtrace ||
      GvisorPlatform() == Platform::kKVM) {
    return PlatformSupport::NotSupported;
  } else {
    return PlatformSupport::Allowed;
  }
}

PlatformSupport PlatformSupportAlignmentCheck() {
  return PlatformSupport::Allowed;
}

PlatformSupport PlatformSupportMultiProcess() {
  return PlatformSupport::Allowed;
}

PlatformSupport PlatformSupportInt3() {
  if (GvisorPlatform() == Platform::kKVM) {
    return PlatformSupport::NotSupported;
  } else {
    return PlatformSupport::Allowed;
  }
}

}  // namespace testing
}  // namespace gvisor
