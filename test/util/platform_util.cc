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

#include <vector>

#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PlatformSupport PlatformSupport32Bit() {
  const char* support = std::getenv("GVISOR_PLATFORM_SUPPORT");
  if (support != nullptr) {
    if (std::string(support).find("32BIT:TRUE") != std::string::npos) {
      return PlatformSupport::Allowed;
    }
    if (std::string(support).find("32BIT:FALSE") != std::string::npos) {
      return PlatformSupport::NotSupported;
    }
    std::cerr << "GVISOR_PLATFORM_SUPPORT variable does not contain 32BIT "
                 "support information: "
              << support << std::endl;
    TEST_CHECK(false);
  }
  std::cerr << "GVISOR_PLATFORM_SUPPORT variable undefined" << std::endl;
  TEST_CHECK(false);
}

PlatformSupport PlatformSupportAlignmentCheck() {
  const char* support = std::getenv("GVISOR_PLATFORM_SUPPORT");
  if (support != nullptr) {
    if (std::string(support).find("ALIGNMENT_CHECK:TRUE") !=
        std::string::npos) {
      return PlatformSupport::Allowed;
    }
    if (std::string(support).find("ALIGNMENT_CHECK:FALSE") !=
        std::string::npos) {
      return PlatformSupport::NotSupported;
    }
    std::cerr
        << "GVISOR_PLATFORM_SUPPORT variable does not contain ALIGNMENT_CHECK "
           "support information: "
        << support << std::endl;
    TEST_CHECK(false);
  }
  std::cerr << "GVISOR_PLATFORM_SUPPORT variable undefined" << std::endl;
  TEST_CHECK(false);
}

PlatformSupport PlatformSupportMultiProcess() {
  const char* support = std::getenv("GVISOR_PLATFORM_SUPPORT");
  if (support != nullptr) {
    if (std::string(support).find("MULTIPROCESS:TRUE") != std::string::npos) {
      return PlatformSupport::Allowed;
    }
    if (std::string(support).find("MULTIPROCESS:FALSE") != std::string::npos) {
      return PlatformSupport::NotSupported;
    }
    std::cerr
        << "GVISOR_PLATFORM_SUPPORT variable does not contain MULTIPROCESS "
           "support information: "
        << support << std::endl;
    TEST_CHECK(false);
  }
  std::cerr << "GVISOR_PLATFORM_SUPPORT variable undefined" << std::endl;
  TEST_CHECK(false);
}

PlatformSupport PlatformSupportInt3() {
  const char* support = std::getenv("GVISOR_PLATFORM_SUPPORT");
  if (support != nullptr) {
    if (std::string(support).find("INT3:TRUE") != std::string::npos) {
      return PlatformSupport::Allowed;
    }
    if (std::string(support).find("INT3:FALSE") != std::string::npos) {
      return PlatformSupport::NotSupported;
    }
    std::cerr << "GVISOR_PLATFORM_SUPPORT variable does not contain INT3 "
                 "support information: "
              << support << std::endl;
    TEST_CHECK(false);
  }
  std::cerr << "GVISOR_PLATFORM_SUPPORT variable undefined" << std::endl;
  TEST_CHECK(false);
}

PlatformSupport PlatformSupportVsyscall() {
  const char* support = std::getenv("GVISOR_PLATFORM_SUPPORT");
  if (support != nullptr) {
    if (std::string(support).find("VSYSCALL:TRUE") != std::string::npos) {
      return PlatformSupport::Allowed;
    }
    if (std::string(support).find("VSYSCALL:FALSE") != std::string::npos) {
      return PlatformSupport::NotSupported;
    }
    std::cerr << "GVISOR_PLATFORM_SUPPORT variable does not contain VSYSCALL "
                 "support information: "
              << support << std::endl;
    TEST_CHECK(false);
  }
  std::cerr << "GVISOR_PLATFORM_SUPPORT variable undefined" << std::endl;
  TEST_CHECK(false);
}

}  // namespace testing
}  // namespace gvisor
