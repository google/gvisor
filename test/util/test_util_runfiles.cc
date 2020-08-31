// Copyright 2019 The gVisor Authors.
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

#include <iostream>
#include <string>

#include "test/util/fs_util.h"
#include "test/util/test_util.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace gvisor {
namespace testing {

std::string RunfilePath(std::string path) {
  static const bazel::tools::cpp::runfiles::Runfiles* const runfiles = [] {
    std::string error;
    auto* runfiles =
        bazel::tools::cpp::runfiles::Runfiles::CreateForTest(&error);
    if (runfiles == nullptr) {
      std::cerr << "Unable to find runfiles: " << error << std::endl;
    }
    return runfiles;
  }();

  if (!runfiles) {
    // Can't find runfiles? This probably won't work, but __main__/path is our
    // best guess.
    return JoinPath("__main__", path);
  }

  return runfiles->Rlocation(JoinPath("__main__", path));
}

}  // namespace testing
}  // namespace gvisor
