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

  // Try to resolve the path as it was passed to us, and check that it exists
  // before returning.
  std::string runfile_path = runfiles->Rlocation(JoinPath("__main__", path));
  struct stat st = {};
  if (!runfile_path.empty() && stat(runfile_path.c_str(), &st) == 0) {
    // Found it.
    return runfile_path;
  }

  // You are not gonna like this, but go_binary data dependencies have an extra
  // directory name with a "_" suffix, so we must check for that path too.
  //
  // For example, a go_binary with name"//foo/bar:baz" will be placed in
  // "<runfiles_dir>/foo/bar/baz_/baz".
  //
  // See
  // https://github.com/bazelbuild/rules_go/blob/d2a3cf2d6b18f5be19adccc6a6806e0c3b8c410b/go/private/context.bzl#L137.
  absl::string_view dirname = Dirname(path);
  absl::string_view basename = Basename(path);
  std::string go_binary_path =
      JoinPath(dirname, absl::StrCat(basename, "_"), basename);
  return runfiles->Rlocation(JoinPath("__main__", go_binary_path));
}

}  // namespace testing
}  // namespace gvisor
