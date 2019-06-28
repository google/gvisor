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

#include <stdlib.h>
#include <unistd.h>

#include <iostream>

#include "test/util/fs_util.h"
#include "test/util/posix_error.h"

int main(int argc, char** argv, char** envp) {
  std::string exe =
      gvisor::testing::ProcessExePath(getpid()).ValueOrDie();
  if (exe[0] != '/') {
    std::cerr << "relative path: " << exe << std::endl;
    exit(1);
  }
  if (exe.find(argv[1]) != std::string::npos) {
    std::cerr << "matching path: " << exe << std::endl;
    exit(1);
  }

  return 0;
}
