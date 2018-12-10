// Copyright 2018 Google LLC
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

#include <iostream>

#include "test/syscalls/linux/exec.h"

int main(int argc, char** argv, char** envp) {
  int i;
  for (i = 0; i < argc; i++) {
    std::cerr << argv[i] << std::endl;
  }
  for (i = 0; envp[i] != nullptr; i++) {
    std::cerr << envp[i] << std::endl;
  }
  exit(gvisor::testing::ArgEnvExitCode(argc - 1, i));
  return 0;
}
