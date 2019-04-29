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

#ifndef GVISOR_TEST_SYSCALLS_EXEC_H_
#define GVISOR_TEST_SYSCALLS_EXEC_H_

#include <sys/wait.h>

namespace gvisor {
namespace testing {

// Returns the exit code used by exec_basic_workload.
inline int ArgEnvExitCode(int args, int envs) { return args + envs * 10; }

// Returns the exit status used by exec_basic_workload.
inline int ArgEnvExitStatus(int args, int envs) {
  return W_EXITCODE(ArgEnvExitCode(args, envs), 0);
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_EXEC_H_
