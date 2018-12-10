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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv, char** envp) {
  errno = 0;
  int prio = getpriority(PRIO_PROCESS, getpid());

  // NOTE: getpriority() can legitimately return negative values
  // in the range [-20, 0). If errno is set, exit with a value that
  // could not be reached by a valid priority. Valid exit values
  // for the test are in the range [1, 40], so we'll use 0.
  if (errno != 0) {
    printf("getpriority() failed with errno = %d\n", errno);
    exit(0);
  }

  // Used by test to verify priority is being maintained through
  // calls to execve(). Since prio should always be in the range
  // [-20, 19], we offset by 20 so as not to have negative exit codes.
  exit(20 - prio);

  return 0;
}
