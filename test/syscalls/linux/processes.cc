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

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "test/util/capability_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

int testSetPGIDOfZombie(void* arg) {
  int p[2];

  TEST_PCHECK(pipe(p) == 0);

  pid_t pid = fork();
  if (pid == 0) {
    pid = fork();
    // Create a second child to repeat one of syzkaller reproducers.
    if (pid == 0) {
      pid = getpid();
      TEST_PCHECK(setpgid(pid, 0) == 0);
      TEST_PCHECK(write(p[1], &pid, sizeof(pid)) == sizeof(pid));
      _exit(0);
    }
    TEST_PCHECK(pid > 0);
    _exit(0);
  }
  close(p[1]);
  TEST_PCHECK(pid > 0);

  // Get PID of the second child.
  pid_t cpid;
  TEST_PCHECK(read(p[0], &cpid, sizeof(cpid)) == sizeof(cpid));

  // Wait when both child processes will die.
  int c;
  TEST_PCHECK(read(p[0], &c, sizeof(c)) == 0);

  // Wait the second child process to collect its zombie.
  int status;
  TEST_PCHECK(RetryEINTR(waitpid)(cpid, &status, 0) == cpid);

  // Set the child's group.
  TEST_PCHECK(setpgid(pid, pid) == 0);

  TEST_PCHECK(RetryEINTR(waitpid)(-pid, &status, 0) == pid);

  TEST_PCHECK(status == 0);
  _exit(0);
}

TEST(Processes, SetPGIDOfZombie) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Fork a test process in a new PID namespace, because it needs to manipulate
  // with reparanted processes.
  struct clone_arg {
    // Reserve some space for clone() to locate arguments and retcode in this
    // place.
    char stack[128] __attribute__((aligned(16)));
    char stack_ptr[0];
  } ca;
  pid_t pid;
  ASSERT_THAT(pid = clone(testSetPGIDOfZombie, ca.stack_ptr,
                          CLONE_NEWPID | SIGCHLD, &ca),
              SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
              SyscallSucceedsWithValue(pid));
  EXPECT_EQ(status, 0);
}

}  // namespace testing
}  // namespace gvisor
