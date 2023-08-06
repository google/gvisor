// Copyright 2023 The gVisor Authors.
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

#include <sched.h>

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(SetnsTest, ChangeIPCNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  struct stat st;
  uint64_t ipcns1, ipcns2, ipcns3;
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/ipc", O_RDONLY));
  ASSERT_THAT(stat("/proc/thread-self/ns/ipc", &st), SyscallSucceeds());
  ipcns1 = st.st_ino;

  // Use unshare(CLONE_NEWIPC) to change into a new IPC namespace.
  ASSERT_THAT(unshare(CLONE_NEWIPC), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/ipc", &st), SyscallSucceeds());
  ipcns2 = st.st_ino;
  ASSERT_NE(ipcns1, ipcns2);

  ASSERT_THAT(setns(nsfd.get(), CLONE_NEWIPC), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/ipc", &st), SyscallSucceeds());
  ipcns3 = st.st_ino;
  EXPECT_EQ(ipcns1, ipcns3);
}

TEST(SetnsTest, ChangeUTSNamespace) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  struct stat st;
  uint64_t utsns1, utsns2, utsns3;
  const FileDescriptor nsfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/uts", O_RDONLY));
  ASSERT_THAT(stat("/proc/thread-self/ns/uts", &st), SyscallSucceeds());
  utsns1 = st.st_ino;

  // Use unshare(CLONE_NEWUTS) to change into a new UTS namespace.
  ASSERT_THAT(unshare(CLONE_NEWUTS), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/uts", &st), SyscallSucceeds());
  utsns2 = st.st_ino;
  ASSERT_NE(utsns1, utsns2);

  ASSERT_THAT(setns(nsfd.get(), CLONE_NEWUTS), SyscallSucceedsWithValue(0));
  ASSERT_THAT(stat("/proc/thread-self/ns/uts", &st), SyscallSucceeds());
  utsns3 = st.st_ino;
  EXPECT_EQ(utsns1, utsns3);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
