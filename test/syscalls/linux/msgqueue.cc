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

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// Queue is a RAII class used to automatically clean message queues.
class Queue {
 public:
  explicit Queue(int id) : id_(id) {}

  ~Queue() {
    if (id_ >= 0) {
      EXPECT_THAT(msgctl(id_, IPC_RMID, nullptr), SyscallSucceeds());
    }
  }

  int release() {
    int old = id_;
    id_ = -1;
    return old;
  }

  int get() { return id_; }

 private:
  int id_ = -1;
};

// Test simple creation and retrieval for msgget(2).
TEST(MsgqueueTest, MsgGet) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  ASSERT_THAT(key, SyscallSucceeds());

  Queue queue(msgget(key, IPC_CREAT));
  ASSERT_THAT(queue.get(), SyscallSucceeds());
  EXPECT_THAT(msgget(key, 0), SyscallSucceedsWithValue(queue.get()));
}

// Test simple failure scenarios for msgget(2).
TEST(MsgqueueTest, MsgGetFail) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  ASSERT_THAT(key, SyscallSucceeds());

  EXPECT_THAT(msgget(key, 0), SyscallFailsWithErrno(ENOENT));

  Queue queue(msgget(key, IPC_CREAT));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  EXPECT_THAT(msgget(key, IPC_CREAT | IPC_EXCL), SyscallFailsWithErrno(EEXIST));
}

// Test using msgget(2) with IPC_PRIVATE option.
TEST(MsgqueueTest, MsgGetIpcPrivate) {
  Queue queue1(msgget(IPC_PRIVATE, 0));
  ASSERT_THAT(queue1.get(), SyscallSucceeds());

  Queue queue2(msgget(IPC_PRIVATE, 0));
  ASSERT_THAT(queue2.get(), SyscallSucceeds());

  EXPECT_NE(queue1.get(), queue2.get());
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
