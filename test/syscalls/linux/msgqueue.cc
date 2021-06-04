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

#include <errno.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include "test/util/capability_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// run is a temporary variable to easily enable/disable running tests. This
// variable should be removed along with SKIP_IF when the tested functionality
// is enabled.
constexpr bool run = false;

constexpr int msgMax = 8192;   // Max size for message in bytes.
constexpr int msgMni = 32000;  // Max number of identifiers.
constexpr int msgMnb = 16384;  // Default max size of message queue in bytes.

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

// Default size for messages.
constexpr size_t msgSize = 50;

// msgbuf is a simple buffer using to send and receive text messages for
// testing purposes.
struct msgbuf {
  long mtype;
  char mtext[msgSize];
};

bool operator==(msgbuf& a, msgbuf& b) {
  for (size_t i = 0; i < msgSize; i++) {
    if (a.mtext[i] != b.mtext[i]) {
      return false;
    }
  }
  return a.mtype == b.mtype;
}

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

// Test simple msgsnd and msgrcv.
TEST(MsgqueueTest, MsgOpSimple) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, "A message."};
  msgbuf rcv;

  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0, 0),
              SyscallSucceedsWithValue(sizeof(buf.mtext)));
  EXPECT_TRUE(buf == rcv);
}

// Test msgsnd and msgrcv of an empty message.
TEST(MsgqueueTest, MsgOpEmpty) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, ""};
  msgbuf rcv;

  ASSERT_THAT(msgsnd(queue.get(), &buf, 0, 0), SyscallSucceeds());
  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0, 0),
              SyscallSucceedsWithValue(0));
}

// Test truncation of message with MSG_NOERROR flag.
TEST(MsgqueueTest, MsgOpTruncate) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, ""};
  msgbuf rcv;

  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) - 1, 0, MSG_NOERROR),
              SyscallSucceedsWithValue(sizeof(buf.mtext) - 1));
}

// Test msgsnd and msgrcv using invalid arguments.
TEST(MsgqueueTest, MsgOpInvalidArgs) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, ""};

  EXPECT_THAT(msgsnd(-1, &buf, 0, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(msgsnd(queue.get(), &buf, -1, 0), SyscallFailsWithErrno(EINVAL));

  buf.mtype = -1;
  EXPECT_THAT(msgsnd(queue.get(), &buf, 1, 0), SyscallFailsWithErrno(EINVAL));

  EXPECT_THAT(msgrcv(-1, &buf, 1, 0, 0), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(msgrcv(queue.get(), &buf, -1, 0, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Test non-blocking msgrcv with an empty queue.
TEST(MsgqueueTest, MsgOpNoMsg) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf rcv{1, ""};
  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(rcv.mtext) + 1, 0, IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test non-blocking msgrcv with a non-empty queue, but no messages of wanted
// type.
TEST(MsgqueueTest, MsgOpNoMsgType) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, ""};
  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf.mtext) + 1, 2, IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test msgrcv with a larger size message than wanted, and truncation disabled.
TEST(MsgqueueTest, MsgOpTooBig) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, ""};
  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf.mtext) - 1, 0, 0),
              SyscallFailsWithErrno(E2BIG));
}

// Test receiving messages based on type.
TEST(MsgqueueTest, MsgRcvType) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  // Send messages in an order and receive them in reverse, based on type,
  // which shouldn't block.
  std::map<long, msgbuf> typeToBuf = {
      {1, msgbuf{1, "Message 1."}}, {2, msgbuf{2, "Message 2."}},
      {3, msgbuf{3, "Message 3."}}, {4, msgbuf{4, "Message 4."}},
      {5, msgbuf{5, "Message 5."}}, {6, msgbuf{6, "Message 6."}},
      {7, msgbuf{7, "Message 7."}}, {8, msgbuf{8, "Message 8."}},
      {9, msgbuf{9, "Message 9."}}};

  for (auto const& [type, buf] : typeToBuf) {
    ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  for (long i = typeToBuf.size(); i > 0; i--) {
    msgbuf rcv;
    EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(typeToBuf[i].mtext) + 1, i, 0),
                SyscallSucceedsWithValue(sizeof(typeToBuf[i].mtext)));
    EXPECT_TRUE(typeToBuf[i] == rcv);
  }
}

// Test using MSG_EXCEPT to receive a different-type message.
TEST(MsgqueueTest, MsgExcept) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  std::map<long, msgbuf> typeToBuf = {
      {1, msgbuf{1, "Message 1."}},
      {2, msgbuf{2, "Message 2."}},
  };

  for (auto const& [type, buf] : typeToBuf) {
    ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  for (long i = typeToBuf.size(); i > 0; i--) {
    msgbuf actual = typeToBuf[i == 1 ? 2 : 1];
    msgbuf rcv;

    EXPECT_THAT(
        msgrcv(queue.get(), &rcv, sizeof(actual.mtext) + 1, i, MSG_EXCEPT),
        SyscallSucceedsWithValue(sizeof(actual.mtext)));
    EXPECT_TRUE(actual == rcv);
  }
}

// Test msgrcv with a negative type.
TEST(MsgqueueTest, MsgRcvTypeNegative) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  //  When msgtyp is negative, msgrcv returns the first message with mtype less
  //  than or equal to the absolute value.
  msgbuf buf{2, "A message."};
  msgbuf rcv;

  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  // Nothing is less than or equal to 1.
  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, -1, IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));

  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, -3, 0),
              SyscallSucceedsWithValue(sizeof(buf.mtext)));
  EXPECT_TRUE(buf == rcv);
}

// Test permission-related failure scenarios.
TEST(MsgqueueTest, MsgOpPermissions) {
  SKIP_IF(!run);

  AutoCapability cap(CAP_IPC_OWNER, false);

  Queue queue(msgget(IPC_PRIVATE, 0000));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, ""};

  EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf.mtext), 0, 0),
              SyscallFailsWithErrno(EACCES));
}

// Test limits for messages and queues.
TEST(MsgqueueTest, MsgOpLimits) {
  SKIP_IF(!run);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, "A message."};

  // Limit for one message.
  EXPECT_THAT(msgsnd(queue.get(), &buf, msgMax + 1, 0),
              SyscallFailsWithErrno(EINVAL));

  // Limit for queue.
  // Use a buffer with the maximum mount of bytes that can be transformed to
  // make it easier to exhaust the queue limit.
  struct msgmax {
    long mtype;
    char mtext[msgMax];
  };

  msgmax limit{1, ""};
  for (size_t i = 0, msgCount = msgMnb / msgMax; i < msgCount; i++) {
    EXPECT_THAT(msgsnd(queue.get(), &limit, sizeof(limit.mtext), 0),
                SyscallSucceeds());
  }
  EXPECT_THAT(msgsnd(queue.get(), &limit, sizeof(limit.mtext), IPC_NOWAIT),
              SyscallFailsWithErrno(EAGAIN));
}

// MsgCopySupported returns true if MSG_COPY is supported.
bool MsgCopySupported() {
  // msgrcv(2) man page states that MSG_COPY flag is available only if the
  // kernel was built with the CONFIG_CHECKPOINT_RESTORE option. If MSG_COPY
  // is used when the kernel was configured without the option, msgrcv produces
  // a ENOSYS error.
  // To avoid test failure, we perform a small test using msgrcv, and skip the
  // test if errno == ENOSYS. This means that the test will always run on
  // gVisor, but may be skipped on native linux.

  Queue queue(msgget(IPC_PRIVATE, 0600));

  msgbuf buf{1, "Test message."};
  msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0);

  return !(msgrcv(queue.get(), &buf, sizeof(buf.mtext) + 1, 0,
                  MSG_COPY | IPC_NOWAIT) == -1 &&
           errno == ENOSYS);
}

// Test usage of MSG_COPY for msgrcv.
TEST(MsgqueueTest, MsgCopy) {
  SKIP_IF(!run);

  SKIP_IF(!MsgCopySupported());

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf bufs[5] = {
      msgbuf{1, "Message 1."}, msgbuf{2, "Message 2."}, msgbuf{3, "Message 3."},
      msgbuf{4, "Message 4."}, msgbuf{5, "Message 5."},
  };

  for (auto& buf : bufs) {
    ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  // Receive a copy of the messages.
  for (size_t i = 0, size = sizeof(bufs) / sizeof(bufs[0]); i < size; i++) {
    msgbuf buf = bufs[i];
    msgbuf rcv;
    EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, i,
                       MSG_COPY | IPC_NOWAIT),
                SyscallSucceedsWithValue(sizeof(buf.mtext)));
    EXPECT_TRUE(buf == rcv);
  }

  // Invalid index.
  msgbuf rcv;
  EXPECT_THAT(msgrcv(queue.get(), &rcv, 1, 5, MSG_COPY | IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));

  // Re-receive the messages normally.
  for (auto& buf : bufs) {
    msgbuf rcv;
    EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0, 0),
                SyscallSucceedsWithValue(sizeof(buf.mtext)));
    EXPECT_TRUE(buf == rcv);
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
