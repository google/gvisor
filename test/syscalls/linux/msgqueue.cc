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

#include "absl/time/clock.h"
#include "test/util/capability_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

// Source: include/uapi/linux/msg.h
constexpr int msgMnb = 16384;  // Maximum number of bytes in a queue.
constexpr int msgMni = 32000;  // Max number of identifiers.
constexpr int msgPool =
    (msgMni * msgMnb / 1024);  // Size of buffer pool used to hold message data.
constexpr int msgMap = msgMnb;  // Maximum number of entries in message map.
constexpr int msgMax = 8192;    // Maximum number of bytes in a single message.
constexpr int msgSsz = 16;      // Message segment size.
constexpr int msgTql = msgMnb;  // Maximum number of messages on all queues.

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
  int64_t mtype;
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
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf rcv;
  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(rcv.mtext) + 1, 0, IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test non-blocking msgrcv with a non-empty queue, but no messages of wanted
// type.
TEST(MsgqueueTest, MsgOpNoMsgType) {
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
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  // Send messages in an order and receive them in reverse, based on type,
  // which shouldn't block.
  std::map<int64_t, msgbuf> typeToBuf = {
      {1, msgbuf{1, "Message 1."}}, {2, msgbuf{2, "Message 2."}},
      {3, msgbuf{3, "Message 3."}}, {4, msgbuf{4, "Message 4."}},
      {5, msgbuf{5, "Message 5."}}, {6, msgbuf{6, "Message 6."}},
      {7, msgbuf{7, "Message 7."}}, {8, msgbuf{8, "Message 8."}},
      {9, msgbuf{9, "Message 9."}}};

  for (auto const& [type, buf] : typeToBuf) {
    ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  for (int64_t i = typeToBuf.size(); i > 0; i--) {
    msgbuf rcv;
    EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(typeToBuf[i].mtext) + 1, i, 0),
                SyscallSucceedsWithValue(sizeof(typeToBuf[i].mtext)));
    EXPECT_TRUE(typeToBuf[i] == rcv);
  }
}

// Test using MSG_EXCEPT to receive a different-type message.
TEST(MsgqueueTest, MsgExcept) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  std::map<int64_t, msgbuf> typeToBuf = {
      {1, msgbuf{1, "Message 1."}},
      {2, msgbuf{2, "Message 2."}},
  };

  for (auto const& [type, buf] : typeToBuf) {
    ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  for (int64_t i = typeToBuf.size(); i > 0; i--) {
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
    int64_t mtype;
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

// Test msgrcv using MSG_COPY.
TEST(MsgqueueTest, MsgCopy) {
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

  // Re-receive the messages normally.
  for (auto& buf : bufs) {
    msgbuf rcv;
    EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0, 0),
                SyscallSucceedsWithValue(sizeof(buf.mtext)));
    EXPECT_TRUE(buf == rcv);
  }
}

// Test msgrcv using MSG_COPY with invalid arguments.
TEST(MsgqueueTest, MsgCopyInvalidArgs) {
  SKIP_IF(!MsgCopySupported());

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf rcv;
  EXPECT_THAT(msgrcv(queue.get(), &rcv, msgSize, 1, MSG_COPY),
              SyscallFailsWithErrno(EINVAL));

  EXPECT_THAT(
      msgrcv(queue.get(), &rcv, msgSize, 5, MSG_COPY | MSG_EXCEPT | IPC_NOWAIT),
      SyscallFailsWithErrno(EINVAL));
}

// Test msgrcv using MSG_COPY with invalid indices.
TEST(MsgqueueTest, MsgCopyInvalidIndex) {
  SKIP_IF(!MsgCopySupported());

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf rcv;
  EXPECT_THAT(msgrcv(queue.get(), &rcv, msgSize, -3, MSG_COPY | IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));

  EXPECT_THAT(msgrcv(queue.get(), &rcv, msgSize, 5, MSG_COPY | IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test msgrcv (most probably) blocking on an empty queue.
TEST(MsgqueueTest, MsgRcvBlocking) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf{1, "A message."};

  const pid_t child_pid = fork();
  if (child_pid == 0) {
    msgbuf rcv;
    TEST_PCHECK(RetryEINTR(msgrcv)(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0,
                                   0) == sizeof(buf.mtext) &&
                buf == rcv);
    _exit(0);
  }

  // Sleep to try and make msgrcv block before sending a message.
  absl::SleepFor(absl::Milliseconds(150));

  EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Test msgrcv (most probably) waiting for a specific-type message.
TEST(MsgqueueTest, MsgRcvTypeBlocking) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf bufs[5] = {{1, "A message."},
                    {1, "A message."},
                    {1, "A message."},
                    {1, "A message."},
                    {2, "A different message."}};

  const pid_t child_pid = fork();
  if (child_pid == 0) {
    msgbuf buf = bufs[4];  // Buffer that should be received.
    msgbuf rcv;
    TEST_PCHECK(RetryEINTR(msgrcv)(queue.get(), &rcv, sizeof(buf.mtext) + 1, 2,
                                   0) == sizeof(buf.mtext) &&
                buf == rcv);
    _exit(0);
  }

  // Sleep to try and make msgrcv block before sending messages.
  absl::SleepFor(absl::Milliseconds(150));

  // Send all buffers in order, only last one should be received.
  for (auto& buf : bufs) {
    EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Test msgsnd (most probably) blocking on a full queue.
TEST(MsgqueueTest, MsgSndBlocking) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  // Use a buffer with the maximum mount of bytes that can be transformed to
  // make it easier to exhaust the queue limit.
  struct msgmax {
    int64_t mtype;
    char mtext[msgMax];
  };

  msgmax buf{1, ""};  // Has max amount of bytes.

  const size_t msgCount = msgMnb / msgMax;  // Number of messages that can be
                                            // sent without blocking.

  const pid_t child_pid = fork();
  if (child_pid == 0) {
    // Fill the queue.
    for (size_t i = 0; i < msgCount; i++) {
      TEST_PCHECK(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0) == 0);
    }

    // Next msgsnd should block.
    TEST_PCHECK(RetryEINTR(msgsnd)(queue.get(), &buf, sizeof(buf.mtext), 0) ==
                0);
    _exit(0);
  }

  // To increase the chance of the last msgsnd blocking before doing a msgrcv,
  // we use MSG_COPY option to copy the last index in the queue. As long as
  // MSG_COPY fails, the queue hasn't yet been filled. When MSG_COPY succeeds,
  // the queue is filled, and most probably, a blocking msgsnd has been made.
  msgmax rcv;
  while (msgrcv(queue.get(), &rcv, msgMax, msgCount - 1,
                MSG_COPY | IPC_NOWAIT) == -1 &&
         errno == ENOMSG) {
  }

  // Delay a bit more for the blocking msgsnd.
  absl::SleepFor(absl::Milliseconds(100));

  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext), 0, 0),
              SyscallSucceedsWithValue(sizeof(buf.mtext)));

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Test removing a queue while a blocking msgsnd is executing.
TEST(MsgqueueTest, MsgSndRmWhileBlocking) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  // Use a buffer with the maximum mount of bytes that can be transformed to
  // make it easier to exhaust the queue limit.
  struct msgmax {
    int64_t mtype;
    char mtext[msgMax];
  };

  const size_t msgCount = msgMnb / msgMax;  // Number of messages that can be
                                            // sent without blocking.
  const pid_t child_pid = fork();
  if (child_pid == 0) {
    // Fill the queue.
    msgmax buf{1, ""};
    for (size_t i = 0; i < msgCount; i++) {
      EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                  SyscallSucceeds());
    }

    // Next msgsnd should block. Because we're repeating on EINTR, msgsnd may
    // race with msgctl(IPC_RMID) and return EINVAL.
    TEST_PCHECK(RetryEINTR(msgsnd)(queue.get(), &buf, sizeof(buf.mtext), 0) ==
                    -1 &&
                (errno == EIDRM || errno == EINVAL));
    _exit(0);
  }

  // Similar to MsgSndBlocking, we do this to increase the chance of msgsnd
  // blocking before removing the queue.
  msgmax rcv;
  while (msgrcv(queue.get(), &rcv, msgMax, msgCount - 1,
                MSG_COPY | IPC_NOWAIT) == -1 &&
         errno == ENOMSG) {
  }
  absl::SleepFor(absl::Milliseconds(100));

  EXPECT_THAT(msgctl(queue.release(), IPC_RMID, nullptr), SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Test removing a queue while a blocking msgrcv is executing.
TEST(MsgqueueTest, MsgRcvRmWhileBlocking) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  const pid_t child_pid = fork();
  if (child_pid == 0) {
    // Because we're repeating on EINTR, msgsnd may race with msgctl(IPC_RMID)
    // and return EINVAL.
    msgbuf rcv;
    TEST_PCHECK(RetryEINTR(msgrcv)(queue.get(), &rcv, 1, 2, 0) == -1 &&
                (errno == EIDRM || errno == EINVAL));
    _exit(0);
  }

  // Sleep to try and make msgrcv block before sending messages.
  absl::SleepFor(absl::Milliseconds(150));

  EXPECT_THAT(msgctl(queue.release(), IPC_RMID, nullptr), SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Test a collection of msgsnd/msgrcv operations in different processes.
TEST(MsgqueueTest, MsgOpGeneral) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  // Create 50 sending, and 50 receiving processes. There are only 5 messages to
  // be sent and received, each with a different type. All messages will be sent
  // and received equally (10 of each.) By the end of the test all processes
  // should unblock and return normally.
  const size_t msgCount = 5;
  std::map<int64_t, msgbuf> typeToBuf = {{1, msgbuf{1, "Message 1."}},
                                         {2, msgbuf{2, "Message 2."}},
                                         {3, msgbuf{3, "Message 3."}},
                                         {4, msgbuf{4, "Message 4."}},
                                         {5, msgbuf{5, "Message 5."}}};

  std::vector<pid_t> children;

  const size_t pCount = 50;
  for (size_t i = 1; i <= pCount; i++) {
    const pid_t child_pid = fork();
    if (child_pid == 0) {
      msgbuf buf = typeToBuf[(i % msgCount) + 1];
      msgbuf rcv;
      TEST_PCHECK(RetryEINTR(msgrcv)(queue.get(), &rcv, sizeof(buf.mtext) + 1,
                                     (i % msgCount) + 1,
                                     0) == sizeof(buf.mtext) &&
                  buf == rcv);
      _exit(0);
    }
    children.push_back(child_pid);
  }

  for (size_t i = 1; i <= pCount; i++) {
    const pid_t child_pid = fork();
    if (child_pid == 0) {
      msgbuf buf = typeToBuf[(i % msgCount) + 1];
      TEST_PCHECK(RetryEINTR(msgsnd)(queue.get(), &buf, sizeof(buf.mtext), 0) ==
                  0);
      _exit(0);
    }
    children.push_back(child_pid);
  }

  for (auto const& pid : children) {
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(pid, &status, 0),
                SyscallSucceedsWithValue(pid));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

// Test msgctl with IPC_STAT option.
TEST(MsgqueueTest, MsgCtlIpcStat) {
  auto start = absl::Now();

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  const uid_t uid = getuid();
  const gid_t gid = getgid();
  const pid_t pid = getpid();

  struct msqid_ds ds;
  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());

  EXPECT_EQ(ds.msg_perm.__key, IPC_PRIVATE);
  EXPECT_EQ(ds.msg_perm.uid, uid);
  EXPECT_EQ(ds.msg_perm.gid, gid);
  EXPECT_EQ(ds.msg_perm.cuid, uid);
  EXPECT_EQ(ds.msg_perm.cgid, gid);
  EXPECT_EQ(ds.msg_perm.mode, 0600);

  EXPECT_EQ(ds.msg_stime, 0);
  EXPECT_EQ(ds.msg_rtime, 0);
  EXPECT_GE(ds.msg_ctime, absl::ToTimeT(start));

  EXPECT_EQ(ds.msg_cbytes, 0);
  EXPECT_EQ(ds.msg_qnum, 0);
  EXPECT_EQ(ds.msg_qbytes, msgMnb);
  EXPECT_EQ(ds.msg_lspid, 0);
  EXPECT_EQ(ds.msg_lrpid, 0);

  // The timestamps only have a resolution of seconds; slow down so we actually
  // see the timestamps change.
  absl::SleepFor(absl::Seconds(1));
  auto pre_send = absl::Now();

  msgbuf buf;
  ASSERT_THAT(msgsnd(queue.get(), &buf, msgSize, 0), SyscallSucceeds());

  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());

  EXPECT_GE(ds.msg_stime, absl::ToTimeT(pre_send));
  EXPECT_EQ(ds.msg_rtime, 0);
  EXPECT_GE(ds.msg_ctime, absl::ToTimeT(start));

  EXPECT_EQ(ds.msg_cbytes, msgSize);
  EXPECT_EQ(ds.msg_qnum, 1);
  EXPECT_EQ(ds.msg_qbytes, msgMnb);
  EXPECT_EQ(ds.msg_lspid, pid);
  EXPECT_EQ(ds.msg_lrpid, 0);

  absl::SleepFor(absl::Seconds(1));
  auto pre_receive = absl::Now();

  ASSERT_THAT(msgrcv(queue.get(), &buf, msgSize, 0, 0),
              SyscallSucceedsWithValue(msgSize));

  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());

  EXPECT_GE(ds.msg_stime, absl::ToTimeT(pre_send));
  EXPECT_GE(ds.msg_rtime, absl::ToTimeT(pre_receive));
  EXPECT_GE(ds.msg_ctime, absl::ToTimeT(start));

  EXPECT_EQ(ds.msg_cbytes, 0);
  EXPECT_EQ(ds.msg_qnum, 0);
  EXPECT_EQ(ds.msg_qbytes, msgMnb);
  EXPECT_EQ(ds.msg_lspid, pid);
  EXPECT_EQ(ds.msg_lrpid, pid);
}

// Test msgctl with IPC_STAT option on a write-only queue.
TEST(MsgqueueTest, MsgCtlIpcStatWriteOnly) {
  // Drop CAP_IPC_OWNER which allows us to bypass permissions.
  AutoCapability cap(CAP_IPC_OWNER, false);

  Queue queue(msgget(IPC_PRIVATE, 0200));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  struct msqid_ds ds;
  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds),
              SyscallFailsWithErrno(EACCES));
}

// Test msgctl with IPC_SET option.
TEST(MsgqueueTest, MsgCtlIpcSet) {
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  struct msqid_ds ds;
  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());
  EXPECT_EQ(ds.msg_perm.mode, 0600);

  ds.msg_perm.mode = 0777;
  ASSERT_THAT(msgctl(queue.get(), IPC_SET, &ds), SyscallSucceeds());

  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());
  EXPECT_EQ(ds.msg_perm.mode, 0777);
}

// Test increasing msg_qbytes beyond limit with IPC_SET.
TEST(MsgqueueTest, MsgCtlIpcSetMaxBytes) {
  // Drop CAP_SYS_RESOURCE which allows us to increase msg_qbytes beyond the
  // system parameter MSGMNB.
  AutoCapability cap(CAP_SYS_RESOURCE, false);

  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  struct msqid_ds ds;
  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());
  EXPECT_EQ(ds.msg_qbytes, msgMnb);

  ds.msg_qbytes = msgMnb - 10;
  ASSERT_THAT(msgctl(queue.get(), IPC_SET, &ds), SyscallSucceeds());

  ASSERT_THAT(msgctl(queue.get(), IPC_STAT, &ds), SyscallSucceeds());
  EXPECT_EQ(ds.msg_qbytes, msgMnb - 10);

  ds.msg_qbytes = msgMnb + 10;
  EXPECT_THAT(msgctl(queue.get(), IPC_SET, &ds), SyscallFailsWithErrno(EPERM));
}

// Test msgctl with IPC_INFO option.
TEST(MsgqueueTest, MsgCtlIpcInfo) {
  struct msginfo info;
  ASSERT_THAT(msgctl(0, IPC_INFO, reinterpret_cast<struct msqid_ds*>(&info)),
              SyscallSucceeds());

  EXPECT_GT(info.msgmax, 0);
  EXPECT_GT(info.msgmni, 0);
  EXPECT_GT(info.msgmnb, 0);
  EXPECT_EQ(info.msgpool, msgPool);
  EXPECT_EQ(info.msgmap, msgMap);
  EXPECT_EQ(info.msgssz, msgSsz);
  EXPECT_EQ(info.msgtql, msgTql);
}

// Test msgctl with MSG_INFO option.
TEST(MsgqueueTest, MsgCtlMsgInfo) {
  struct msginfo info;
  ASSERT_THAT(msgctl(0, MSG_INFO, reinterpret_cast<struct msqid_ds*>(&info)),
              SyscallSucceeds());

  EXPECT_GT(info.msgmax, 0);
  EXPECT_GT(info.msgmni, 0);
  EXPECT_GT(info.msgmnb, 0);
  EXPECT_EQ(info.msgpool, 0);  // Number of queues in the system.
  EXPECT_EQ(info.msgmap, 0);   // Total number of messages in all queues.
  EXPECT_EQ(info.msgtql, 0);   // Total number of bytes in all messages.
  EXPECT_EQ(info.msgssz, msgSsz);

  // Add a queue and a message.
  Queue queue(msgget(IPC_PRIVATE, 0600));
  ASSERT_THAT(queue.get(), SyscallSucceeds());

  msgbuf buf;
  ASSERT_THAT(msgsnd(queue.get(), &buf, msgSize, 0), SyscallSucceeds());

  ASSERT_THAT(msgctl(0, MSG_INFO, reinterpret_cast<struct msqid_ds*>(&info)),
              SyscallSucceeds());

  EXPECT_GT(info.msgmax, 0);
  EXPECT_GT(info.msgmni, 0);
  EXPECT_GT(info.msgmnb, 0);
  EXPECT_EQ(info.msgpool, 1);       // Number of queues in the system.
  EXPECT_EQ(info.msgmap, 1);        // Total number of messages in all queues.
  EXPECT_EQ(info.msgtql, msgSize);  // Total number of bytes in all messages.
  EXPECT_EQ(info.msgssz, msgSsz);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
