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
#include <signal.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "test/util/capability_util.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr int msgMax = 8192;   // Max size for message in bytes.
constexpr int msgMni = 32000;  // Max number of identifiers.
constexpr int msgMnb = 16384;  // Default max size of message queue in bytes.

constexpr int kInterruptSignal = SIGALRM;

// Queue is a RAII class used to automatically clean message queues.
class Queue {
 public:
  explicit Queue(int id) : id_(id) {}
  Queue(const Queue&) = delete;
  Queue& operator=(const Queue&) = delete;

  Queue(Queue&& other) { id_ = other.release(); }

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

PosixErrorOr<Queue> Msgget(key_t key, int flags) {
  int id = msgget(key, flags);
  if (id == -1) {
    return PosixError(errno, absl::StrFormat("msgget(%d, %d)", key, flags));
  }
  return Queue(id);
}

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

// msgmax represents a buffer for the largest possible single message.
struct msgmax {
  int64_t mtype;
  char mtext[msgMax];
};

// Test simple creation and retrieval for msgget(2).
TEST(MsgqueueTest, MsgGet) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  ASSERT_THAT(key, SyscallSucceeds());

  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(key, IPC_CREAT));
  EXPECT_THAT(msgget(key, 0), SyscallSucceedsWithValue(queue.get()));
}

// Test simple failure scenarios for msgget(2).
TEST(MsgqueueTest, MsgGetFail) {
  const TempPath keyfile = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const key_t key = ftok(keyfile.path().c_str(), 1);
  ASSERT_THAT(key, SyscallSucceeds());

  EXPECT_THAT(msgget(key, 0), SyscallFailsWithErrno(ENOENT));

  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(key, IPC_CREAT));
  EXPECT_THAT(msgget(key, IPC_CREAT | IPC_EXCL), SyscallFailsWithErrno(EEXIST));
}

// Test using msgget(2) with IPC_PRIVATE option.
TEST(MsgqueueTest, MsgGetIpcPrivate) {
  Queue queue1 = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0));
  Queue queue2 = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0));
  EXPECT_NE(queue1.get(), queue2.get());
}

// Test simple msgsnd and msgrcv.
TEST(MsgqueueTest, MsgOpSimple) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

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
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  msgbuf buf{1, ""};
  msgbuf rcv;

  ASSERT_THAT(msgsnd(queue.get(), &buf, 0, 0), SyscallSucceeds());
  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0, 0),
              SyscallSucceedsWithValue(0));
}

// Test truncation of message with MSG_NOERROR flag.
TEST(MsgqueueTest, MsgOpTruncate) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  msgbuf buf{1, ""};
  msgbuf rcv;

  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(buf.mtext) - 1, 0, MSG_NOERROR),
              SyscallSucceedsWithValue(sizeof(buf.mtext) - 1));
}

// Test msgsnd and msgrcv using invalid arguments.
TEST(MsgqueueTest, MsgOpInvalidArgs) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

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
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  msgbuf rcv;
  EXPECT_THAT(msgrcv(queue.get(), &rcv, sizeof(rcv.mtext) + 1, 0, IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test non-blocking msgrcv with a non-empty queue, but no messages of wanted
// type.
TEST(MsgqueueTest, MsgOpNoMsgType) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  msgbuf buf{1, ""};
  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf.mtext) + 1, 2, IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test msgrcv with a larger size message than wanted, and truncation disabled.
TEST(MsgqueueTest, MsgOpTooBig) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  msgbuf buf{1, ""};
  ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());

  EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf.mtext) - 1, 0, 0),
              SyscallFailsWithErrno(E2BIG));
}

// Test receiving messages based on type.
TEST(MsgqueueTest, MsgRcvType) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

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
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

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
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

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

  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0000));

  msgbuf buf{1, ""};

  EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf.mtext), 0, 0),
              SyscallFailsWithErrno(EACCES));
}

// Test limits for messages and queues.
TEST(MsgqueueTest, MsgOpLimits) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  msgbuf buf{1, "A message."};

  // Limit for one message.
  EXPECT_THAT(msgsnd(queue.get(), &buf, msgMax + 1, 0),
              SyscallFailsWithErrno(EINVAL));

  // Limit for queue.
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

  auto maybe_id = Msgget(IPC_PRIVATE, 0600);
  if (!maybe_id.ok()) {
    return false;
  }
  Queue queue(std::move(maybe_id.ValueOrDie()));
  msgbuf buf{1, "Test message."};

  msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0);
  return !(msgrcv(queue.get(), &buf, sizeof(buf.mtext) + 1, 0,
                  MSG_COPY | IPC_NOWAIT) == -1 &&
           errno == ENOSYS);
}

// Test msgrcv using MSG_COPY.
TEST(MsgqueueTest, MsgCopy) {
  SKIP_IF(!MsgCopySupported());

  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
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

  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
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

  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
  msgbuf rcv;
  EXPECT_THAT(msgrcv(queue.get(), &rcv, msgSize, -3, MSG_COPY | IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));

  EXPECT_THAT(msgrcv(queue.get(), &rcv, msgSize, 5, MSG_COPY | IPC_NOWAIT),
              SyscallFailsWithErrno(ENOMSG));
}

// Test msgrcv (most probably) blocking on an empty queue.
TEST(MsgqueueTest, MsgRcvBlocking) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
  msgbuf buf{1, "A message."};

  ScopedThread t([&] {
    msgbuf rcv;
    ASSERT_THAT(
        RetryEINTR(msgrcv)(queue.get(), &rcv, sizeof(buf.mtext) + 1, 0, 0),
        SyscallSucceedsWithValue(sizeof(buf.mtext)));
    EXPECT_TRUE(rcv == buf);
  });

  // Sleep to try and make msgrcv block before sending a message.
  absl::SleepFor(absl::Milliseconds(150));

  EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
              SyscallSucceeds());
}

// Test msgrcv (most probably) waiting for a specific-type message.
TEST(MsgqueueTest, MsgRcvTypeBlocking) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
  msgbuf bufs[5] = {{1, "A message."},
                    {1, "A message."},
                    {1, "A message."},
                    {1, "A message."},
                    {2, "A different message."}};

  ScopedThread t([&] {
    msgbuf buf = bufs[4];  // Buffer that should be received.
    msgbuf rcv;
    ASSERT_THAT(
        RetryEINTR(msgrcv)(queue.get(), &rcv, sizeof(buf.mtext) + 1, 2, 0),
        SyscallSucceedsWithValue(sizeof(buf.mtext)));
    EXPECT_TRUE(rcv == buf);
  });

  // Sleep to try and make msgrcv block before sending messages.
  absl::SleepFor(absl::Milliseconds(150));

  // Send all buffers in order, only last one should be received.
  for (auto& buf : bufs) {
    EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }
}

// Test msgsnd (most probably) blocking on a full queue.
TEST(MsgqueueTest, MsgSndBlocking) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
  msgmax buf{1, ""};  // Has max amount of bytes.

  const size_t msgCount = msgMnb / msgMax;  // Number of messages that can be
                                            // sent without blocking.

  ScopedThread t([&] {
    // Fill the queue.
    for (size_t i = 0; i < msgCount; i++) {
      ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                  SyscallSucceeds());
    }

    // Next msgsnd should block.
    ASSERT_THAT(RetryEINTR(msgsnd)(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  });

  const DisableSave ds;  // Too many syscalls.

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
}

// Test removing a queue while a blocking msgsnd is executing.
TEST(MsgqueueTest, MsgSndRmWhileBlocking) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  // Number of messages that can be sent without blocking.
  const size_t msgCount = msgMnb / msgMax;

  ScopedThread t([&] {
    // Fill the queue.
    msgmax buf{1, ""};
    for (size_t i = 0; i < msgCount; i++) {
      EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                  SyscallSucceeds());
    }

    // Next msgsnd should block. Because we're repeating on EINTR, msgsnd may
    // race with msgctl(IPC_RMID) and return EINVAL.
    EXPECT_THAT(RetryEINTR(msgsnd)(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallFails());
    EXPECT_TRUE((errno == EIDRM || errno == EINVAL));
  });

  const DisableSave ds;  // Too many syscalls.

  // Similar to MsgSndBlocking, we do this to increase the chance of msgsnd
  // blocking before removing the queue.
  msgmax rcv;
  while (msgrcv(queue.get(), &rcv, msgMax, msgCount - 1,
                MSG_COPY | IPC_NOWAIT) == -1 &&
         errno == ENOMSG) {
  }
  absl::SleepFor(absl::Milliseconds(100));

  EXPECT_THAT(msgctl(queue.release(), IPC_RMID, nullptr), SyscallSucceeds());
}

// Test removing a queue while a blocking msgrcv is executing.
TEST(MsgqueueTest, MsgRcvRmWhileBlocking) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  ScopedThread t([&] {
    // Because we're repeating on EINTR, msgsnd may race with msgctl(IPC_RMID)
    // and return EINVAL.
    msgbuf rcv;
    EXPECT_THAT(RetryEINTR(msgrcv)(queue.get(), &rcv, 1, 2, 0), SyscallFails());
    EXPECT_TRUE(errno == EIDRM || errno == EINVAL);
  });

  // Sleep to try and make msgrcv block before sending messages.
  absl::SleepFor(absl::Milliseconds(150));

  EXPECT_THAT(msgctl(queue.release(), IPC_RMID, nullptr), SyscallSucceeds());
}

// Test a collection of msgsnd/msgrcv operations in different processes.
TEST(MsgqueueTest, MsgOpGeneral) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));

  // Create multiple sending/receiving threads that send messages back and
  // forth. There's a matching recv for each send, so by the end of the test,
  // all threads should succeed and return.
  const std::vector<msgbuf> msgs = {
      msgbuf{1, "Message 1."}, msgbuf{2, "Message 2."}, msgbuf{3, "Message 3."},
      msgbuf{4, "Message 4."}, msgbuf{5, "Message 5."}};

  auto receiver = [&](int i) {
    return [i, &msgs, &queue]() {
      const msgbuf& target = msgs[i];
      msgbuf rcv;
      EXPECT_THAT(RetryEINTR(msgrcv)(queue.get(), &rcv,
                                     sizeof(target.mtext) + 1, target.mtype, 0),
                  SyscallSucceedsWithValue(sizeof(target.mtext)));
      EXPECT_EQ(rcv.mtype, target.mtype);
      EXPECT_EQ(0, memcmp(rcv.mtext, target.mtext, sizeof(target.mtext)));
    };
  };

  ScopedThread r1(receiver(0));
  ScopedThread r2(receiver(1));
  ScopedThread r3(receiver(2));
  ScopedThread r4(receiver(3));
  ScopedThread r5(receiver(4));
  ScopedThread r6(receiver(0));
  ScopedThread r7(receiver(1));
  ScopedThread r8(receiver(2));
  ScopedThread r9(receiver(3));
  ScopedThread r10(receiver(4));

  auto sender = [&](int i) {
    return [i, &msgs, &queue]() {
      const msgbuf& target = msgs[i];
      EXPECT_THAT(
          RetryEINTR(msgsnd)(queue.get(), &target, sizeof(target.mtext), 0),
          SyscallSucceeds());
    };
  };

  ScopedThread s1(sender(0));
  ScopedThread s2(sender(1));
  ScopedThread s3(sender(2));
  ScopedThread s4(sender(3));
  ScopedThread s5(sender(4));
  ScopedThread s6(sender(0));
  ScopedThread s7(sender(1));
  ScopedThread s8(sender(2));
  ScopedThread s9(sender(3));
  ScopedThread s10(sender(4));
}

void empty_sighandler(int sig, siginfo_t* info, void* context) {}

TEST(MsgqueueTest, InterruptRecv) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
  char buf[64];

  absl::Notification done, exit;

  // Thread calling msgrcv with no corresponding send. It would block forever,
  // but we'll interrupt with a signal below.
  ScopedThread t([&] {
    struct sigaction sa = {};
    sa.sa_sigaction = empty_sighandler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    auto cleanup_sigaction =
        ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kInterruptSignal, sa));
    auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(
        ScopedSignalMask(SIG_UNBLOCK, kInterruptSignal));

    EXPECT_THAT(msgrcv(queue.get(), &buf, sizeof(buf), 0, 0),
                SyscallFailsWithErrno(EINTR));

    done.Notify();
    exit.WaitForNotification();
  });

  const DisableSave ds;  // Too many syscalls.

  // We want the signal to arrive while msgrcv is blocking, but not after the
  // thread has exited. Signals that arrive before msgrcv are no-ops.
  do {
    EXPECT_THAT(kill(getpid(), kInterruptSignal), SyscallSucceeds());
    absl::SleepFor(absl::Milliseconds(100));  // Rate limit.
  } while (!done.HasBeenNotified());

  exit.Notify();
  t.Join();
}

TEST(MsgqueueTest, InterruptSend) {
  Queue queue = ASSERT_NO_ERRNO_AND_VALUE(Msgget(IPC_PRIVATE, 0600));
  msgmax buf{1, ""};
  // Number of messages that can be sent without blocking.
  const size_t msgCount = msgMnb / msgMax;

  // Fill the queue.
  for (size_t i = 0; i < msgCount; i++) {
    ASSERT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallSucceeds());
  }

  absl::Notification done, exit;

  // Thread calling msgsnd on a full queue. It would block forever, but we'll
  // interrupt with a signal below.
  ScopedThread t([&] {
    struct sigaction sa = {};
    sa.sa_sigaction = empty_sighandler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    auto cleanup_sigaction =
        ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kInterruptSignal, sa));
    auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(
        ScopedSignalMask(SIG_UNBLOCK, kInterruptSignal));

    EXPECT_THAT(msgsnd(queue.get(), &buf, sizeof(buf.mtext), 0),
                SyscallFailsWithErrno(EINTR));

    done.Notify();
    exit.WaitForNotification();
  });

  const DisableSave ds;  // Too many syscalls.

  // We want the signal to arrive while msgsnd is blocking, but not after the
  // thread has exited. Signals that arrive before msgsnd are no-ops.
  do {
    EXPECT_THAT(kill(getpid(), kInterruptSignal), SyscallSucceeds());
    absl::SleepFor(absl::Milliseconds(100));  // Rate limit.
  } while (!done.HasBeenNotified());

  exit.Notify();
  t.Join();
}

}  // namespace
}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // Some tests depend on delivering a signal to the main thread. Block the
  // target signal so that any other threads created by TestInit will also have
  // the signal blocked.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, gvisor::testing::kInterruptSignal);
  TEST_PCHECK(sigprocmask(SIG_BLOCK, &set, nullptr) == 0);

  gvisor::testing::TestInit(&argc, &argv);
  return gvisor::testing::RunAllTests();
}
