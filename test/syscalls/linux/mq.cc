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

#include <fcntl.h>
#include <mqueue.h>
#include <sched.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#define NAME_MAX 255

namespace gvisor {
namespace testing {
namespace {

using ::testing::_;

constexpr int maxMsgSize = 8192;
constexpr size_t maxMsgCount = 10;

constexpr int kInterruptSignal = SIGALRM;

// PosixQueue is a RAII class used to automatically clean POSIX message queues.
class PosixQueue {
 public:
  PosixQueue(mqd_t fd, std::string name) : fd_(fd), name_(std::string(name)) {}
  PosixQueue(const PosixQueue&) = delete;
  PosixQueue& operator=(const PosixQueue&) = delete;

  // Move constructor.
  PosixQueue(PosixQueue&& q) {
    fd_ = q.fd_;
    name_ = q.name_;
    // Call PosixQueue::release, to prevent the object being released from
    // unlinking the underlying queue.
    q.release();
  }

  ~PosixQueue() {
    if (fd_ != -1) {
      EXPECT_THAT(mq_close(fd_), SyscallSucceeds());
      EXPECT_THAT(mq_unlink(name_.c_str()), SyscallSucceeds());
    }
  }

  mqd_t fd() { return fd_; }

  std::string name() { return name_; }

  mqd_t release() {
    mqd_t old = fd_;
    fd_ = -1;
    return old;
  }

 private:
  mqd_t fd_;
  std::string name_;
};

// MqOpen wraps mq_open(3) using a given name.
PosixErrorOr<PosixQueue> MqOpen(std::string name, int oflag) {
  mqd_t fd = mq_open(name.c_str(), oflag);
  if (fd == -1) {
    return PosixError(errno, absl::StrFormat("mq_open(%s, %d)", name, oflag));
  }
  return PosixQueue(fd, name);
}

// MqOpen wraps mq_open(3) using a given name.
PosixErrorOr<PosixQueue> MqOpen(int oflag, mode_t mode, struct mq_attr* attr) {
  auto name = "/" + NextTempBasename();
  mqd_t fd = mq_open(name.c_str(), oflag, mode, attr);
  if (fd == -1) {
    return PosixError(errno, absl::StrFormat("mq_open(%d)", oflag));
  }
  return PosixQueue(fd, name);
}

// MqOpen wraps mq_open(3) using a generated name.
PosixErrorOr<PosixQueue> MqOpen(std::string name, int oflag, mode_t mode,
                                struct mq_attr* attr) {
  mqd_t fd = mq_open(name.c_str(), oflag, mode, attr);
  if (fd == -1) {
    return PosixError(errno, absl::StrFormat("mq_open(%d)", oflag));
  }
  return PosixQueue(fd, name);
}

// MqUnlink wraps mq_unlink(3).
PosixError MqUnlink(std::string name) {
  int err = mq_unlink(name.c_str());
  if (err == -1) {
    return PosixError(errno, absl::StrFormat("mq_unlink(%s)", name.c_str()));
  }
  return NoError();
}

// MqClose wraps mq_close(3).
PosixError MqClose(mqd_t fd) {
  int err = mq_close(fd);
  if (err == -1) {
    return PosixError(errno, absl::StrFormat("mq_close(%d)", fd));
  }
  return NoError();
}

// MqSend wraps mq_send(3).
PosixError MqSend(mqd_t fd, const char* msg, size_t len, uint prio) {
  int err = mq_send(fd, msg, len, prio);
  if (err == -1) {
    return PosixError(errno, absl::StrFormat("mq_send(%d, %s)", fd, msg));
  }
  return NoError();
}

// MqTimedSend wraps mq_timedsend(3).
PosixError MqTimedSend(mqd_t fd, const char* msg, size_t len, uint prio,
                       const struct timespec* timeout) {
  int err = mq_timedsend(fd, msg, len, prio, timeout);
  if (err == -1) {
    return PosixError(errno, absl::StrFormat("mq_timedsend(%d, %s)", fd, msg));
  }
  return NoError();
}

// MqReceive wraps mq_receive(3).
PosixErrorOr<ssize_t> MqReceive(mqd_t fd, char* msg, size_t len, uint* prio) {
  ssize_t size = mq_receive(fd, msg, len, prio);
  if (size == -1) {
    return PosixError(errno, absl::StrFormat("mq_receive(%d)", fd));
  }
  return size;
}

// MqReceive wraps mq_timedreceive(3).
PosixErrorOr<ssize_t> MqTimedReceive(mqd_t fd, char* msg, size_t len,
                                     uint* prio,
                                     const struct timespec* timeout) {
  ssize_t size = mq_timedreceive(fd, msg, len, prio, timeout);
  if (size == -1) {
    return PosixError(errno, absl::StrFormat("mq_timedreceive(%d)", fd));
  }
  return size;
}

// Test simple opening and closing of a message queue.
TEST(MqTest, Open) {
  SKIP_IF(IsRunningWithVFS1());
  ASSERT_NO_ERRNO(MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));
}

TEST(MqTest, ModeWithFileType) {
  SKIP_IF(IsRunningWithVFS1());
  // S_IFIFO should be ignored.
  ASSERT_NO_ERRNO(MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777 | S_IFIFO, nullptr));
}

// Test mq_open(2) after mq_unlink(2).
TEST(MqTest, OpenAfterUnlink) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  ASSERT_NO_ERRNO(MqUnlink(queue.name()));
  EXPECT_THAT(MqOpen(queue.name(), O_RDWR), PosixErrorIs(ENOENT));
  ASSERT_NO_ERRNO(MqClose(queue.release()));
}

// Test using invalid args with mq_open.
TEST(MqTest, OpenInvalidArgs) {
  SKIP_IF(IsRunningWithVFS1());

  // Name must start with a slash.
  EXPECT_THAT(MqOpen("test", O_RDWR), PosixErrorIs(EINVAL));

  // Name can't contain more that one slash.
  EXPECT_THAT(MqOpen("/test/name", O_RDWR), PosixErrorIs(EACCES));

  // Both "." and ".." can't be used as queue names.
  EXPECT_THAT(MqOpen(".", O_RDWR), PosixErrorIs(EINVAL));
  EXPECT_THAT(MqOpen("..", O_RDWR), PosixErrorIs(EINVAL));

  // mq_attr's mq_maxmsg and mq_msgsize must be > 0.
  struct mq_attr attr;
  attr.mq_maxmsg = -1;
  attr.mq_msgsize = 10;

  EXPECT_THAT(MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, &attr),
              PosixErrorIs(EINVAL));

  attr.mq_maxmsg = 10;
  attr.mq_msgsize = -1;

  EXPECT_THAT(MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, &attr),
              PosixErrorIs(EINVAL));

  // Names should be shorter than NAME_MAX.
  char max[NAME_MAX + 3];
  max[0] = '/';
  for (size_t i = 1; i < NAME_MAX + 2; i++) {
    max[i] = 'a';
  }
  max[NAME_MAX + 2] = '\0';

  EXPECT_THAT(MqOpen(std::string(max), O_RDWR | O_CREAT | O_EXCL, 0777, &attr),
              PosixErrorIs(ENAMETOOLONG));
}

// Test creating a queue that already exists.
TEST(MqTest, CreateAlreadyExists) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  EXPECT_THAT(MqOpen(queue.name(), O_RDWR | O_CREAT | O_EXCL, 0777, nullptr),
              PosixErrorIs(EEXIST));
}

// Test opening a queue that doesn't exists.
TEST(MqTest, NoQueueExists) {
  SKIP_IF(IsRunningWithVFS1());

  // Choose a name to pass that's unlikely to exist if the test is run locally.
  EXPECT_THAT(MqOpen("/gvisor-mq-test-nonexistent-queue", O_RDWR),
              PosixErrorIs(ENOENT));
}

// Test trying to re-open a queue with invalid permissions.
TEST(MqTest, OpenNoAccess) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0000, nullptr));

  EXPECT_THAT(MqOpen(queue.name(), O_RDONLY), PosixErrorIs(EACCES));
  EXPECT_THAT(MqOpen(queue.name(), O_WRONLY), PosixErrorIs(EACCES));
  EXPECT_THAT(MqOpen(queue.name(), O_RDWR), PosixErrorIs(EACCES));
}

// Test trying to re-open a read-only queue for write.
TEST(MqTest, OpenReadAccess) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0400, nullptr));

  EXPECT_THAT(MqOpen(queue.name(), O_WRONLY), PosixErrorIs(EACCES));
  EXPECT_NO_ERRNO(MqOpen(queue.name(), O_RDONLY));
  queue.release();
}

// Test trying to re-open a write-only queue for read.
TEST(MqTest, OpenWriteAccess) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0200, nullptr));

  EXPECT_THAT(MqOpen(queue.name(), O_RDONLY), PosixErrorIs(EACCES));
  EXPECT_NO_ERRNO(MqOpen(queue.name(), O_WRONLY));
  queue.release();
}

// Test changing IPC namespace.
TEST(MqTest, ChangeIpcNamespace) {
  SKIP_IF(IsRunningWithVFS1() ||
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // When changing IPC namespaces, Linux doesn't invalidate or close the
  // previously opened file descriptions and allows operations to be performed
  // on them normally, until they're closed.
  //
  // To test this we create a new queue, use unshare(CLONE_NEWIPC) to change
  // into a new IPC namespace, and trying performing a read(2) on the queue.
  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  // As mq_unlink(2) uses queue's name, it should fail after changing IPC
  // namespace. To clean the queue, we should unlink it now, this should not
  // cause a problem, as the queue presists until the last mq_close(2).
  ASSERT_NO_ERRNO(MqUnlink(queue.name()));

  ASSERT_THAT(unshare(CLONE_NEWIPC), SyscallSucceeds());

  const size_t msgSize = 60;
  std::vector<char> queueRead(msgSize);
  EXPECT_THAT(read(queue.fd(), queueRead.data(), msgSize - 1),
              SyscallSucceeds());

  ASSERT_NO_ERRNO(MqClose(queue.release()));

  // Unlinking should fail now after changing IPC namespace.
  EXPECT_THAT(MqUnlink(queue.name()), PosixErrorIs(ENOENT));
}

// Test mounting the mqueue filesystem.
TEST(MqTest, Mount) {
  SKIP_IF(IsRunningWithVFS1() ||
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_NO_ERRNO(Mount("none", dir.path(), "mqueue", 0, "", 0));
}

// Test mounting the mqueue filesystem to several places.
TEST(MqTest, MountSeveral) {
  SKIP_IF(IsRunningWithVFS1() ||
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  constexpr int numMounts = 3;

  // mountDirs should outlive mountCUs and queue so that its destructor succeeds
  // in unlinking the mountpoints and does not interfere with queue destruction.
  testing::TempPath mountDirs[numMounts];
  testing::Cleanup mountCUs[numMounts];
  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  for (int i = 0; i < numMounts; ++i) {
    mountDirs[i] = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    mountCUs[i] = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("none", mountDirs[i].path(), "mqueue", 0, "", 0));
  }

  // Ensure that queue is visible from all mounts.
  for (int i = 0; i < numMounts; ++i) {
    ASSERT_NO_ERRNO(Stat(JoinPath(mountDirs[i].path(), queue.name())));
  }
}

// Test mounting mqueue and opening a queue as normal file.
TEST(MqTest, OpenAsFile) {
  SKIP_IF(IsRunningWithVFS1() ||
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("none", dir.path(), "mqueue", 0, "", 0));

  // Open queue using open(2).
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(dir.path(), queue.name()), O_RDONLY));

  // File descriptors returned through open(2) behave like normal files. They
  // can be used for reading/polling, but can't be used in mq_* syscalls.
  EXPECT_THAT(MqSend(fd.get(), "", 0, 0), PosixErrorIs(EBADF));

  const size_t msgSize = 60;
  std::vector<char> queueRead(msgSize);
  queueRead[msgSize - 1] = '\0';

  ASSERT_THAT(read(fd.get(), queueRead.data(), msgSize - 1), SyscallSucceeds());

  std::string want(
      "QSIZE:0          NOTIFY:0     SIGNO:0     NOTIFY_PID:0     ");
  std::string got(&queueRead[0]);
  EXPECT_EQ(got, want);
}

// Test removing a queue using unlink(2).
TEST(MqTest, UnlinkAsFile) {
  SKIP_IF(IsRunningWithVFS1() ||
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  auto const dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("none", dir.path(), "mqueue", 0, "", 0));

  ASSERT_NO_ERRNO(
      UnlinkAt(FileDescriptor(), JoinPath(dir.path(), queue.name()), 0));

  // Trying to unlink again should fail.
  EXPECT_THAT(MqUnlink(queue.name()), PosixErrorIs(ENOENT));
  queue.release();
}

// Test read(2) from an empty queue.
TEST(MqTest, ReadEmpty) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  const size_t msgSize = 60;
  std::vector<char> queueRead(msgSize);
  queueRead[msgSize - 1] = '\0';

  ASSERT_THAT(read(queue.fd(), queueRead.data(), msgSize - 1),
              SyscallSucceeds());

  std::string want(
      "QSIZE:0          NOTIFY:0     SIGNO:0     NOTIFY_PID:0     ");
  std::string got(&queueRead[0]);
  EXPECT_EQ(got, want);
}

// Test poll(2) on an empty queue.
TEST(MqTest, PollEmpty) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  struct pollfd pfd;
  pfd.fd = queue.fd();
  pfd.events = POLLOUT | POLLIN | POLLRDNORM | POLLWRNORM;

  ASSERT_THAT(poll(&pfd, 1, -1), SyscallSucceeds());
  EXPECT_EQ(pfd.revents, POLLOUT | POLLWRNORM);
}

// Test simple mq_{send,receive}.
TEST(MqTest, SimpleSendReceive) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  std::string msg = "A test message.";
  size_t msgSize = msg.length();
  ASSERT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msgSize, 1));

  uint priority;
  std::vector<char> receive(msgSize);
  auto bytes = EXPECT_NO_ERRNO_AND_VALUE(
      MqReceive(queue.fd(), receive.data(), maxMsgSize, &priority));

  EXPECT_EQ(std::string(receive.data()), msg);
  EXPECT_EQ(priority, 1);
  EXPECT_EQ(bytes, msgSize);
}

// Test mq_{send,receive} using a bad fd.
TEST(MqTest, SendReceiveBadFD) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  // Close the queue to test a bad file descriptor.
  ASSERT_NO_ERRNO(MqClose(queue.release()));
  ASSERT_NO_ERRNO(MqUnlink(queue.name()));

  EXPECT_THAT(MqSend(queue.fd(), "Message.", 8, 1), PosixErrorIs(EBADF));

  uint priority;
  std::vector<char> receive(10);
  EXPECT_THAT(MqReceive(queue.fd(), receive.data(), maxMsgSize, &priority),
              PosixErrorIs(EBADF));
}

// Test mq_timed{send,receive} using an invalid timeout.
TEST(MqTest, InvalidTime) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  // Variables to be received into.
  uint priority;
  std::vector<char> receive(10);

  const struct timespec timeout1 = {-1, 10};
  EXPECT_THAT(MqTimedSend(queue.fd(), "Message.", 8, 1, &timeout1),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(MqTimedReceive(queue.fd(), receive.data(), maxMsgSize, &priority,
                             &timeout1),
              PosixErrorIs(EINVAL));

  const struct timespec timeout2 = {10, -1};
  EXPECT_THAT(MqTimedSend(queue.fd(), "Message.", 8, 1, &timeout2),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(MqTimedReceive(queue.fd(), receive.data(), maxMsgSize, &priority,
                             &timeout2),
              PosixErrorIs(EINVAL));

  const struct timespec timeout3 = {10, 1000000000};
  EXPECT_THAT(MqTimedSend(queue.fd(), "Message.", 8, 1, &timeout3),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(MqTimedReceive(queue.fd(), receive.data(), maxMsgSize, &priority,
                             &timeout3),
              PosixErrorIs(EINVAL));
}

// Test mq_{send,receive} with an invalid msg size.
TEST(MqTest, SendMsgSize) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  // Values to be received.
  uint priority;
  std::vector<char> receive(10);

  EXPECT_THAT(MqSend(queue.fd(), "Message.", maxMsgSize + 1, 1),
              PosixErrorIs(EMSGSIZE));
  EXPECT_THAT(MqReceive(queue.fd(), receive.data(), maxMsgSize - 1, &priority),
              PosixErrorIs(EMSGSIZE));
}

// Test using send with a different maximum message count.
TEST(MqTest, SendMaxMsgCount) {
  SKIP_IF(IsRunningWithVFS1());

  struct mq_attr attr;
  attr.mq_maxmsg = maxMsgCount - 1;
  attr.mq_msgsize = maxMsgSize;

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_NONBLOCK | O_CREAT | O_EXCL, 0777, &attr));

  std::string msg = "A test message.";

  // Fill the queue. mq_send shouldn't block, even after exceeding default max
  // msg count.
  for (size_t i = 0; i < maxMsgCount - 1; i++) {
    EXPECT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msg.length(), 1));
  }
  EXPECT_THAT(MqSend(queue.fd(), msg.c_str(), msg.length(), 1),
              PosixErrorIs(EAGAIN));
}

// Test using send with a different maximum message size.
TEST(MqTest, SendMaxMsgSize) {
  SKIP_IF(IsRunningWithVFS1());

  struct mq_attr attr;
  attr.mq_maxmsg = maxMsgCount;
  attr.mq_msgsize = maxMsgSize - 1;

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_NONBLOCK | O_CREAT | O_EXCL, 0777, &attr));

  char msg[maxMsgSize + 1];

  EXPECT_NO_ERRNO(MqSend(queue.fd(), &msg[0], maxMsgSize - 1, 1));
  EXPECT_THAT(MqSend(queue.fd(), &msg[0], maxMsgSize, 1),
              PosixErrorIs(EMSGSIZE));
}

// Test mq_{send,receive} of several messages in order.
TEST(MqTest, SendReceiveSeveral) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  const size_t msgSize = 10;
  const size_t msgCount = 10;
  std::string msgs[msgCount] = {
      "Message 0.", "Message 1.", "Message 2.", "Message 3.", "Message 4.",
      "Message 5.", "Message 6.", "Message 7.", "Message 8.", "Message 9."};

  for (size_t i = 0; i < msgCount; i++) {
    ASSERT_NO_ERRNO(MqSend(queue.fd(), msgs[i].c_str(), msgSize, 1));
  }

  // Messages with the same priority should be received in order of insertion
  // (sent first, received first).
  for (size_t i = 0; i < msgCount; i++) {
    uint priority;
    std::vector<char> receive(msgSize + 1);
    receive[msgSize] = '\0';

    auto bytes = ASSERT_NO_ERRNO_AND_VALUE(
        MqReceive(queue.fd(), receive.data(), maxMsgSize, &priority));

    EXPECT_EQ(std::string(receive.data()), msgs[i]);
    EXPECT_EQ(priority, 1);
    EXPECT_EQ(bytes, msgSize);
  }
}

// Test mq_{send,receive} based on priority.
TEST(MqTest, Priority) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  const size_t msgSize = 10;
  const size_t msgCount = 10;
  std::string msgs[msgCount] = {
      "Message 0.", "Message 1.", "Message 2.", "Message 3.", "Message 4.",
      "Message 5.", "Message 6.", "Message 7.", "Message 8.", "Message 9."};

  for (size_t i = 0; i < msgCount; i++) {
    ASSERT_NO_ERRNO(MqSend(queue.fd(), msgs[i].c_str(), msgSize, i));
  }

  // Highest priority should be received first.
  for (size_t j = 0; j < msgCount; j++) {
    size_t i = msgCount - j - 1;

    uint priority;
    std::vector<char> receive(msgSize + 1);
    receive[msgSize] = '\0';

    auto bytes = ASSERT_NO_ERRNO_AND_VALUE(
        MqReceive(queue.fd(), receive.data(), maxMsgSize, &priority));

    EXPECT_EQ(std::string(receive.data()), msgs[i]);
    EXPECT_EQ(priority, i);
    EXPECT_EQ(bytes, msgSize);
  }
}

// Test blocking mq_{send,receive} with NON_BLOCK flag enabled.
TEST(MqTest, NonBlocking) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_NONBLOCK | O_CREAT | O_EXCL, 0777, nullptr));

  // mq_receive should fail because queue is empty.
  char receive[1];
  EXPECT_THAT(MqReceive(queue.fd(), &receive[0], maxMsgSize, nullptr),
              PosixErrorIs(EAGAIN));

  for (size_t i = 0; i < maxMsgCount; i++) {
    ASSERT_NO_ERRNO(MqSend(queue.fd(), "", 0, 1));
  }

  // Next mq_send should fail because we reached maxMsgCount.
  EXPECT_THAT(MqSend(queue.fd(), "", 0, 1), PosixErrorIs(EAGAIN));
}

// Test mq_{send,receive} on different modes for a queue.
TEST(MqTest, RdOnlyWrOnlyRdWr) {
  SKIP_IF(IsRunningWithVFS1());

  // Create two views into the same queue.
  PosixQueue wrOnly = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_WRONLY | O_CREAT | O_EXCL, 0777, nullptr));
  PosixQueue rdOnly =
      ASSERT_NO_ERRNO_AND_VALUE(MqOpen(wrOnly.name(), O_RDONLY));

  std::string msg = "A test message.";
  size_t msgSize = msg.length();

  // Variables to be received into.
  std::vector<char> receive(msgSize + 1);
  receive[msgSize] = '\0';

  // wrOnly should send, but fail to receive.
  EXPECT_NO_ERRNO(MqSend(wrOnly.fd(), msg.c_str(), msgSize, 1));
  EXPECT_THAT(MqReceive(wrOnly.fd(), receive.data(), maxMsgSize, nullptr),
              PosixErrorIs(EBADF));

  // rdOnly should receive, but fail to send.
  auto bytes = EXPECT_NO_ERRNO_AND_VALUE(
      MqReceive(rdOnly.fd(), receive.data(), maxMsgSize, nullptr));
  EXPECT_EQ(std::string(receive.data()), msg);
  EXPECT_EQ(bytes, msgSize);

  EXPECT_THAT(MqSend(rdOnly.fd(), msg.c_str(), msgSize, 1),
              PosixErrorIs(EBADF));

  // Release rdOnly so the queue can be unlinked only once.
  ASSERT_NO_ERRNO(MqClose(rdOnly.release()));
}

// Test mq_send blocking with a timeout.
TEST(MqTest, SendTimeout) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  std::string msg = "A test message.";
  size_t msgSize = msg.length();

  // Send maximum number of messages that wouldn't block.
  for (size_t i = 0; i < maxMsgCount; i++) {
    EXPECT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msgSize, 1));
  }

  auto start = absl::Now();
  const struct timespec spec = {0 /* Seconds */, 1000 /* Nanoseconds */};

  // Next mq_send should block.
  EXPECT_THAT(MqTimedSend(queue.fd(), msg.c_str(), msgSize, 1, &spec),
              PosixErrorIs(ETIMEDOUT));
  EXPECT_GE(absl::Now(), start + absl::Microseconds(1));
}

// Test mq_receive blocking with a timeout.
TEST(MqTest, ReceiveTimeout) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  auto start = absl::Now();
  const struct timespec spec = {0 /* Seconds */, 1000 /* Nanoseconds */};

  char receive[1];
  EXPECT_THAT(
      MqTimedReceive(queue.fd(), &receive[0], maxMsgSize, nullptr, &spec),
      PosixErrorIs(ETIMEDOUT));
  EXPECT_GE(absl::Now(), start + absl::Microseconds(1));
}

// Test mq_receive using a zero timeout.
TEST(MqTest, ZeroTimeout) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  auto start = absl::Now();
  const struct timespec spec = {0 /* Seconds */, 0 /* Nanoseconds */};

  char receive[1];
  EXPECT_THAT(
      MqTimedReceive(queue.fd(), &receive[0], maxMsgSize, nullptr, &spec),
      PosixErrorIs(ETIMEDOUT));
  EXPECT_GE(absl::Now(), start);
}

// Test a blocking mq_send.
TEST(MqTest, SendBlocking) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  std::string msg = "A test message.";
  size_t msgSize = msg.length();

  // Send maximum number of messages that wouldn't block.
  for (size_t i = 0; i < maxMsgCount; i++) {
    EXPECT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msgSize, 1));
  }

  ScopedThread t([&] {
    EXPECT_THAT(RetryEINTR(mq_send)(queue.fd(), msg.c_str(), msgSize, 1),
                SyscallSucceeds());
  });

  // Delay a bit for the blocking mq_send.
  absl::SleepFor(absl::Milliseconds(500));

  std::vector<char> receive(msgSize + 1);
  receive[msgSize] = '\0';

  auto bytes = ASSERT_NO_ERRNO_AND_VALUE(
      MqReceive(queue.fd(), receive.data(), maxMsgSize, nullptr));
  EXPECT_EQ(std::string(receive.data()), msg);
  EXPECT_EQ(bytes, msgSize);
}

// Test a blocking mq_receive.
TEST(MqTest, ReceiveBlocking) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  std::string msg = "A test message.";
  size_t msgSize = msg.length();

  ScopedThread t([&] {
    uint priority;
    std::vector<char> receive(msgSize + 1);
    receive[msgSize] = '\0';

    ASSERT_THAT(RetryEINTR(mq_receive)(queue.fd(), receive.data(), maxMsgSize,
                                       &priority),
                SyscallSucceedsWithValue(msgSize));

    EXPECT_EQ(std::string(receive.data()), msg);
    EXPECT_EQ(priority, 1);
  });

  // Delay a bit for the blocking mq_receive.
  absl::SleepFor(absl::Milliseconds(500));

  EXPECT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msgSize, 1));
}

// Test sending and receiving several messages.
TEST(MqTest, General) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  // Create several senders and receivers. Each sender has a matching receiver,
  // so all thread should succeed and return. Unlike SysV queues, we can't
  // specify a certain type or priority of a message to receive. Unless we send
  // all messages sequentially, we won't be able to specify receiving order. To
  // avoid order-related problems, have all messages have the same order and
  // priority.

  std::string msg = "A test message.";

  auto receiver = [&](int i) {
    return [i, &msg, &queue]() {
      uint priority;
      std::vector<char> receive(msg.length() + 1);
      receive[msg.length()] = '\0';

      auto bytes = ASSERT_NO_ERRNO_AND_VALUE(
          MqReceive(queue.fd(), receive.data(), maxMsgSize, &priority));

      EXPECT_EQ(std::string(receive.data()), msg);
      EXPECT_EQ(priority, 1);
      EXPECT_EQ(bytes, msg.length());
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
    return [i, &msg, &queue]() {
      EXPECT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msg.length(), 1));
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

// Test interrupting mq_receive.
TEST(MqTest, InterruptReceive) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  char buf[64];

  absl::Notification done, exit;

  // Thread calling mq_receive with no corresponding send. It would block
  // forever, but we'll interrupt with a signal below.
  ScopedThread t([&] {
    struct sigaction sa = {};
    sa.sa_sigaction = empty_sighandler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    auto cleanup_sigaction =
        ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(kInterruptSignal, sa));
    auto sa_cleanup = ASSERT_NO_ERRNO_AND_VALUE(
        ScopedSignalMask(SIG_UNBLOCK, kInterruptSignal));

    EXPECT_THAT(MqReceive(queue.fd(), &buf[0], maxMsgSize, nullptr),
                PosixErrorIs(EINTR));

    done.Notify();
    exit.WaitForNotification();
  });

  const DisableSave ds;  // Too many syscalls.

  // We want the signal to arrive while mq_send is blocking, but not after the
  // thread has exited. Signals that arrive before mq_receive are no-ops.
  do {
    EXPECT_THAT(kill(getpid(), kInterruptSignal), SyscallSucceeds());
    absl::SleepFor(absl::Milliseconds(100));  // Rate limit.
  } while (!done.HasBeenNotified());

  exit.Notify();
  t.Join();
}

// Test interrupting mq_receive.
TEST(MqTest, InterruptSend) {
  SKIP_IF(IsRunningWithVFS1());

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  std::string msg = "Test message.";

  // Fill the queue.
  for (size_t i = 0; i < maxMsgCount; i++) {
    ASSERT_NO_ERRNO(MqSend(queue.fd(), msg.c_str(), msg.length(), 1));
  }

  absl::Notification done, exit;

  // Thread calling mq_send on a full queue. It would block forever, but we'll
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

    EXPECT_THAT(MqSend(queue.fd(), msg.c_str(), msg.length(), 1),
                PosixErrorIs(EINTR));

    done.Notify();
    exit.WaitForNotification();
  });

  const DisableSave ds;  // Too many syscalls.

  // We want the signal to arrive while mq_send is blocking, but not after the
  // thread has exited. Signals that arrive before mq_send are no-ops.
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
