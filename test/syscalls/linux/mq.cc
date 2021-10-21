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
#include <unistd.h>

#include <string>

#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

#define NAME_MAX 255

namespace gvisor {
namespace testing {
namespace {

using ::testing::_;

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

  const char* name() { return name_.c_str(); }

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

// MqUnlink wraps mq_unlink(2).
PosixError MqUnlink(std::string name) {
  int err = mq_unlink(name.c_str());
  if (err == -1) {
    return PosixError(errno, absl::StrFormat("mq_unlink(%s)", name.c_str()));
  }
  return NoError();
}

// MqClose wraps mq_close(2).
PosixError MqClose(mqd_t fd) {
  int err = mq_close(fd);
  if (err == -1) {
    return PosixError(errno, absl::StrFormat("mq_close(%d)", fd));
  }
  return NoError();
}

// Test simple opening and closing of a message queue.
TEST(MqTest, Open) {
  SKIP_IF(IsRunningWithVFS1());
  EXPECT_THAT(MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr),
              IsPosixErrorOkAndHolds(_));
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
  char queueRead[msgSize];
  ASSERT_THAT(read(queue.fd(), &queueRead[0], msgSize - 1), SyscallSucceeds());

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

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  auto const dir1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  // Assign the pointer so it doesn't get destroyed before the second mount is
  // created.
  auto mnt =
      ASSERT_NO_ERRNO_AND_VALUE(Mount("none", dir1.path(), "mqueue", 0, "", 0));

  auto const dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  ASSERT_NO_ERRNO(Mount("none", dir2.path(), "mqueue", 0, "", 0));
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

  const size_t msgSize = 60;
  char queueRead[msgSize];
  queueRead[msgSize - 1] = '\0';

  ASSERT_THAT(read(fd.get(), &queueRead[0], msgSize - 1), SyscallSucceeds());

  std::string want(
      "QSIZE:0          NOTIFY:0     SIGNO:0     NOTIFY_PID:0     ");
  std::string got(queueRead);
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
  char queueRead[msgSize];
  queueRead[msgSize - 1] = '\0';

  ASSERT_THAT(read(queue.fd(), &queueRead[0], msgSize - 1), SyscallSucceeds());

  std::string want(
      "QSIZE:0          NOTIFY:0     SIGNO:0     NOTIFY_PID:0     ");
  std::string got(queueRead);
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
  ASSERT_EQ(pfd.revents, POLLOUT | POLLWRNORM);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
