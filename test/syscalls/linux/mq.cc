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
#include <sys/stat.h>
#include <unistd.h>

#include <string>

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
  PosixQueue(PosixQueue&& q) : fd_(q.fd_), name_(q.name_) {
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
  GTEST_SKIP();
  EXPECT_THAT(MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr),
              IsPosixErrorOkAndHolds(_));
}

// Test mq_open(2) after mq_unlink(2).
TEST(MqTest, OpenAfterUnlink) {
  GTEST_SKIP();

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  ASSERT_NO_ERRNO(MqUnlink(queue.name()));
  EXPECT_THAT(MqOpen(queue.name(), O_RDWR), PosixErrorIs(ENOENT));
  ASSERT_NO_ERRNO(MqClose(queue.release()));
}

// Test using invalid args with mq_open.
TEST(MqTest, OpenInvalidArgs) {
  GTEST_SKIP();

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
  GTEST_SKIP();

  PosixQueue queue = ASSERT_NO_ERRNO_AND_VALUE(
      MqOpen(O_RDWR | O_CREAT | O_EXCL, 0777, nullptr));

  EXPECT_THAT(MqOpen(queue.name(), O_RDWR | O_CREAT | O_EXCL, 0777, nullptr),
              PosixErrorIs(EEXIST));
}

// Test opening a queue that doesn't exists.
TEST(MqTest, NoQueueExists) {
  GTEST_SKIP();

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

}  // namespace
}  // namespace testing
}  // namespace gvisor
