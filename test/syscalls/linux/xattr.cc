// Copyright 2018 The gVisor Authors.
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
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"

namespace gvisor {
namespace testing {

namespace {

class XattrTest : public FileTest {};

TEST_F(XattrTest, XattrNullName) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), nullptr, nullptr, 0, /*flags=*/0),
      SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(getxattr(test_file_name_.c_str(), nullptr, nullptr, 0),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(XattrTest, XattrEmptyName) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  EXPECT_THAT(setxattr(test_file_name_.c_str(), "", nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(ERANGE));
  EXPECT_THAT(getxattr(test_file_name_.c_str(), "", nullptr, 0),
              SyscallFailsWithErrno(ERANGE));
}

TEST_F(XattrTest, XattrLargeName) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  std::string name = "user.";
  name += std::string(XATTR_NAME_MAX - name.length(), 'a');
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0, /*flags=*/0),
      SyscallSucceeds());
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0),
              SyscallSucceedsWithValue(0));

  name += "a";
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0, /*flags=*/0),
      SyscallFailsWithErrno(ERANGE));
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0),
              SyscallFailsWithErrno(ERANGE));
}

TEST_F(XattrTest, XattrInvalidPrefix) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  std::string name(XATTR_NAME_MAX, 'a');
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0, /*flags=*/0),
      SyscallFailsWithErrno(EOPNOTSUPP));
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

TEST_F(XattrTest, XattrOnDirectory) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  char name[] = "user.abc";
  EXPECT_THAT(setxattr(dir.path().c_str(), name, NULL, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(dir.path().c_str(), name, NULL, 0),
              SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, XattrOnSymlink) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir.path(), test_file_name_));
  char name[] = "user.abc";
  EXPECT_THAT(setxattr(link.path().c_str(), name, NULL, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(link.path().c_str(), name, NULL, 0),
              SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, XattrOnInvalidFileTypes) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";

  char char_device[] = "/dev/zero";
  EXPECT_THAT(setxattr(char_device, name, NULL, 0, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(getxattr(char_device, name, NULL, 0),
              SyscallFailsWithErrno(ENODATA));

  // Use tmpfs, where creation of named pipes is supported.
  const std::string fifo = NewTempAbsPathInDir("/dev/shm");
  EXPECT_THAT(mknod(fifo.c_str(), S_IFIFO | S_IRUSR | S_IWUSR, 0),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(fifo.c_str(), name, NULL, 0, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(getxattr(fifo.c_str(), name, NULL, 0),
              SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, SetxattrSizeSmallerThanValue) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  std::vector<char> val = {'a', 'a'};
  size_t size = 1;
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), size, /*flags=*/0),
      SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  std::vector<char> expected_buf = {'a', '-'};
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, buf.data(), buf.size()),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, SetxattrZeroSize) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  char val = 'a';
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, 0, /*flags=*/0),
              SyscallSucceeds());

  char buf = '-';
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, &buf, XATTR_SIZE_MAX),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(buf, '-');
}

TEST_F(XattrTest, SetxattrSizeTooLarge) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  // Note that each particular fs implementation may stipulate a lower size
  // limit, in which case we actually may fail (e.g. error with ENOSPC) for
  // some sizes under XATTR_SIZE_MAX.
  char name[] = "user.abc";
  size_t size = XATTR_SIZE_MAX + 1;
  std::vector<char> val(size);
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), size, /*flags=*/0),
      SyscallFailsWithErrno(E2BIG));

  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, SetxattrNullValueAndNonzeroSize) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, nullptr, 1, /*flags=*/0),
              SyscallFailsWithErrno(EFAULT));

  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, SetxattrNullValueAndZeroSize) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, nullptr, 0, /*flags=*/0),
              SyscallSucceeds());

  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, 0),
              SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, SetxattrValueTooLargeButOKSize) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  std::vector<char> val(XATTR_SIZE_MAX + 1);
  std::fill(val.begin(), val.end(), 'a');
  size_t size = 1;
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), size, /*flags=*/0),
      SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  std::vector<char> expected_buf = {'a', '-'};
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, buf.data(), size),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, SetxattrReplaceWithSmaller) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  std::vector<char> val = {'a', 'a'};
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), 2, /*flags=*/0),
      SyscallSucceeds());
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), 1, /*flags=*/0),
      SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  std::vector<char> expected_buf = {'a', '-'};
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, buf.data(), 2),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, SetxattrReplaceWithLarger) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  std::vector<char> val = {'a', 'a'};
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), 1, /*flags=*/0),
      SyscallSucceeds());
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, val.data(), 2, /*flags=*/0),
      SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, buf.data(), 2),
              SyscallSucceedsWithValue(2));
  EXPECT_EQ(buf, val);
}

TEST_F(XattrTest, SetxattrCreateFlag) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, nullptr, 0, XATTR_CREATE),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, nullptr, 0, XATTR_CREATE),
              SyscallFailsWithErrno(EEXIST));

  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, 0),
              SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, SetxattrReplaceFlag) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, nullptr, 0, XATTR_REPLACE),
      SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, nullptr, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, nullptr, 0, XATTR_REPLACE),
      SyscallSucceeds());

  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, 0),
              SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, Getxattr) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  int val = 1234;
  size_t size = sizeof(val);
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, size, /*flags=*/0),
              SyscallSucceeds());

  int buf = 0;
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, &buf, size),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, val);
}

TEST_F(XattrTest, GetxattrSizeSmallerThanValue) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  std::vector<char> val = {'a', 'a'};
  size_t size = val.size();
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, size, /*flags=*/0),
              SyscallSucceeds());

  char buf = '-';
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, &buf, 1),
              SyscallFailsWithErrno(ERANGE));
  // No change to buf.
  EXPECT_EQ(buf, '-');
}

TEST_F(XattrTest, GetxattrSizeLargerThanValue) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  char val = 'a';
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, 1, /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> buf(XATTR_SIZE_MAX);
  std::fill(buf.begin(), buf.end(), '-');
  std::vector<char> expected_buf = buf;
  expected_buf[0] = 'a';
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, buf.data(), buf.size()),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, GetxattrZeroSize) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  char val = 'a';
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, &val, sizeof(val), /*flags=*/0),
      SyscallSucceeds());

  char buf = '-';
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, &buf, 0),
              SyscallSucceedsWithValue(sizeof(val)));
  EXPECT_EQ(buf, '-');
}

TEST_F(XattrTest, GetxattrSizeTooLarge) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  char val = 'a';
  EXPECT_THAT(
      setxattr(test_file_name_.c_str(), name, &val, sizeof(val), /*flags=*/0),
      SyscallSucceeds());

  std::vector<char> buf(XATTR_SIZE_MAX + 1);
  std::fill(buf.begin(), buf.end(), '-');
  std::vector<char> expected_buf = buf;
  expected_buf[0] = 'a';
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, buf.data(), buf.size()),
              SyscallSucceedsWithValue(sizeof(val)));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, GetxattrNullValue) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  char val = 'a';
  size_t size = sizeof(val);
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, size, /*flags=*/0),
              SyscallSucceeds());

  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, size),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(XattrTest, GetxattrNullValueAndZeroSize) {
  // TODO(b/127675828): Support setxattr and getxattr.
  SKIP_IF(IsRunningOnGvisor());

  char name[] = "user.abc";
  char val = 'a';
  size_t size = sizeof(val);
  // Set value with zero size.
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, 0, /*flags=*/0),
              SyscallSucceeds());
  // Get value with nonzero size.
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, size),
              SyscallSucceedsWithValue(0));

  // Set value with nonzero size.
  EXPECT_THAT(setxattr(test_file_name_.c_str(), name, &val, size, /*flags=*/0),
              SyscallSucceeds());
  // Get value with zero size.
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name, nullptr, 0),
              SyscallSucceedsWithValue(size));
}

TEST_F(XattrTest, GetxattrNonexistentName) {
  // TODO(b/127675828): Support getxattr.
  SKIP_IF(IsRunningOnGvisor());

  std::string name = "user.nonexistent";
  EXPECT_THAT(getxattr(test_file_name_.c_str(), name.c_str(), nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
