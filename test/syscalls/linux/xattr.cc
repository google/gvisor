// Copyright 2019 The gVisor Authors.
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
#include "absl/container/flat_hash_set.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::gvisor::testing::IsTmpfs;

class XattrTest : public FileTest {};

TEST_F(XattrTest, XattrNonexistentFile) {
  const char* path = "/does/not/exist";
  const char* name = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(listxattr(path, nullptr, 0), SyscallFailsWithErrno(ENOENT));
  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(ENOENT));
}

TEST_F(XattrTest, XattrNullName) {
  const char* path = test_file_name_.c_str();

  EXPECT_THAT(setxattr(path, nullptr, nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(getxattr(path, nullptr, nullptr, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(removexattr(path, nullptr), SyscallFailsWithErrno(EFAULT));
}

TEST_F(XattrTest, XattrEmptyName) {
  const char* path = test_file_name_.c_str();

  EXPECT_THAT(setxattr(path, "", nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(ERANGE));
  EXPECT_THAT(getxattr(path, "", nullptr, 0), SyscallFailsWithErrno(ERANGE));
  EXPECT_THAT(removexattr(path, ""), SyscallFailsWithErrno(ERANGE));
}

TEST_F(XattrTest, XattrLargeName) {
  const char* path = test_file_name_.c_str();
  std::string name = "user.";
  name += std::string(XATTR_NAME_MAX - name.length(), 'a');

  if (!IsRunningOnGvisor()) {
    // In gVisor, access to xattrs is controlled with an explicit list of
    // allowed names. This name isn't going to be configured to allow access, so
    // don't test it.
    EXPECT_THAT(setxattr(path, name.c_str(), nullptr, 0, /*flags=*/0),
                SyscallSucceeds());
    EXPECT_THAT(getxattr(path, name.c_str(), nullptr, 0),
                SyscallSucceedsWithValue(0));
  }

  name += "a";
  EXPECT_THAT(setxattr(path, name.c_str(), nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(ERANGE));
  EXPECT_THAT(getxattr(path, name.c_str(), nullptr, 0),
              SyscallFailsWithErrno(ERANGE));
  EXPECT_THAT(removexattr(path, name.c_str()), SyscallFailsWithErrno(ERANGE));
}

TEST_F(XattrTest, XattrInvalidPrefix) {
  const char* path = test_file_name_.c_str();
  std::string name(XATTR_NAME_MAX, 'a');
  EXPECT_THAT(setxattr(path, name.c_str(), nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(EOPNOTSUPP));
  EXPECT_THAT(getxattr(path, name.c_str(), nullptr, 0),
              SyscallFailsWithErrno(EOPNOTSUPP));
  EXPECT_THAT(removexattr(path, name.c_str()),
              SyscallFailsWithErrno(EOPNOTSUPP));
}

// Do not allow save/restore cycles after making the test file read-only, as
// the restore will fail to open it with r/w permissions.
TEST_F(XattrTest, XattrReadOnly) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  size_t size = sizeof(val);

  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  DisableSave ds;
  ASSERT_NO_ERRNO(testing::Chmod(test_file_name_, S_IRUSR));

  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0),
              SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(EACCES));

  char buf = '-';
  EXPECT_THAT(getxattr(path, name, &buf, size), SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, val);

  char list[sizeof(name)];
  EXPECT_THAT(listxattr(path, list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);
}

// Do not allow save/restore cycles after making the test file write-only, as
// the restore will fail to open it with r/w permissions.
TEST_F(XattrTest, XattrWriteOnly) {
  // Drop capabilities that allow us to override file and directory permissions.
  AutoCapability cap1(CAP_DAC_OVERRIDE, false);
  AutoCapability cap2(CAP_DAC_READ_SEARCH, false);

  DisableSave ds;
  ASSERT_NO_ERRNO(testing::Chmod(test_file_name_, S_IWUSR));

  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  size_t size = sizeof(val);

  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(EACCES));

  // listxattr will succeed even without read permissions.
  char list[sizeof(name)];
  EXPECT_THAT(listxattr(path, list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  EXPECT_THAT(removexattr(path, name), SyscallSucceeds());
}

TEST_F(XattrTest, XattrTrustedWithNonadmin) {
  // TODO(b/148380782): Support setxattr and getxattr with "trusted" prefix.
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const char* path = test_file_name_.c_str();
  const char name[] = "trusted.abc";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, XattrOnDirectory) {
  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(dir.path().c_str(), name, nullptr, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(dir.path().c_str(), name, nullptr, 0),
              SyscallSucceedsWithValue(0));

  char list[sizeof(name)];
  EXPECT_THAT(listxattr(dir.path().c_str(), list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  EXPECT_THAT(removexattr(dir.path().c_str(), name), SyscallSucceeds());
}

TEST_F(XattrTest, XattrOnSymlink) {
  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir.path(), test_file_name_));
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(link.path().c_str(), name, nullptr, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(getxattr(link.path().c_str(), name, nullptr, 0),
              SyscallSucceedsWithValue(0));

  char list[sizeof(name)];
  EXPECT_THAT(listxattr(link.path().c_str(), list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  EXPECT_THAT(removexattr(link.path().c_str(), name), SyscallSucceeds());
}

TEST_F(XattrTest, XattrOnInvalidFileTypes) {
  const char name[] = "user.test";

  char char_device[] = "/dev/zero";
  EXPECT_THAT(setxattr(char_device, name, nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(getxattr(char_device, name, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(listxattr(char_device, nullptr, 0), SyscallSucceedsWithValue(0));

  // Use tmpfs, where creation of named pipes is supported.
  const std::string fifo = NewTempAbsPathInDir("/dev/shm");
  const char* path = fifo.c_str();
  EXPECT_THAT(mknod(path, S_IFIFO | S_IRUSR | S_IWUSR, 0), SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(listxattr(path, nullptr, 0), SyscallSucceedsWithValue(0));
  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(EPERM));
}

TEST_F(XattrTest, SetXattrSizeSmallerThanValue) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  std::vector<char> val = {'a', 'a'};
  size_t size = 1;
  EXPECT_THAT(setxattr(path, name, val.data(), size, /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  std::vector<char> expected_buf = {'a', '-'};
  EXPECT_THAT(getxattr(path, name, buf.data(), buf.size()),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, SetXattrZeroSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  EXPECT_THAT(setxattr(path, name, &val, 0, /*flags=*/0), SyscallSucceeds());

  char buf = '-';
  EXPECT_THAT(getxattr(path, name, &buf, XATTR_SIZE_MAX),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(buf, '-');
}

TEST_F(XattrTest, SetXattrSizeTooLarge) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";

  // Note that each particular fs implementation may stipulate a lower size
  // limit, in which case we actually may fail (e.g. error with ENOSPC) for
  // some sizes under XATTR_SIZE_MAX.
  size_t size = XATTR_SIZE_MAX + 1;
  std::vector<char> val(size);
  EXPECT_THAT(setxattr(path, name, val.data(), size, /*flags=*/0),
              SyscallFailsWithErrno(E2BIG));

  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, SetXattrNullValueAndNonzeroSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 1, /*flags=*/0),
              SyscallFailsWithErrno(EFAULT));

  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, SetXattrNullValueAndZeroSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0), SyscallSucceeds());

  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, SetXattrValueTooLargeButOKSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  std::vector<char> val(XATTR_SIZE_MAX + 1);
  std::fill(val.begin(), val.end(), 'a');
  size_t size = 1;
  EXPECT_THAT(setxattr(path, name, val.data(), size, /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  std::vector<char> expected_buf = {'a', '-'};
  EXPECT_THAT(getxattr(path, name, buf.data(), size),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, SetXattrReplaceWithSmaller) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  std::vector<char> val = {'a', 'a'};
  EXPECT_THAT(setxattr(path, name, val.data(), 2, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name, val.data(), 1, /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  std::vector<char> expected_buf = {'a', '-'};
  EXPECT_THAT(getxattr(path, name, buf.data(), 2), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, SetXattrReplaceWithLarger) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  std::vector<char> val = {'a', 'a'};
  EXPECT_THAT(setxattr(path, name, val.data(), 1, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name, val.data(), 2, /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> buf = {'-', '-'};
  EXPECT_THAT(getxattr(path, name, buf.data(), 2), SyscallSucceedsWithValue(2));
  EXPECT_EQ(buf, val);
}

TEST_F(XattrTest, SetXattrCreateFlag) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, XATTR_CREATE),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name, nullptr, 0, XATTR_CREATE),
              SyscallFailsWithErrno(EEXIST));

  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, SetXattrReplaceFlag) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, XATTR_REPLACE),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0), SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name, nullptr, 0, XATTR_REPLACE),
              SyscallSucceeds());

  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, SetXattrInvalidFlags) {
  const char* path = test_file_name_.c_str();
  int invalid_flags = 0xff;
  EXPECT_THAT(setxattr(path, nullptr, nullptr, 0, invalid_flags),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(XattrTest, GetXattr) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  int val = 1234;
  size_t size = sizeof(val);
  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  int buf = 0;
  EXPECT_THAT(getxattr(path, name, &buf, size), SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, val);
}

TEST_F(XattrTest, GetXattrSizeSmallerThanValue) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  std::vector<char> val = {'a', 'a'};
  size_t size = val.size();
  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  char buf = '-';
  EXPECT_THAT(getxattr(path, name, &buf, 1), SyscallFailsWithErrno(ERANGE));
  EXPECT_EQ(buf, '-');
}

TEST_F(XattrTest, GetXattrSizeLargerThanValue) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  EXPECT_THAT(setxattr(path, name, &val, 1, /*flags=*/0), SyscallSucceeds());

  std::vector<char> buf(XATTR_SIZE_MAX);
  std::fill(buf.begin(), buf.end(), '-');
  std::vector<char> expected_buf = buf;
  expected_buf[0] = 'a';
  EXPECT_THAT(getxattr(path, name, buf.data(), buf.size()),
              SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, GetXattrZeroSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  EXPECT_THAT(setxattr(path, name, &val, sizeof(val), /*flags=*/0),
              SyscallSucceeds());

  char buf = '-';
  EXPECT_THAT(getxattr(path, name, &buf, 0),
              SyscallSucceedsWithValue(sizeof(val)));
  EXPECT_EQ(buf, '-');
}

TEST_F(XattrTest, GetXattrSizeTooLarge) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  EXPECT_THAT(setxattr(path, name, &val, sizeof(val), /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> buf(XATTR_SIZE_MAX + 1);
  std::fill(buf.begin(), buf.end(), '-');
  std::vector<char> expected_buf = buf;
  expected_buf[0] = 'a';
  EXPECT_THAT(getxattr(path, name, buf.data(), buf.size()),
              SyscallSucceedsWithValue(sizeof(val)));
  EXPECT_EQ(buf, expected_buf);
}

TEST_F(XattrTest, GetXattrNullValue) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  size_t size = sizeof(val);
  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  EXPECT_THAT(getxattr(path, name, nullptr, size),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(XattrTest, GetXattrNullValueAndZeroSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  char val = 'a';
  size_t size = sizeof(val);
  // Set value with zero size.
  EXPECT_THAT(setxattr(path, name, &val, 0, /*flags=*/0), SyscallSucceeds());
  // Get value with nonzero size.
  EXPECT_THAT(getxattr(path, name, nullptr, size), SyscallSucceedsWithValue(0));

  // Set value with nonzero size.
  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());
  // Get value with zero size.
  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallSucceedsWithValue(size));
}

TEST_F(XattrTest, GetXattrNonexistentName) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, ListXattr) {
  const char* path = test_file_name_.c_str();
  const std::string name = "user.test";
  const std::string name2 = "user.test2";
  const std::string name3 = "user.test3";
  EXPECT_THAT(setxattr(path, name.c_str(), nullptr, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name2.c_str(), nullptr, 0, /*flags=*/0),
              SyscallSucceeds());
  EXPECT_THAT(setxattr(path, name3.c_str(), nullptr, 0, /*flags=*/0),
              SyscallSucceeds());

  std::vector<char> list(name.size() + 1 + name2.size() + 1 + name3.size() + 1);
  char* buf = list.data();
  EXPECT_THAT(listxattr(path, buf, XATTR_SIZE_MAX),
              SyscallSucceedsWithValue(list.size()));

  absl::flat_hash_set<std::string> got = {};
  for (char* p = buf; p < buf + list.size(); p += strlen(p) + 1) {
    got.insert(std::string{p});
  }

  absl::flat_hash_set<std::string> expected = {name, name2, name3};
  EXPECT_EQ(got, expected);
}

TEST_F(XattrTest, ListXattrNoXattrs) {
  const char* path = test_file_name_.c_str();

  std::vector<char> list, expected;
  EXPECT_THAT(listxattr(path, list.data(), sizeof(list)),
              SyscallSucceedsWithValue(0));
  EXPECT_EQ(list, expected);

  // ListXattr should succeed if there are no attributes, even if the buffer
  // passed in is a nullptr.
  EXPECT_THAT(listxattr(path, nullptr, sizeof(list)),
              SyscallSucceedsWithValue(0));
}

TEST_F(XattrTest, ListXattrNullBuffer) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0), SyscallSucceeds());

  EXPECT_THAT(listxattr(path, nullptr, sizeof(name)),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(XattrTest, ListXattrSizeTooSmall) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0), SyscallSucceeds());

  char list[sizeof(name) - 1];
  EXPECT_THAT(listxattr(path, list, sizeof(list)),
              SyscallFailsWithErrno(ERANGE));
}

TEST_F(XattrTest, ListXattrZeroSize) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0), SyscallSucceeds());
  EXPECT_THAT(listxattr(path, nullptr, 0),
              SyscallSucceedsWithValue(sizeof(name)));
}

TEST_F(XattrTest, RemoveXattr) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(setxattr(path, name, nullptr, 0, /*flags=*/0), SyscallSucceeds());
  EXPECT_THAT(removexattr(path, name), SyscallSucceeds());
  EXPECT_THAT(getxattr(path, name, nullptr, 0), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, RemoveXattrNonexistentName) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, LXattrOnSymlink) {
  const char name[] = "user.test";
  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(dir.path(), test_file_name_));

  EXPECT_THAT(lsetxattr(link.path().c_str(), name, nullptr, 0, 0),
              SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(lgetxattr(link.path().c_str(), name, nullptr, 0),
              SyscallFailsWithErrno(ENODATA));
  EXPECT_THAT(llistxattr(link.path().c_str(), nullptr, 0),
              SyscallSucceedsWithValue(0));
  EXPECT_THAT(lremovexattr(link.path().c_str(), name),
              SyscallFailsWithErrno(EPERM));
}

TEST_F(XattrTest, LXattrOnNonsymlink) {
  const char* path = test_file_name_.c_str();
  const char name[] = "user.test";
  int val = 1234;
  size_t size = sizeof(val);
  EXPECT_THAT(lsetxattr(path, name, &val, size, /*flags=*/0),
              SyscallSucceeds());

  int buf = 0;
  EXPECT_THAT(lgetxattr(path, name, &buf, size),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, val);

  char list[sizeof(name)];
  EXPECT_THAT(llistxattr(path, list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  EXPECT_THAT(lremovexattr(path, name), SyscallSucceeds());
}

TEST_F(XattrTest, XattrWithFD) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_.c_str(), 0));
  const char name[] = "user.test";
  int val = 1234;
  size_t size = sizeof(val);
  EXPECT_THAT(fsetxattr(fd.get(), name, &val, size, /*flags=*/0),
              SyscallSucceeds());

  int buf = 0;
  EXPECT_THAT(fgetxattr(fd.get(), name, &buf, size),
              SyscallSucceedsWithValue(size));
  EXPECT_EQ(buf, val);

  char list[sizeof(name)];
  EXPECT_THAT(flistxattr(fd.get(), list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  EXPECT_THAT(fremovexattr(fd.get(), name), SyscallSucceeds());
}

TEST_F(XattrTest, XattrWithOPath) {
  SKIP_IF(IsRunningWithVFS1());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_.c_str(), O_PATH));
  const char name[] = "user.test";
  int val = 1234;
  size_t size = sizeof(val);
  EXPECT_THAT(fsetxattr(fd.get(), name, &val, size, /*flags=*/0),
              SyscallFailsWithErrno(EBADF));

  int buf;
  EXPECT_THAT(fgetxattr(fd.get(), name, &buf, size),
              SyscallFailsWithErrno(EBADF));

  char list[sizeof(name)];
  EXPECT_THAT(flistxattr(fd.get(), list, sizeof(list)),
              SyscallFailsWithErrno(EBADF));

  EXPECT_THAT(fremovexattr(fd.get(), name), SyscallFailsWithErrno(EBADF));
}

TEST_F(XattrTest, TrustedNamespaceWithCapSysAdmin) {
  // Trusted namespace not supported in VFS1.
  SKIP_IF(IsRunningWithVFS1());

  // TODO(b/66162845): Only gVisor tmpfs currently supports trusted namespace.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(test_file_name_)));

  const char* path = test_file_name_.c_str();
  const char name[] = "trusted.test";

  // Writing to the trusted.* xattr namespace requires CAP_SYS_ADMIN in the root
  // user namespace. There's no easy way to check that, other than trying the
  // operation and seeing what happens. We'll call removexattr because it's
  // simplest.
  if (removexattr(path, name) < 0) {
    SKIP_IF(errno == EPERM);
    FAIL() << "unexpected errno from removexattr: " << errno;
  }

  // Set.
  char val = 'a';
  size_t size = sizeof(val);
  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  // Get.
  char got = '\0';
  EXPECT_THAT(getxattr(path, name, &got, size), SyscallSucceedsWithValue(size));
  EXPECT_EQ(val, got);

  // List.
  char list[sizeof(name)];
  EXPECT_THAT(listxattr(path, list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  // Remove.
  EXPECT_THAT(removexattr(path, name), SyscallSucceeds());

  // Get should now return ENODATA.
  EXPECT_THAT(getxattr(path, name, &got, size), SyscallFailsWithErrno(ENODATA));
}

TEST_F(XattrTest, TrustedNamespaceWithoutCapSysAdmin) {
  // Trusted namespace not supported in VFS1.
  SKIP_IF(IsRunningWithVFS1());

  // TODO(b/66162845): Only gVisor tmpfs currently supports trusted namespace.
  SKIP_IF(IsRunningOnGvisor() &&
          !ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(test_file_name_)));

  // Drop CAP_SYS_ADMIN if we have it.
  AutoCapability cap(CAP_SYS_ADMIN, false);

  const char* path = test_file_name_.c_str();
  const char name[] = "trusted.test";

  // Set fails.
  char val = 'a';
  size_t size = sizeof(val);
  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));

  // Get fails.
  char got = '\0';
  EXPECT_THAT(getxattr(path, name, &got, size), SyscallFailsWithErrno(ENODATA));

  // List still works, but returns no items.
  char list[sizeof(name)];
  EXPECT_THAT(listxattr(path, list, sizeof(list)), SyscallSucceedsWithValue(0));

  // Remove fails.
  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(EPERM));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
