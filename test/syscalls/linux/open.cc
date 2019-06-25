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
#include <linux/capability.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/file_base.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// This test is currently very rudimentary.
//
// There are plenty of extra cases to cover once the sentry supports them.
//
// Different types of opens:
// * O_CREAT
// * O_DIRECTORY
// * O_NOFOLLOW
// * O_PATH <- Will we ever support this?
//
// Special operations on open:
// * O_EXCL
//
// Special files:
// * Blocking behavior for a named pipe.
//
// Different errors:
// * EACCES
// * EEXIST
// * ENAMETOOLONG
// * ELOOP
// * ENOTDIR
// * EPERM
class OpenTest : public FileTest {
  void SetUp() override {
    FileTest::SetUp();

    ASSERT_THAT(
        write(test_file_fd_.get(), test_data_.c_str(), test_data_.length()),
        SyscallSucceedsWithValue(test_data_.length()));
    EXPECT_THAT(lseek(test_file_fd_.get(), 0, SEEK_SET), SyscallSucceeds());
  }

 public:
  const std::string test_data_ = "hello world\n";
};

TEST_F(OpenTest, ReadOnly) {
  char buf;
  const FileDescriptor ro_file =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));

  EXPECT_THAT(read(ro_file.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(lseek(ro_file.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(ro_file.get(), &buf, 1), SyscallFailsWithErrno(EBADF));
}

TEST_F(OpenTest, WriteOnly) {
  char buf;
  const FileDescriptor wo_file =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_WRONLY));

  EXPECT_THAT(read(wo_file.get(), &buf, 1), SyscallFailsWithErrno(EBADF));
  EXPECT_THAT(lseek(wo_file.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(wo_file.get(), &buf, 1), SyscallSucceedsWithValue(1));
}

TEST_F(OpenTest, ReadWrite) {
  char buf;
  const FileDescriptor rw_file =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  EXPECT_THAT(read(rw_file.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(lseek(rw_file.get(), 0, SEEK_SET), SyscallSucceeds());
  EXPECT_THAT(write(rw_file.get(), &buf, 1), SyscallSucceedsWithValue(1));
}

TEST_F(OpenTest, RelPath) {
  auto name = std::string(Basename(test_file_name_));

  ASSERT_THAT(chdir(GetAbsoluteTestTmpdir().c_str()), SyscallSucceeds());
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(name, O_RDONLY));
}

TEST_F(OpenTest, AbsPath) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));
}

TEST_F(OpenTest, AtRelPath) {
  auto name = std::string(Basename(test_file_name_));
  const FileDescriptor dirfd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(GetAbsoluteTestTmpdir(), O_RDONLY | O_DIRECTORY));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenAt(dirfd.get(), name, O_RDONLY));
}

TEST_F(OpenTest, AtAbsPath) {
  const FileDescriptor dirfd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(GetAbsoluteTestTmpdir(), O_RDONLY | O_DIRECTORY));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenAt(dirfd.get(), test_file_name_, O_RDONLY));
}

TEST_F(OpenTest, OpenNoFollowSymlink) {
  const std::string link_path = JoinPath(GetAbsoluteTestTmpdir(), "link");
  ASSERT_THAT(symlink(test_file_name_.c_str(), link_path.c_str()),
              SyscallSucceeds());
  auto cleanup = Cleanup([link_path]() {
    EXPECT_THAT(unlink(link_path.c_str()), SyscallSucceeds());
  });

  // Open will succeed without O_NOFOLLOW and fails with O_NOFOLLOW.
  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(link_path, O_RDONLY));
  ASSERT_THAT(open(link_path.c_str(), O_RDONLY | O_NOFOLLOW),
              SyscallFailsWithErrno(ELOOP));
}

TEST_F(OpenTest, OpenNoFollowStillFollowsLinksInPath) {
  // We will create the following structure:
  // tmp_folder/real_folder/file
  // tmp_folder/sym_folder -> tmp_folder/real_folder
  //
  // We will then open tmp_folder/sym_folder/file with O_NOFOLLOW and it
  // should succeed as O_NOFOLLOW only applies to the final path component.
  auto tmp_path =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(GetAbsoluteTestTmpdir()));
  auto sym_path = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(GetAbsoluteTestTmpdir(), tmp_path.path()));
  auto file_path =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(tmp_path.path()));

  auto path_via_symlink = JoinPath(sym_path.path(), Basename(file_path.path()));
  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path_via_symlink, O_RDONLY | O_NOFOLLOW));
}

TEST_F(OpenTest, Fault) {
  char* totally_not_null = nullptr;
  ASSERT_THAT(open(totally_not_null, O_RDONLY), SyscallFailsWithErrno(EFAULT));
}

TEST_F(OpenTest, AppendOnly) {
  // First write some data to the fresh file.
  const int64_t kBufSize = 1024;
  std::vector<char> buf(kBufSize, 'a');

  FileDescriptor fd0 = ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR));

  std::fill(buf.begin(), buf.end(), 'a');
  EXPECT_THAT(WriteFd(fd0.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  fd0.reset();  // Close the file early.

  // Next get two handles to the same file. We open two files because we want
  // to make sure that appending is respected between them.
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR | O_APPEND));
  EXPECT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR | O_APPEND));
  EXPECT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  // Then try to write to the first file and make sure the bytes are appended.
  EXPECT_THAT(WriteFd(fd1.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Check that the size of the file is correct and that the offset has been
  // incremented to that size.
  struct stat s0;
  EXPECT_THAT(fstat(fd1.get(), &s0), SyscallSucceeds());
  EXPECT_EQ(s0.st_size, kBufSize * 2);
  EXPECT_THAT(lseek(fd1.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kBufSize * 2));

  // Then try to write to the second file and make sure the bytes are appended.
  EXPECT_THAT(WriteFd(fd2.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Check that the size of the file is correct and that the offset has been
  // incremented to that size.
  struct stat s1;
  EXPECT_THAT(fstat(fd2.get(), &s1), SyscallSucceeds());
  EXPECT_EQ(s1.st_size, kBufSize * 3);
  EXPECT_THAT(lseek(fd2.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(kBufSize * 3));
}

TEST_F(OpenTest, AppendConcurrentWrite) {
  constexpr int kThreadCount = 5;
  constexpr int kBytesPerThread = 10000;
  std::unique_ptr<ScopedThread> threads[kThreadCount];

  // In case of the uncached policy, we expect that a file system can be changed
  // externally, so we create a new inode each time when we open a file and we
  // can't guarantee that writes to files with O_APPEND will work correctly.
  SKIP_IF(getenv("GVISOR_GOFER_UNCACHED"));

  EXPECT_THAT(truncate(test_file_name_.c_str(), 0), SyscallSucceeds());

  std::string filename = test_file_name_;
  DisableSave ds;  // Too many syscalls.
  // Start kThreadCount threads which will write concurrently into the same
  // file.
  for (int i = 0; i < kThreadCount; i++) {
    threads[i] = absl::make_unique<ScopedThread>([filename]() {
      const FileDescriptor fd =
          ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_RDWR | O_APPEND));

      for (int j = 0; j < kBytesPerThread; j++) {
        EXPECT_THAT(WriteFd(fd.get(), &j, 1), SyscallSucceedsWithValue(1));
      }
    });
  }
  for (int i = 0; i < kThreadCount; i++) {
    threads[i]->Join();
  }

  // Check that the size of the file is correct.
  struct stat st;
  EXPECT_THAT(stat(test_file_name_.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, kThreadCount * kBytesPerThread);
}

TEST_F(OpenTest, Truncate) {
  {
    // First write some data to the new file and close it.
    FileDescriptor fd0 =
        ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_WRONLY));
    std::vector<char> orig(10, 'a');
    EXPECT_THAT(WriteFd(fd0.get(), orig.data(), orig.size()),
                SyscallSucceedsWithValue(orig.size()));
  }

  // Then open with truncate and verify that offset is set to 0.
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDWR | O_TRUNC));
  EXPECT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  // Then write less data to the file and ensure the old content is gone.
  std::vector<char> want(5, 'b');
  EXPECT_THAT(WriteFd(fd1.get(), want.data(), want.size()),
              SyscallSucceedsWithValue(want.size()));

  struct stat stat;
  EXPECT_THAT(fstat(fd1.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(stat.st_size, want.size());
  EXPECT_THAT(lseek(fd1.get(), 0, SEEK_CUR),
              SyscallSucceedsWithValue(want.size()));

  // Read the data and ensure only the latest write is in the file.
  std::vector<char> got(want.size() + 1, 'c');
  ASSERT_THAT(pread(fd1.get(), got.data(), got.size(), 0),
              SyscallSucceedsWithValue(want.size()));
  EXPECT_EQ(memcmp(want.data(), got.data(), want.size()), 0)
      << "rbuf=" << got.data();
  EXPECT_EQ(got.back(), 'c');  // Last byte should not have been modified.
}

TEST_F(OpenTest, NameTooLong) {
  char buf[4097] = {};
  memset(buf, 'a', 4097);
  EXPECT_THAT(open(buf, O_RDONLY), SyscallFailsWithErrno(ENAMETOOLONG));
}

TEST_F(OpenTest, DotsFromRoot) {
  const FileDescriptor rootfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/", O_RDONLY | O_DIRECTORY));
  const FileDescriptor other_rootfd =
      ASSERT_NO_ERRNO_AND_VALUE(OpenAt(rootfd.get(), "..", O_RDONLY));
}

TEST_F(OpenTest, DirectoryWritableFails) {
  ASSERT_THAT(open(GetAbsoluteTestTmpdir().c_str(), O_RDWR),
              SyscallFailsWithErrno(EISDIR));
}

TEST_F(OpenTest, FileNotDirectory) {
  // Create a file and try to open it with O_DIRECTORY.
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  ASSERT_THAT(open(file.path().c_str(), O_RDONLY | O_DIRECTORY),
              SyscallFailsWithErrno(ENOTDIR));
}

TEST_F(OpenTest, Null) {
  char c = '\0';
  ASSERT_THAT(open(&c, O_RDONLY), SyscallFailsWithErrno(ENOENT));
}

// NOTE(b/119785738): While the man pages specify that this behavior should be
// undefined, Linux truncates the file on opening read only if we have write
// permission, so we will too.
TEST_F(OpenTest, CanTruncateReadOnly) {
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY | O_TRUNC));

  struct stat stat;
  EXPECT_THAT(fstat(fd1.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(stat.st_size, 0);
}

// If we don't have read permission on the file, opening with
// O_TRUNC should fail.
TEST_F(OpenTest, CanTruncateReadOnlyNoWritePermission_NoRandomSave) {
  // Drop capabilities that allow us to override file permissions.
  ASSERT_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));

  const DisableSave ds;  // Permissions are dropped.
  ASSERT_THAT(chmod(test_file_name_.c_str(), S_IRUSR | S_IRGRP),
              SyscallSucceeds());

  ASSERT_THAT(open(test_file_name_.c_str(), O_RDONLY | O_TRUNC),
              SyscallFailsWithErrno(EACCES));

  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));

  struct stat stat;
  EXPECT_THAT(fstat(fd1.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(stat.st_size, test_data_.size());
}

// If we don't have read permission but have write permission, opening O_WRONLY
// and O_TRUNC should succeed.
TEST_F(OpenTest, CanTruncateWriteOnlyNoReadPermission_NoRandomSave) {
  const DisableSave ds;  // Permissions are dropped.

  EXPECT_THAT(fchmod(test_file_fd_.get(), S_IWUSR | S_IWGRP),
              SyscallSucceeds());

  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_WRONLY | O_TRUNC));

  EXPECT_THAT(fchmod(test_file_fd_.get(), S_IRUSR | S_IRGRP),
              SyscallSucceeds());

  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(test_file_name_, O_RDONLY));

  struct stat stat;
  EXPECT_THAT(fstat(fd2.get(), &stat), SyscallSucceeds());
  EXPECT_EQ(stat.st_size, 0);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
