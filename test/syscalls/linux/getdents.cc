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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/node_hash_map.h"
#include "absl/container/node_hash_set.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::Contains;
using ::testing::IsEmpty;
using ::testing::IsSupersetOf;
using ::testing::Not;
using ::testing::NotNull;

namespace gvisor {
namespace testing {

namespace {

// New Linux dirent format.
struct linux_dirent64 {
  uint64_t d_ino;           // Inode number
  int64_t d_off;            // Offset to next linux_dirent64
  unsigned short d_reclen;  // NOLINT, Length of this linux_dirent64
  unsigned char d_type;     // NOLINT, File type
  char d_name[0];           // Filename (null-terminated)
};

// Old Linux dirent format.
struct linux_dirent {
  unsigned long d_ino;      // NOLINT
  unsigned long d_off;      // NOLINT
  unsigned short d_reclen;  // NOLINT
  char d_name[0];
};

// Wraps a buffer to provide a set of dirents.
// T is the underlying dirent type.
template <typename T>
class DirentBuffer {
 public:
  // DirentBuffer manages the buffer.
  explicit DirentBuffer(size_t size)
      : managed_(true), actual_size_(size), reported_size_(size) {
    data_ = new char[actual_size_];
  }

  // The buffer is managed externally.
  DirentBuffer(char* data, size_t actual_size, size_t reported_size)
      : managed_(false),
        data_(data),
        actual_size_(actual_size),
        reported_size_(reported_size) {}

  ~DirentBuffer() {
    if (managed_) {
      delete[] data_;
    }
  }

  T* Data() { return reinterpret_cast<T*>(data_); }

  T* Start(size_t read) {
    read_ = read;
    if (read_) {
      return Data();
    } else {
      return nullptr;
    }
  }

  T* Current() { return reinterpret_cast<T*>(&data_[off_]); }

  T* Next() {
    size_t new_off = off_ + Current()->d_reclen;
    if (new_off >= read_ || new_off >= actual_size_) {
      return nullptr;
    }

    off_ = new_off;
    return Current();
  }

  size_t Size() { return reported_size_; }

  void Reset() {
    off_ = 0;
    read_ = 0;
    memset(data_, 0, actual_size_);
  }

 private:
  bool managed_;
  char* data_;
  size_t actual_size_;
  size_t reported_size_;

  size_t off_ = 0;

  size_t read_ = 0;
};

// Test for getdents/getdents64.
// T is the Linux dirent type.
template <typename T>
class GetdentsTest : public ::testing::Test {
 public:
  using LinuxDirentType = T;
  using DirentBufferType = DirentBuffer<T>;

 protected:
  void SetUp() override {
    dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    fd_ = ASSERT_NO_ERRNO_AND_VALUE(Open(dir_.path(), O_RDONLY | O_DIRECTORY));
  }

  // Must be overridden with explicit specialization. See below.
  int SyscallNum();

  int Getdents(LinuxDirentType* dirp, unsigned int count) {
    return RetryEINTR(syscall)(SyscallNum(), fd_.get(), dirp, count);
  }

  // Fill directory with num files, named by number starting at 0.
  void FillDirectory(size_t num) {
    for (size_t i = 0; i < num; i++) {
      auto name = JoinPath(dir_.path(), absl::StrCat(i));
      TEST_CHECK(CreateWithContents(name, "").ok());
    }
  }

  // Fill directory with a given list of filenames.
  void FillDirectoryWithFiles(const std::vector<std::string>& filenames) {
    for (const auto& filename : filenames) {
      auto name = JoinPath(dir_.path(), filename);
      TEST_CHECK(CreateWithContents(name, "").ok());
    }
  }

  // Seek to the start of the directory.
  PosixError SeekStart() {
    constexpr off_t kStartOfFile = 0;
    off_t offset = lseek(fd_.get(), kStartOfFile, SEEK_SET);
    if (offset < 0) {
      return PosixError(errno, absl::StrCat("error seeking to ", kStartOfFile));
    }
    if (offset != kStartOfFile) {
      return PosixError(EINVAL, absl::StrCat("tried to seek to ", kStartOfFile,
                                             " but got ", offset));
    }
    return NoError();
  }

  // Call getdents multiple times, reading all dirents and calling f on each.
  // f has the type signature PosixError f(T*).
  // If f returns a non-OK error, so does ReadDirents.
  template <typename F>
  PosixError ReadDirents(DirentBufferType* dirents, F const& f) {
    int n;
    do {
      dirents->Reset();

      n = Getdents(dirents->Data(), dirents->Size());
      MaybeSave();
      if (n < 0) {
        return PosixError(errno, "getdents");
      }

      for (auto d = dirents->Start(n); d; d = dirents->Next()) {
        RETURN_IF_ERRNO(f(d));
      }
    } while (n > 0);

    return NoError();
  }

  // Call Getdents successively and count all entries.
  int ReadAndCountAllEntries(DirentBufferType* dirents) {
    int found = 0;

    EXPECT_NO_ERRNO(ReadDirents(dirents, [&](LinuxDirentType* d) {
      found++;
      return NoError();
    }));

    return found;
  }

 private:
  TempPath dir_;
  FileDescriptor fd_;
};

// Multiple template parameters are not allowed, so we must use explicit
// template specialization to set the syscall number.

// SYS_getdents isn't defined on arm64.
#ifdef __x86_64__
template <>
int GetdentsTest<struct linux_dirent>::SyscallNum() {
  return SYS_getdents;
}
#endif

template <>
int GetdentsTest<struct linux_dirent64>::SyscallNum() {
  return SYS_getdents64;
}

#ifdef __x86_64__
// Test both legacy getdents and getdents64 on x86_64.
typedef ::testing::Types<struct linux_dirent, struct linux_dirent64>
    GetdentsTypes;
#elif __aarch64__
// Test only getdents64 on arm64.
typedef ::testing::Types<struct linux_dirent64> GetdentsTypes;
#endif
TYPED_TEST_SUITE(GetdentsTest, GetdentsTypes);

// N.B. TYPED_TESTs require explicitly using this-> to access members of
// GetdentsTest, since we are inside of a derived class template.

TYPED_TEST(GetdentsTest, VerifyEntries) {
  typename TestFixture::DirentBufferType dirents(1024);

  this->FillDirectory(2);

  // Map of all the entries we expect to find.
  std::map<std::string, bool> found;
  found["."] = false;
  found[".."] = false;
  found["0"] = false;
  found["1"] = false;

  EXPECT_NO_ERRNO(this->ReadDirents(
      &dirents, [&](typename TestFixture::LinuxDirentType* d) {
        auto kv = found.find(d->d_name);
        EXPECT_NE(kv, found.end()) << "Unexpected file: " << d->d_name;
        if (kv != found.end()) {
          EXPECT_FALSE(kv->second);
        }
        found[d->d_name] = true;
        return NoError();
      }));

  for (auto& kv : found) {
    EXPECT_TRUE(kv.second) << "File not found: " << kv.first;
  }
}

TYPED_TEST(GetdentsTest, VerifyPadding) {
  typename TestFixture::DirentBufferType dirents(1024);

  // Create files with names of length 1 through 16.
  std::vector<std::string> files;
  std::string filename;
  for (int i = 0; i < 16; ++i) {
    absl::StrAppend(&filename, "a");
    files.push_back(filename);
  }
  this->FillDirectoryWithFiles(files);

  // We expect to find all the files, plus '.' and '..'.
  const int expect_found = 2 + files.size();
  int found = 0;

  EXPECT_NO_ERRNO(this->ReadDirents(
      &dirents, [&](typename TestFixture::LinuxDirentType* d) {
        EXPECT_EQ(d->d_reclen % 8, 0)
            << "Dirent " << d->d_name
            << " had reclen that was not byte aligned: " << d->d_name;
        found++;
        return NoError();
      }));

  // Make sure we found all the files.
  EXPECT_EQ(found, expect_found);
}

// For a small directory, the provided buffer should be large enough
// for all entries.
TYPED_TEST(GetdentsTest, SmallDir) {
  // . and .. should be in an otherwise empty directory.
  int expect = 2;

  // Add some actual files.
  this->FillDirectory(2);
  expect += 2;

  typename TestFixture::DirentBufferType dirents(256);

  EXPECT_EQ(expect, this->ReadAndCountAllEntries(&dirents));
}

// A directory with lots of files requires calling getdents multiple times.
TYPED_TEST(GetdentsTest, LargeDir) {
  // . and .. should be in an otherwise empty directory.
  int expect = 2;

  // Add some actual files.
  this->FillDirectory(100);
  expect += 100;

  typename TestFixture::DirentBufferType dirents(256);

  EXPECT_EQ(expect, this->ReadAndCountAllEntries(&dirents));
}

// If we lie about the size of the buffer, we should still be able to read the
// entries with the available space.
TYPED_TEST(GetdentsTest, PartialBuffer) {
  // . and .. should be in an otherwise empty directory.
  int expect = 2;

  // Add some actual files.
  this->FillDirectory(100);
  expect += 100;

  void* addr = mmap(0, 2 * kPageSize, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(addr, MAP_FAILED);

  char* buf = reinterpret_cast<char*>(addr);

  // Guard page
  EXPECT_THAT(
      mprotect(reinterpret_cast<void*>(buf + kPageSize), kPageSize, PROT_NONE),
      SyscallSucceeds());

  // Limit space in buf to 256 bytes.
  buf += kPageSize - 256;

  // Lie about the buffer. Even though we claim the buffer is 1 page,
  // we should still get all of the dirents in the first 256 bytes.
  typename TestFixture::DirentBufferType dirents(buf, 256, kPageSize);

  EXPECT_EQ(expect, this->ReadAndCountAllEntries(&dirents));

  EXPECT_THAT(munmap(addr, 2 * kPageSize), SyscallSucceeds());
}

// Open many file descriptors, then scan through /proc/self/fd to find and close
// them all. (The latter is commonly used to handle races between fork/execve
// and the creation of unwanted non-O_CLOEXEC file descriptors.) This tests that
// getdents iterates correctly despite mutation of /proc/self/fd.
TYPED_TEST(GetdentsTest, ProcSelfFd) {
  constexpr size_t kNfds = 10;
  absl::node_hash_map<int, FileDescriptor> fds;
  fds.reserve(kNfds);
  for (size_t i = 0; i < kNfds; i++) {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());
    fds.emplace(fd.get(), std::move(fd));
  }

  const FileDescriptor proc_self_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/fd", O_RDONLY | O_DIRECTORY));

  // Make the buffer very small since we want to iterate.
  typename TestFixture::DirentBufferType dirents(
      2 * sizeof(typename TestFixture::LinuxDirentType));
  absl::node_hash_set<int> prev_fds;
  while (true) {
    dirents.Reset();
    int rv;
    ASSERT_THAT(rv = RetryEINTR(syscall)(this->SyscallNum(), proc_self_fd.get(),
                                         dirents.Data(), dirents.Size()),
                SyscallSucceeds());
    if (rv == 0) {
      break;
    }
    for (auto* d = dirents.Start(rv); d; d = dirents.Next()) {
      int dfd;
      if (!absl::SimpleAtoi(d->d_name, &dfd)) continue;
      EXPECT_TRUE(prev_fds.insert(dfd).second)
          << "Repeated observation of /proc/self/fd/" << dfd;
      fds.erase(dfd);
    }
  }

  // Check that we closed every fd.
  EXPECT_THAT(fds, ::testing::IsEmpty());
}

// Test that getdents returns ENOTDIR when called on a file.
TYPED_TEST(GetdentsTest, NotDir) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  typename TestFixture::DirentBufferType dirents(256);
  EXPECT_THAT(RetryEINTR(syscall)(this->SyscallNum(), fd.get(), dirents.Data(),
                                  dirents.Size()),
              SyscallFailsWithErrno(ENOTDIR));
}

// Test that getdents returns EBADF when called on an opath file.
TYPED_TEST(GetdentsTest, OpathFile) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_PATH));

  typename TestFixture::DirentBufferType dirents(256);
  EXPECT_THAT(RetryEINTR(syscall)(this->SyscallNum(), fd.get(), dirents.Data(),
                                  dirents.Size()),
              SyscallFailsWithErrno(EBADF));
}

// Test that getdents returns EBADF when called on an opath directory.
TYPED_TEST(GetdentsTest, OpathDirectory) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_PATH | O_DIRECTORY));

  typename TestFixture::DirentBufferType dirents(256);
  ASSERT_THAT(RetryEINTR(syscall)(this->SyscallNum(), fd.get(), dirents.Data(),
                                  dirents.Size()),
              SyscallFailsWithErrno(EBADF));
}

// Test that SEEK_SET to 0 causes getdents to re-read the entries.
TYPED_TEST(GetdentsTest, SeekResetsCursor) {
  // . and .. should be in an otherwise empty directory.
  int expect = 2;

  // Add some files to the directory.
  this->FillDirectory(10);
  expect += 10;

  typename TestFixture::DirentBufferType dirents(256);

  // We should get all the expected entries.
  EXPECT_EQ(expect, this->ReadAndCountAllEntries(&dirents));

  // Seek back to 0.
  ASSERT_NO_ERRNO(this->SeekStart());

  // We should get all the expected entries again.
  EXPECT_EQ(expect, this->ReadAndCountAllEntries(&dirents));
}

// Test that getdents() after SEEK_END succeeds.
// This is a regression test for #128.
TYPED_TEST(GetdentsTest, Issue128ProcSeekEnd) {
  auto fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self", O_RDONLY | O_DIRECTORY));
  typename TestFixture::DirentBufferType dirents(256);

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(syscall)(this->SyscallNum(), fd.get(), dirents.Data(),
                                  dirents.Size()),
              SyscallSucceeds());
}

// Tests that getdents() fails when called with a zero-length buffer.
TYPED_TEST(GetdentsTest, ZeroLengthOutBuffer) {
  auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_DIRECTORY));

  typename TestFixture::DirentBufferType dirents(0);
  ASSERT_THAT(RetryEINTR(syscall)(this->SyscallNum(), fd.get(), dirents.Data(),
                                  dirents.Size()),
              SyscallFailsWithErrno(EINVAL));
}

// Some tests using the glibc readdir interface.
TEST(ReaddirTest, OpenDir) {
  DIR* dev;
  ASSERT_THAT(dev = opendir("/dev"), NotNull());
  EXPECT_THAT(closedir(dev), SyscallSucceeds());
}

TEST(ReaddirTest, RootContainsBasicDirectories) {
  EXPECT_THAT(ListDir("/", true),
              IsPosixErrorOkAndHolds(IsSupersetOf(
                  {"bin", "dev", "etc", "lib", "proc", "sbin", "usr"})));
}

TEST(ReaddirTest, Bug24096713Dev) {
  auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir("/dev", true));
  EXPECT_THAT(contents, Not(IsEmpty()));
}

TEST(ReaddirTest, Bug24096713ProcTid) {
  auto contents = ASSERT_NO_ERRNO_AND_VALUE(
      ListDir(absl::StrCat("/proc/", syscall(SYS_gettid), "/"), true));
  EXPECT_THAT(contents, Not(IsEmpty()));
}

TEST(ReaddirTest, Bug33429925Proc) {
  auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir("/proc", true));
  EXPECT_THAT(contents, Not(IsEmpty()));
}

TEST(ReaddirTest, Bug35110122Root) {
  auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir("/", true));
  EXPECT_THAT(contents, Not(IsEmpty()));
}

// Unlink should invalidate getdents cache.
TEST(ReaddirTest, GoneAfterRemoveCache) {
  TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  std::string name = std::string(Basename(file.path()));

  auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(dir.path(), true));
  EXPECT_THAT(contents, Contains(name));

  file.reset();

  contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(dir.path(), true));
  EXPECT_THAT(contents, Not(Contains(name)));
}

// Regression test for b/137398511. Rename should invalidate getdents cache.
TEST(ReaddirTest, GoneAfterRenameCache) {
  TempPath src = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath dst = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(src.path()));
  std::string name = std::string(Basename(file.path()));

  auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(src.path(), true));
  EXPECT_THAT(contents, Contains(name));

  ASSERT_THAT(rename(file.path().c_str(), JoinPath(dst.path(), name).c_str()),
              SyscallSucceeds());
  // Release file since it was renamed. dst cleanup will ultimately delete it.
  file.release();

  contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(src.path(), true));
  EXPECT_THAT(contents, Not(Contains(name)));

  contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(dst.path(), true));
  EXPECT_THAT(contents, Contains(name));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
