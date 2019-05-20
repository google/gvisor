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

#include <fcntl.h>
#include <sys/stat.h>

#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using ::testing::IsEmpty;
using ::testing::Not;

std::tuple<absl::Time, absl::Time, absl::Time> GetTime(const TempPath& file) {
  struct stat statbuf = {};
  EXPECT_THAT(stat(file.path().c_str(), &statbuf), SyscallSucceeds());

  const auto atime = absl::TimeFromTimespec(statbuf.st_atim);
  const auto mtime = absl::TimeFromTimespec(statbuf.st_mtim);
  const auto ctime = absl::TimeFromTimespec(statbuf.st_ctim);
  return std::make_tuple(atime, mtime, ctime);
}

enum class AtimeEffect {
  Unchanged,
  Changed,
};

enum class MtimeEffect {
  Unchanged,
  Changed,
};

enum class CtimeEffect {
  Unchanged,
  Changed,
};

// Tests that fn modifies the atime/mtime/ctime of path as specified.
void CheckTimes(const TempPath& path, std::function<void()> fn,
                AtimeEffect atime_effect, MtimeEffect mtime_effect,
                CtimeEffect ctime_effect) {
  absl::Time atime, mtime, ctime;
  std::tie(atime, mtime, ctime) = GetTime(path);

  // FIXME(b/132819225): gVisor filesystem timestamps inconsistently use the
  // internal or host clock, which may diverge slightly. Allow some slack on
  // times to account for the difference.
  //
  // Here we sleep for 1s so that initial creation of path doesn't fall within
  // the before slack window.
  absl::SleepFor(absl::Seconds(1));

  const absl::Time before = absl::Now() - absl::Seconds(1);

  // Perform the op.
  fn();

  const absl::Time after = absl::Now() + absl::Seconds(1);

  absl::Time atime2, mtime2, ctime2;
  std::tie(atime2, mtime2, ctime2) = GetTime(path);

  if (atime_effect == AtimeEffect::Changed) {
    EXPECT_LE(before, atime2);
    EXPECT_GE(after, atime2);
    EXPECT_GT(atime2, atime);
  } else {
    EXPECT_EQ(atime2, atime);
  }

  if (mtime_effect == MtimeEffect::Changed) {
    EXPECT_LE(before, mtime2);
    EXPECT_GE(after, mtime2);
    EXPECT_GT(mtime2, mtime);
  } else {
    EXPECT_EQ(mtime2, mtime);
  }

  if (ctime_effect == CtimeEffect::Changed) {
    EXPECT_LE(before, ctime2);
    EXPECT_GE(after, ctime2);
    EXPECT_GT(ctime2, ctime);
  } else {
    EXPECT_EQ(ctime2, ctime);
  }
}

// File creation time is reflected in atime, mtime, and ctime.
TEST(StatTimesTest, FileCreation) {
  const DisableSave ds;  // Timing-related test.

  // Get a time for when the file is created.
  //
  // FIXME(b/132819225): See above.
  const absl::Time before = absl::Now() - absl::Seconds(1);
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const absl::Time after = absl::Now() + absl::Seconds(1);

  absl::Time atime, mtime, ctime;
  std::tie(atime, mtime, ctime) = GetTime(file);

  EXPECT_LE(before, atime);
  EXPECT_LE(before, mtime);
  EXPECT_LE(before, ctime);
  EXPECT_GE(after, atime);
  EXPECT_GE(after, mtime);
  EXPECT_GE(after, ctime);
}

// Calling chmod on a file changes ctime.
TEST(StatTimesTest, FileChmod) {
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  auto fn = [&] {
    EXPECT_THAT(chmod(file.path().c_str(), 0666), SyscallSucceeds());
  };
  CheckTimes(file, fn, AtimeEffect::Unchanged, MtimeEffect::Unchanged,
             CtimeEffect::Changed);
}

// Renaming a file changes ctime.
TEST(StatTimesTest, FileRename) {
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  const std::string newpath = NewTempAbsPath();

  auto fn = [&] {
    ASSERT_THAT(rename(file.release().c_str(), newpath.c_str()),
                SyscallSucceeds());
    file.reset(newpath);
  };
  CheckTimes(file, fn, AtimeEffect::Unchanged, MtimeEffect::Unchanged,
             CtimeEffect::Changed);
}

// Renaming a file changes ctime, even with an open FD.
//
// NOTE(b/132732387): This is a regression test for fs/gofer failing to update
// cached ctime.
TEST(StatTimesTest, FileRenameOpenFD) {
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Holding an FD shouldn't affect behavior.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  const std::string newpath = NewTempAbsPath();

  // FIXME(b/132814682): Restore fails with an uncached gofer and an open FD
  // across rename.
  //
  // N.B. The logic here looks backwards because it isn't possible to
  // conditionally disable save, only conditionally re-enable it.
  DisableSave ds;
  if (!getenv("GVISOR_GOFER_UNCACHED")) {
    ds.reset();
  }

  auto fn = [&] {
    ASSERT_THAT(rename(file.release().c_str(), newpath.c_str()),
                SyscallSucceeds());
    file.reset(newpath);
  };
  CheckTimes(file, fn, AtimeEffect::Unchanged, MtimeEffect::Unchanged,
             CtimeEffect::Changed);
}

// Calling utimes on a file changes ctime and the time that we ask to change
// (atime to now in this case).
TEST(StatTimesTest, FileUtimes) {
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  auto fn = [&] {
    const struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
    ASSERT_THAT(utimensat(AT_FDCWD, file.path().c_str(), ts, 0),
                SyscallSucceeds());
  };
  CheckTimes(file, fn, AtimeEffect::Changed, MtimeEffect::Unchanged,
             CtimeEffect::Changed);
}

// Truncating a file changes mtime and ctime.
TEST(StatTimesTest, FileTruncate) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "yaaass", 0666));

  auto fn = [&] {
    EXPECT_THAT(truncate(file.path().c_str(), 0), SyscallSucceeds());
  };
  CheckTimes(file, fn, AtimeEffect::Unchanged, MtimeEffect::Changed,
             CtimeEffect::Changed);
}

// Writing a file changes mtime and ctime.
TEST(StatTimesTest, FileWrite) {
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "yaaass", 0666));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0));

  auto fn = [&] {
    const std::string contents = "all the single dollars";
    EXPECT_THAT(WriteFd(fd.get(), contents.data(), contents.size()),
                SyscallSucceeds());
  };
  CheckTimes(file, fn, AtimeEffect::Unchanged, MtimeEffect::Changed,
             CtimeEffect::Changed);
}

// Reading a file changes atime.
TEST(StatTimesTest, FileRead) {
  const std::string contents = "bills bills bills";
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), contents, 0666));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY, 0));

  auto fn = [&] {
    char buf[20];
    ASSERT_THAT(ReadFd(fd.get(), buf, sizeof(buf)),
                SyscallSucceedsWithValue(contents.size()));
  };
  CheckTimes(file, fn, AtimeEffect::Changed, MtimeEffect::Unchanged,
             CtimeEffect::Unchanged);
}

// Listing files in a directory changes atime.
TEST(StatTimesTest, DirList) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  auto fn = [&] {
    const auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(dir.path(), false));
    EXPECT_THAT(contents, Not(IsEmpty()));
  };
  CheckTimes(dir, fn, AtimeEffect::Changed, MtimeEffect::Unchanged,
             CtimeEffect::Unchanged);
}

// Creating a file in a directory changes mtime and ctime.
TEST(StatTimesTest, DirCreateFile) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  TempPath file;
  auto fn = [&] {
    file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  };
  CheckTimes(dir, fn, AtimeEffect::Unchanged, MtimeEffect::Changed,
             CtimeEffect::Changed);
}

// Creating a directory in a directory changes mtime and ctime.
TEST(StatTimesTest, DirCreateDir) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  TempPath dir2;
  auto fn = [&] {
    dir2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  };
  CheckTimes(dir, fn, AtimeEffect::Unchanged, MtimeEffect::Changed,
             CtimeEffect::Changed);
}

// Removing a file from a directory changes mtime and ctime.
TEST(StatTimesTest, DirRemoveFile) {
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  auto fn = [&] { file.reset(); };
  CheckTimes(dir, fn, AtimeEffect::Unchanged, MtimeEffect::Changed,
             CtimeEffect::Changed);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
