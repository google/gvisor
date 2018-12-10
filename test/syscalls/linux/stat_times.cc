// Copyright 2018 Google LLC
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

class StatTimesTest : public ::testing::Test {
 protected:
  std::tuple<absl::Time, absl::Time, absl::Time> GetTime(const TempPath& file) {
    struct stat statbuf = {};
    EXPECT_THAT(stat(file.path().c_str(), &statbuf), SyscallSucceeds());

    const auto atime = absl::TimeFromTimespec(statbuf.st_atim);
    const auto mtime = absl::TimeFromTimespec(statbuf.st_mtim);
    const auto ctime = absl::TimeFromTimespec(statbuf.st_ctim);
    return std::make_tuple(atime, mtime, ctime);
  }
};

TEST_F(StatTimesTest, FileCreationTimes) {
  const DisableSave ds;  // Timing-related test.

  // Get a time for when the file is created.
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

TEST_F(StatTimesTest, FileCtimeChanges) {
  auto file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  MaybeSave();  // FIXME: ctime is inconsistent.

  absl::Time atime, mtime, ctime;
  std::tie(atime, mtime, ctime) = GetTime(file);

  absl::SleepFor(absl::Seconds(1));

  // Chmod should only change ctime.
  EXPECT_THAT(chmod(file.path().c_str(), 0666), SyscallSucceeds());

  absl::Time atime2, mtime2, ctime2;
  std::tie(atime2, mtime2, ctime2) = GetTime(file);
  EXPECT_EQ(atime2, atime);
  EXPECT_EQ(mtime2, mtime);
  EXPECT_GT(ctime2, ctime);

  absl::SleepFor(absl::Seconds(1));

  // Rename should only change ctime.
  const auto newpath = NewTempAbsPath();
  EXPECT_THAT(rename(file.path().c_str(), newpath.c_str()), SyscallSucceeds());
  file.reset(newpath);

  std::tie(atime, mtime, ctime) = GetTime(file);
  EXPECT_EQ(atime, atime2);
  EXPECT_EQ(mtime, mtime2);
  EXPECT_GT(ctime, ctime2);

  absl::SleepFor(absl::Seconds(1));

  // Utimes should only change ctime and the time that we ask to change (atime
  // to now in this case).
  const absl::Time before = absl::Now() - absl::Seconds(1);
  const struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
  ASSERT_THAT(utimensat(AT_FDCWD, file.path().c_str(), ts, 0),
              SyscallSucceeds());
  const absl::Time after = absl::Now() + absl::Seconds(1);

  std::tie(atime2, mtime2, ctime2) = GetTime(file);
  EXPECT_LE(before, atime2);
  EXPECT_GE(after, atime2);
  EXPECT_EQ(mtime2, mtime);
  EXPECT_GT(ctime2, ctime);
}

TEST_F(StatTimesTest, FileMtimeChanges) {
  const auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "yaaass", 0666));

  absl::Time atime, mtime, ctime;
  std::tie(atime, mtime, ctime) = GetTime(file);

  absl::SleepFor(absl::Seconds(1));

  // Truncate should only change mtime and ctime.
  EXPECT_THAT(truncate(file.path().c_str(), 0), SyscallSucceeds());

  absl::Time atime2, mtime2, ctime2;
  std::tie(atime2, mtime2, ctime2) = GetTime(file);
  EXPECT_EQ(atime2, atime);
  EXPECT_GT(mtime2, mtime);
  EXPECT_GT(ctime2, ctime);

  absl::SleepFor(absl::Seconds(1));

  // Write should only change mtime and ctime.
  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR, 0));
  const std::string contents = "all the single dollars";
  EXPECT_THAT(write(fd.get(), contents.data(), contents.size()),
              SyscallSucceeds());

  std::tie(atime, mtime, ctime) = GetTime(file);
  EXPECT_EQ(atime, atime2);
  EXPECT_GT(mtime, mtime2);
  EXPECT_GT(ctime, ctime2);
}

TEST_F(StatTimesTest, FileAtimeChanges) {
  const std::string contents = "bills bills bills";
  const auto file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), contents, 0666));

  MaybeSave();  // FIXME: ctime is inconsistent.

  absl::Time atime, mtime, ctime;
  std::tie(atime, mtime, ctime) = GetTime(file);

  absl::SleepFor(absl::Seconds(1));

  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY, 0));

  // Read should only change atime.
  char buf[20];
  const absl::Time before = absl::Now() - absl::Seconds(1);
  int read_result;
  ASSERT_THAT(read_result = read(fd.get(), buf, sizeof(buf)),
              SyscallSucceeds());
  const absl::Time after = absl::Now() + absl::Seconds(1);

  EXPECT_EQ(std::string(buf, read_result), contents);

  absl::Time atime2, mtime2, ctime2;
  std::tie(atime2, mtime2, ctime2) = GetTime(file);

  EXPECT_LE(before, atime2);
  EXPECT_GE(after, atime2);
  EXPECT_GT(atime2, atime);
  EXPECT_EQ(mtime2, mtime);
  EXPECT_EQ(ctime2, ctime);
}

TEST_F(StatTimesTest, DirAtimeChanges) {
  const auto dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const auto file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  MaybeSave();  // FIXME: ctime is inconsistent.

  absl::Time atime, mtime, ctime;
  std::tie(atime, mtime, ctime) = GetTime(dir);

  absl::SleepFor(absl::Seconds(1));

  const absl::Time before = absl::Now() - absl::Seconds(1);

  // NOTE: Keep an fd open. This ensures that the inode backing the
  // directory won't be destroyed before the final GetTime to avoid writing out
  // timestamps and causing side effects.
  const auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir.path(), O_RDONLY, 0));

  // Listing the directory contents should only change atime.
  auto contents = ASSERT_NO_ERRNO_AND_VALUE(ListDir(dir.path(), false));
  EXPECT_THAT(contents, Not(IsEmpty()));

  const absl::Time after = absl::Now() + absl::Seconds(1);

  absl::Time atime2, mtime2, ctime2;
  std::tie(atime2, mtime2, ctime2) = GetTime(dir);

  EXPECT_LE(before, atime2);
  EXPECT_GE(after, atime2);
  EXPECT_GT(atime2, atime);
  EXPECT_EQ(mtime2, mtime);
  EXPECT_EQ(ctime2, ctime);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
