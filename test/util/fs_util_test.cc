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
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(FsUtilTest, RecursivelyCreateDirManualDelete) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string base_path = JoinPath(root.path(), "/a/b/c/d/e/f/g/h/i/j/k/l/m");

  ASSERT_THAT(Exists(base_path), IsPosixErrorOkAndHolds(false));
  ASSERT_NO_ERRNO(RecursivelyCreateDir(base_path));

  // Delete everything until we hit root and then stop, we want to try this
  // without using RecursivelyDelete.
  std::string cur_path = base_path;
  while (cur_path != root.path()) {
    ASSERT_THAT(Exists(cur_path), IsPosixErrorOkAndHolds(true));
    ASSERT_NO_ERRNO(Rmdir(cur_path));
    ASSERT_THAT(Exists(cur_path), IsPosixErrorOkAndHolds(false));
    auto dir = Dirname(cur_path);
    cur_path = std::string(dir);
  }
}

TEST(FsUtilTest, RecursivelyCreateAndDeleteDir) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string base_path = JoinPath(root.path(), "/a/b/c/d/e/f/g/h/i/j/k/l/m");

  ASSERT_THAT(Exists(base_path), IsPosixErrorOkAndHolds(false));
  ASSERT_NO_ERRNO(RecursivelyCreateDir(base_path));

  const std::string sub_path = JoinPath(root.path(), "a");
  ASSERT_NO_ERRNO(RecursivelyDelete(sub_path, nullptr, nullptr));
  ASSERT_THAT(Exists(sub_path), IsPosixErrorOkAndHolds(false));
}

TEST(FsUtilTest, RecursivelyCreateAndDeletePartial) {
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string base_path = JoinPath(root.path(), "/a/b/c/d/e/f/g/h/i/j/k/l/m");

  ASSERT_THAT(Exists(base_path), IsPosixErrorOkAndHolds(false));
  ASSERT_NO_ERRNO(RecursivelyCreateDir(base_path));

  const std::string a = JoinPath(root.path(), "a");
  auto listing = ASSERT_NO_ERRNO_AND_VALUE(ListDir(a, true));
  ASSERT_THAT(listing, ::testing::Contains("b"));
  ASSERT_EQ(listing.size(), 1);

  listing = ASSERT_NO_ERRNO_AND_VALUE(ListDir(a, false));
  ASSERT_THAT(listing, ::testing::Contains("."));
  ASSERT_THAT(listing, ::testing::Contains(".."));
  ASSERT_THAT(listing, ::testing::Contains("b"));
  ASSERT_EQ(listing.size(), 3);

  const std::string sub_path = JoinPath(root.path(), "/a/b/c/d/e/f");

  ASSERT_NO_ERRNO(
      CreateWithContents(JoinPath(Dirname(sub_path), "file"), "Hello World"));
  std::string contents = "";
  ASSERT_NO_ERRNO(GetContents(JoinPath(Dirname(sub_path), "file"), &contents));
  ASSERT_EQ(contents, "Hello World");

  ASSERT_NO_ERRNO(RecursivelyDelete(sub_path, nullptr, nullptr));
  ASSERT_THAT(Exists(sub_path), IsPosixErrorOkAndHolds(false));

  // The parent of the subpath (directory e) should still exist.
  ASSERT_THAT(Exists(Dirname(sub_path)), IsPosixErrorOkAndHolds(true));

  // The file we created along side f should also still exist.
  ASSERT_THAT(Exists(JoinPath(Dirname(sub_path), "file")),
              IsPosixErrorOkAndHolds(true));
}
}  // namespace

}  // namespace testing
}  // namespace gvisor
