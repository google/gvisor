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

#include "test/util/proc_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"

using ::testing::IsEmpty;

namespace gvisor {
namespace testing {

namespace {

TEST(ParseProcMapsLineTest, WithoutFilename) {
  auto entry = ASSERT_NO_ERRNO_AND_VALUE(
      ParseProcMapsLine("2ab4f00b7000-2ab4f00b9000 r-xp 00000000 00:00 0 "));
  EXPECT_EQ(entry.start, 0x2ab4f00b7000);
  EXPECT_EQ(entry.end, 0x2ab4f00b9000);
  EXPECT_TRUE(entry.readable);
  EXPECT_FALSE(entry.writable);
  EXPECT_TRUE(entry.executable);
  EXPECT_TRUE(entry.priv);
  EXPECT_EQ(entry.offset, 0);
  EXPECT_EQ(entry.major, 0);
  EXPECT_EQ(entry.minor, 0);
  EXPECT_EQ(entry.inode, 0);
  EXPECT_THAT(entry.filename, IsEmpty());
}

TEST(ParseProcMapsLineTest, WithFilename) {
  auto entry = ASSERT_NO_ERRNO_AND_VALUE(
      ParseProcMapsLine("00407000-00408000 rw-p 00006000 00:0e 10              "
                        "                   /bin/cat"));
  EXPECT_EQ(entry.start, 0x407000);
  EXPECT_EQ(entry.end, 0x408000);
  EXPECT_TRUE(entry.readable);
  EXPECT_TRUE(entry.writable);
  EXPECT_FALSE(entry.executable);
  EXPECT_TRUE(entry.priv);
  EXPECT_EQ(entry.offset, 0x6000);
  EXPECT_EQ(entry.major, 0);
  EXPECT_EQ(entry.minor, 0x0e);
  EXPECT_EQ(entry.inode, 10);
  EXPECT_EQ(entry.filename, "/bin/cat");
}

TEST(ParseProcMapsLineTest, WithFilenameContainingSpaces) {
  auto entry = ASSERT_NO_ERRNO_AND_VALUE(
      ParseProcMapsLine("7f26b3b12000-7f26b3b13000 rw-s 00000000 00:05 1432484 "
                        "                   /dev/zero (deleted)"));
  EXPECT_EQ(entry.start, 0x7f26b3b12000);
  EXPECT_EQ(entry.end, 0x7f26b3b13000);
  EXPECT_TRUE(entry.readable);
  EXPECT_TRUE(entry.writable);
  EXPECT_FALSE(entry.executable);
  EXPECT_FALSE(entry.priv);
  EXPECT_EQ(entry.offset, 0);
  EXPECT_EQ(entry.major, 0);
  EXPECT_EQ(entry.minor, 0x05);
  EXPECT_EQ(entry.inode, 1432484);
  EXPECT_EQ(entry.filename, "/dev/zero (deleted)");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
