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

#include "test/util/proc_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/test_util.h"

using ::testing::ElementsAreArray;
using ::testing::IsEmpty;
using ::testing::Optional;

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

TEST(ParseProcSmapsTest, Correctness) {
  auto entries = ASSERT_NO_ERRNO_AND_VALUE(
      ParseProcSmaps("0-10000 rw-s 00000000 00:00 0 "
                     "                   /dev/zero (deleted)\n"
                     "Size:                  0 kB\n"
                     "Rss:                   1 kB\n"
                     "Pss:                   2 kB\n"
                     "Shared_Clean:          3 kB\n"
                     "Shared_Dirty:          4 kB\n"
                     "Private_Clean:         5 kB\n"
                     "Private_Dirty:         6 kB\n"
                     "Referenced:            7 kB\n"
                     "Anonymous:             8 kB\n"
                     "AnonHugePages:         9 kB\n"
                     "Shared_Hugetlb:       10 kB\n"
                     "Private_Hugetlb:      11 kB\n"
                     "Swap:                 12 kB\n"
                     "SwapPss:              13 kB\n"
                     "KernelPageSize:       14 kB\n"
                     "MMUPageSize:          15 kB\n"
                     "Locked:               16 kB\n"
                     "FutureUnknownKey:     17 kB\n"
                     "VmFlags: rd wr sh mr mw me ms lo ?? sd \n"));
  ASSERT_EQ(entries.size(), 1);
  auto& entry = entries[0];
  EXPECT_EQ(entry.maps_entry.filename, "/dev/zero (deleted)");
  EXPECT_EQ(entry.size_kb, 0);
  EXPECT_EQ(entry.rss_kb, 1);
  EXPECT_THAT(entry.pss_kb, Optional(2));
  EXPECT_EQ(entry.shared_clean_kb, 3);
  EXPECT_EQ(entry.shared_dirty_kb, 4);
  EXPECT_EQ(entry.private_clean_kb, 5);
  EXPECT_EQ(entry.private_dirty_kb, 6);
  EXPECT_THAT(entry.referenced_kb, Optional(7));
  EXPECT_THAT(entry.anonymous_kb, Optional(8));
  EXPECT_THAT(entry.anon_huge_pages_kb, Optional(9));
  EXPECT_THAT(entry.shared_hugetlb_kb, Optional(10));
  EXPECT_THAT(entry.private_hugetlb_kb, Optional(11));
  EXPECT_THAT(entry.swap_kb, Optional(12));
  EXPECT_THAT(entry.swap_pss_kb, Optional(13));
  EXPECT_THAT(entry.kernel_page_size_kb, Optional(14));
  EXPECT_THAT(entry.mmu_page_size_kb, Optional(15));
  EXPECT_THAT(entry.locked_kb, Optional(16));
  EXPECT_THAT(entry.vm_flags,
              Optional(ElementsAreArray({"rd", "wr", "sh", "mr", "mw", "me",
                                         "ms", "lo", "??", "sd"})));
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
