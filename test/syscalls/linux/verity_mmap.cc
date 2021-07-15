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

#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/memory_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/verity_util.h"

namespace gvisor {
namespace testing {

namespace {

class MmapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Verity is implemented in VFS2.
    SKIP_IF(IsRunningWithVFS1());

    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
    // Mount a tmpfs file system, to be wrapped by a verity fs.
    tmpfs_dir_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    ASSERT_THAT(mount("", tmpfs_dir_.path().c_str(), "tmpfs", 0, ""),
                SyscallSucceeds());

    // Create a new file in the tmpfs mount.
    file_ = ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateFileWith(tmpfs_dir_.path(), kContents, 0777));
    filename_ = Basename(file_.path());
  }

  TempPath tmpfs_dir_;
  TempPath file_;
  std::string filename_;
};

TEST_F(MmapTest, MmapRead) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Make sure the file can be open and mmapped in the mounted verity fs.
  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));

  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(Mmap(nullptr, sizeof(kContents) - 1, PROT_READ,
                                     MAP_SHARED, verity_fd.get(), 0));
  EXPECT_THAT(std::string(m.view()), ::testing::StrEq(kContents));
}

TEST_F(MmapTest, ModifiedBeforeMmap) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Modify the file and check verification failure upon mmapping.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(tmpfs_dir_.path(), filename_), O_RDWR, 0777));
  ASSERT_NO_ERRNO(FlipRandomBit(fd.get(), sizeof(kContents) - 1));

  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(Mmap(nullptr, sizeof(kContents) - 1, PROT_READ,
                                     MAP_SHARED, verity_fd.get(), 0));

  // Memory fault is expected when Translate fails.
  EXPECT_EXIT(std::string(m.view()), ::testing::KilledBySignal(SIGSEGV), "");
}

TEST_F(MmapTest, ModifiedAfterMmap) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(Mmap(nullptr, sizeof(kContents) - 1, PROT_READ,
                                     MAP_SHARED, verity_fd.get(), 0));

  // Modify the file after mapping and check verification failure upon mmapping.
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(tmpfs_dir_.path(), filename_), O_RDWR, 0777));
  ASSERT_NO_ERRNO(FlipRandomBit(fd.get(), sizeof(kContents) - 1));

  // Memory fault is expected when Translate fails.
  EXPECT_EXIT(std::string(m.view()), ::testing::KilledBySignal(SIGSEGV), "");
}

class MmapParamTest
    : public MmapTest,
      public ::testing::WithParamInterface<std::tuple<int, int>> {
 protected:
  int prot() const { return std::get<0>(GetParam()); }
  int flags() const { return std::get<1>(GetParam()); }
};

INSTANTIATE_TEST_SUITE_P(
    WriteExecNoneSharedPrivate, MmapParamTest,
    ::testing::Combine(::testing::ValuesIn({
                           PROT_WRITE,
                           PROT_EXEC,
                           PROT_NONE,
                       }),
                       ::testing::ValuesIn({MAP_SHARED, MAP_PRIVATE})));

TEST_P(MmapParamTest, Mmap) {
  std::string verity_dir = ASSERT_NO_ERRNO_AND_VALUE(
      MountVerity(tmpfs_dir_.path(), filename_, /*targets=*/{}));

  // Make sure the file can be open and mmapped in the mounted verity fs.
  auto const verity_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(verity_dir, filename_), O_RDONLY, 0777));

  if (prot() == PROT_WRITE && flags() == MAP_SHARED) {
    // Verity file system is read-only.
    EXPECT_THAT(
        reinterpret_cast<intptr_t>(mmap(nullptr, sizeof(kContents) - 1, prot(),
                                        flags(), verity_fd.get(), 0)),
        SyscallFailsWithErrno(EACCES));
  } else {
    Mapping const m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
        nullptr, sizeof(kContents) - 1, prot(), flags(), verity_fd.get(), 0));
    if (prot() == PROT_NONE) {
      // Memory mapped by MAP_NONE cannot be accessed.
      EXPECT_EXIT(std::string(m.view()), ::testing::KilledBySignal(SIGSEGV),
                  "");
    } else {
      EXPECT_THAT(std::string(m.view()), ::testing::StrEq(kContents));
    }
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
