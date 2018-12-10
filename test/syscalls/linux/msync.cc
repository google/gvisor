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

#include <sys/mman.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "test/util/file_descriptor.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Parameters for msync tests. Use a std::tuple so we can use
// ::testing::Combine.
using MsyncTestParam =
    std::tuple<int,                                    // msync flags
               std::function<PosixErrorOr<Mapping>()>  // returns mapping to
                                                       // msync
               >;

class MsyncParameterizedTest : public ::testing::TestWithParam<MsyncTestParam> {
 protected:
  int msync_flags() const { return std::get<0>(GetParam()); }

  PosixErrorOr<Mapping> GetMapping() const {
    auto rv = std::get<1>(GetParam())();
    return rv;
  }
};

// All valid msync(2) flag combinations (not including MS_INVALIDATE, which
// gVisor doesn't implement).
constexpr std::initializer_list<int> kMsyncFlags = {MS_SYNC, MS_ASYNC, 0};

// Returns functions that return mappings that should be successfully
// msync()able.
std::vector<std::function<PosixErrorOr<Mapping>()>> SyncableMappings() {
  std::vector<std::function<PosixErrorOr<Mapping>()>> funcs;
  for (bool const writable : {false, true}) {
    for (int const mflags : {MAP_PRIVATE, MAP_SHARED}) {
      int const prot = PROT_READ | (writable ? PROT_WRITE : 0);
      int const oflags = O_CREAT | (writable ? O_RDWR : O_RDONLY);
      funcs.push_back([=] {
        return MmapAnon(kPageSize, prot, mflags);
      });
      funcs.push_back([=]() -> PosixErrorOr<Mapping> {
        std::string const path = NewTempAbsPath();
        ASSIGN_OR_RETURN_ERRNO(auto fd, Open(path, oflags, 0644));
        // Don't unlink the file since that breaks save/restore. Just let the
        // test infrastructure clean up all of our temporary files when we're
        // done.
        return Mmap(nullptr, kPageSize, prot, mflags, fd.get(), 0);
      });
    }
  }
  return funcs;
}

PosixErrorOr<Mapping> NoMappings() {
  return PosixError(EINVAL, "unexpected attempt to create a mapping");
}

// "Fixture" for msync tests that hold for all valid flags, but do not create
// mappings.
using MsyncNoMappingTest = MsyncParameterizedTest;

TEST_P(MsyncNoMappingTest, UnmappedAddressWithZeroLengthSucceeds) {
  EXPECT_THAT(msync(nullptr, 0, msync_flags()), SyscallSucceeds());
}

TEST_P(MsyncNoMappingTest, UnmappedAddressWithNonzeroLengthFails) {
  EXPECT_THAT(msync(nullptr, kPageSize, msync_flags()),
              SyscallFailsWithErrno(ENOMEM));
}

INSTANTIATE_TEST_CASE_P(All, MsyncNoMappingTest,
                        ::testing::Combine(::testing::ValuesIn(kMsyncFlags),
                                           ::testing::Values(NoMappings)));

// "Fixture" for msync tests that are not parameterized by msync flags, but do
// create mappings.
using MsyncNoFlagsTest = MsyncParameterizedTest;

TEST_P(MsyncNoFlagsTest, BothSyncAndAsyncFails) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(GetMapping());
  EXPECT_THAT(msync(m.ptr(), m.len(), MS_SYNC | MS_ASYNC),
              SyscallFailsWithErrno(EINVAL));
}

INSTANTIATE_TEST_CASE_P(
    All, MsyncNoFlagsTest,
    ::testing::Combine(::testing::Values(0),  // ignored
                       ::testing::ValuesIn(SyncableMappings())));

// "Fixture" for msync tests parameterized by both msync flags and sources of
// mappings.
using MsyncFullParamTest = MsyncParameterizedTest;

TEST_P(MsyncFullParamTest, NormallySucceeds) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(GetMapping());
  EXPECT_THAT(msync(m.ptr(), m.len(), msync_flags()), SyscallSucceeds());
}

TEST_P(MsyncFullParamTest, UnalignedLengthSucceeds) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(GetMapping());
  EXPECT_THAT(msync(m.ptr(), m.len() - 1, msync_flags()), SyscallSucceeds());
}

TEST_P(MsyncFullParamTest, UnalignedAddressFails) {
  auto m = ASSERT_NO_ERRNO_AND_VALUE(GetMapping());
  EXPECT_THAT(
      msync(reinterpret_cast<void*>(m.addr() + 1), m.len() - 1, msync_flags()),
      SyscallFailsWithErrno(EINVAL));
}

INSTANTIATE_TEST_CASE_P(
    All, MsyncFullParamTest,
    ::testing::Combine(::testing::ValuesIn(kMsyncFlags),
                       ::testing::ValuesIn(SyncableMappings())));

}  // namespace

}  // namespace testing
}  // namespace gvisor
