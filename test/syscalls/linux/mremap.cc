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
#include <string.h>
#include <sys/mman.h>

#include <string>

#include "gmock/gmock.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::_;

namespace gvisor {
namespace testing {

namespace {

// Wrapper for mremap that returns a PosixErrorOr<>, since the return type of
// void* isn't directly compatible with SyscallSucceeds.
PosixErrorOr<void*> Mremap(void* old_address, size_t old_size, size_t new_size,
                           int flags, void* new_address) {
  void* rv = mremap(old_address, old_size, new_size, flags, new_address);
  if (rv == MAP_FAILED) {
    return PosixError(errno, "mremap failed");
  }
  return rv;
}

// Fixture for mremap tests parameterized by mmap flags.
using MremapParamTest = ::testing::TestWithParam<int>;

TEST_P(MremapParamTest, Noop) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));

  ASSERT_THAT(Mremap(m.ptr(), kPageSize, kPageSize, 0, nullptr),
              IsPosixErrorOkAndHolds(m.ptr()));
  EXPECT_TRUE(IsMapped(m.addr()));
}

TEST_P(MremapParamTest, InPlace_ShrinkingWholeVMA) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // N.B. we must be in a single-threaded subprocess to ensure a
    // background thread doesn't concurrently map the second page.
    void* addr = mremap(m.ptr(), 2 * kPageSize, kPageSize, 0, nullptr);
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == m.ptr());
    MaybeSave();

    TEST_CHECK(IsMapped(m.addr()));
    TEST_CHECK(!IsMapped(m.addr() + kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, InPlace_ShrinkingPartialVMA) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(3 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    void* addr = mremap(m.ptr(), 2 * kPageSize, kPageSize, 0, nullptr);
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == m.ptr());
    MaybeSave();

    TEST_CHECK(IsMapped(m.addr()));
    TEST_CHECK(!IsMapped(m.addr() + kPageSize));
    TEST_CHECK(IsMapped(m.addr() + 2 * kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, InPlace_ShrinkingAcrossVMAs) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(3 * kPageSize, PROT_READ, GetParam()));
  // Changing permissions on the first page forces it to become a separate vma.
  ASSERT_THAT(mprotect(m.ptr(), kPageSize, PROT_NONE), SyscallSucceeds());

  const auto rest = [&] {
    // Both old_size and new_size now span two vmas; mremap
    // shouldn't care.
    void* addr = mremap(m.ptr(), 3 * kPageSize, 2 * kPageSize, 0, nullptr);
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == m.ptr());
    MaybeSave();

    TEST_CHECK(IsMapped(m.addr()));
    TEST_CHECK(IsMapped(m.addr() + kPageSize));
    TEST_CHECK(!IsMapped(m.addr() + 2 * kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, InPlace_ExpansionSuccess) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap the second page so that the first can be expanded back into it.
    //
    // N.B. we must be in a single-threaded subprocess to ensure a
    // background thread doesn't concurrently map this page.
    TEST_PCHECK(
        munmap(reinterpret_cast<void*>(m.addr() + kPageSize), kPageSize) == 0);
    MaybeSave();

    void* addr = mremap(m.ptr(), kPageSize, 2 * kPageSize, 0, nullptr);
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == m.ptr());
    MaybeSave();

    TEST_CHECK(IsMapped(m.addr()));
    TEST_CHECK(IsMapped(m.addr() + kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, InPlace_ExpansionFailure) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(3 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap the second page, leaving a one-page hole. Trying to expand the
    // first page to three pages should fail since the original third page
    // is still mapped.
    TEST_PCHECK(
        munmap(reinterpret_cast<void*>(m.addr() + kPageSize), kPageSize) == 0);
    MaybeSave();

    void* addr = mremap(m.ptr(), kPageSize, 3 * kPageSize, 0, nullptr);
    TEST_CHECK_MSG(addr == MAP_FAILED, "mremap unexpectedly succeeded");
    TEST_PCHECK_MSG(errno == ENOMEM, "mremap failed with wrong errno");
    MaybeSave();

    TEST_CHECK(IsMapped(m.addr()));
    TEST_CHECK(!IsMapped(m.addr() + kPageSize));
    TEST_CHECK(IsMapped(m.addr() + 2 * kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, MayMove_Expansion) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(3 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap the second page, leaving a one-page hole. Trying to expand the
    // first page to three pages with MREMAP_MAYMOVE should force the
    // mapping to be relocated since the original third page is still
    // mapped.
    TEST_PCHECK(
        munmap(reinterpret_cast<void*>(m.addr() + kPageSize), kPageSize) == 0);
    MaybeSave();

    void* addr2 =
        mremap(m.ptr(), kPageSize, 3 * kPageSize, MREMAP_MAYMOVE, nullptr);
    TEST_PCHECK_MSG(addr2 != MAP_FAILED, "mremap failed");
    MaybeSave();

    const Mapping m2 = Mapping(addr2, 3 * kPageSize);
    TEST_CHECK(m.addr() != m2.addr());

    TEST_CHECK(!IsMapped(m.addr()));
    TEST_CHECK(!IsMapped(m.addr() + kPageSize));
    TEST_CHECK(IsMapped(m.addr() + 2 * kPageSize));
    TEST_CHECK(IsMapped(m2.addr()));
    TEST_CHECK(IsMapped(m2.addr() + kPageSize));
    TEST_CHECK(IsMapped(m2.addr() + 2 * kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, Fixed_SourceAndDestinationCannotOverlap) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));

  ASSERT_THAT(Mremap(m.ptr(), kPageSize, kPageSize,
                     MREMAP_MAYMOVE | MREMAP_FIXED, m.ptr()),
              PosixErrorIs(EINVAL, _));
  EXPECT_TRUE(IsMapped(m.addr()));
}

TEST_P(MremapParamTest, Fixed_SameSize) {
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap dst to create a hole.
    TEST_PCHECK(munmap(dst.ptr(), kPageSize) == 0);
    MaybeSave();

    void* addr = mremap(src.ptr(), kPageSize, kPageSize,
                        MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr());
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == dst.ptr());
    MaybeSave();

    TEST_CHECK(!IsMapped(src.addr()));
    TEST_CHECK(IsMapped(dst.addr()));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, Fixed_SameSize_Unmapping) {
  // Like the Fixed_SameSize case, but expect mremap to unmap the destination
  // automatically.
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    void* addr = mremap(src.ptr(), kPageSize, kPageSize,
                        MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr());
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == dst.ptr());
    MaybeSave();

    TEST_CHECK(!IsMapped(src.addr()));
    TEST_CHECK(IsMapped(dst.addr()));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, Fixed_ShrinkingWholeVMA) {
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap dst so we can check that mremap does not keep the
    // second page.
    TEST_PCHECK(munmap(dst.ptr(), 2 * kPageSize) == 0);
    MaybeSave();

    void* addr = mremap(src.ptr(), 2 * kPageSize, kPageSize,
                        MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr());
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == dst.ptr());
    MaybeSave();

    TEST_CHECK(!IsMapped(src.addr()));
    TEST_CHECK(!IsMapped(src.addr() + kPageSize));
    TEST_CHECK(IsMapped(dst.addr()));
    TEST_CHECK(!IsMapped(dst.addr() + kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, Fixed_ShrinkingPartialVMA) {
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(3 * kPageSize, PROT_NONE, GetParam()));
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap dst so we can check that mremap does not keep the
    // second page.
    TEST_PCHECK(munmap(dst.ptr(), 2 * kPageSize) == 0);
    MaybeSave();

    void* addr = mremap(src.ptr(), 2 * kPageSize, kPageSize,
                        MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr());
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == dst.ptr());
    MaybeSave();

    TEST_CHECK(!IsMapped(src.addr()));
    TEST_CHECK(!IsMapped(src.addr() + kPageSize));
    TEST_CHECK(IsMapped(src.addr() + 2 * kPageSize));
    TEST_CHECK(IsMapped(dst.addr()));
    TEST_CHECK(!IsMapped(dst.addr() + kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, Fixed_ShrinkingAcrossVMAs) {
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(3 * kPageSize, PROT_READ, GetParam()));
  // Changing permissions on the first page forces it to become a separate vma.
  ASSERT_THAT(mprotect(src.ptr(), kPageSize, PROT_NONE), SyscallSucceeds());
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unlike flags=0, MREMAP_FIXED requires that [old_address,
    // old_address+new_size) only spans a single vma.
    void* addr = mremap(src.ptr(), 3 * kPageSize, 2 * kPageSize,
                        MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr());
    TEST_CHECK_MSG(addr == MAP_FAILED, "mremap unexpectedly succeeded");
    TEST_PCHECK_MSG(errno == EFAULT, "mremap failed with wrong errno");
    MaybeSave();

    TEST_CHECK(IsMapped(src.addr()));
    TEST_CHECK(IsMapped(src.addr() + kPageSize));
    // Despite failing, mremap should have unmapped [old_address+new_size,
    // old_address+old_size) (i.e. the third page).
    TEST_CHECK(!IsMapped(src.addr() + 2 * kPageSize));
    // Despite failing, mremap should have unmapped the destination pages.
    TEST_CHECK(!IsMapped(dst.addr()));
    TEST_CHECK(!IsMapped(dst.addr() + kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST_P(MremapParamTest, Fixed_Expansion) {
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, GetParam()));
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(2 * kPageSize, PROT_NONE, GetParam()));

  const auto rest = [&] {
    // Unmap dst so we can check that mremap actually maps all pages
    // at the destination.
    TEST_PCHECK(munmap(dst.ptr(), 2 * kPageSize) == 0);
    MaybeSave();

    void* addr = mremap(src.ptr(), kPageSize, 2 * kPageSize,
                        MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr());
    TEST_PCHECK_MSG(addr != MAP_FAILED, "mremap failed");
    TEST_CHECK(addr == dst.ptr());
    MaybeSave();

    TEST_CHECK(!IsMapped(src.addr()));
    TEST_CHECK(IsMapped(dst.addr()));
    TEST_CHECK(IsMapped(dst.addr() + kPageSize));
  };

  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(PrivateShared, MremapParamTest,
                         ::testing::Values(MAP_PRIVATE, MAP_SHARED));

// mremap with old_size == 0 only works with MAP_SHARED after Linux 4.14
// (dba58d3b8c50 "mm/mremap: fail map duplication attempts for private
// mappings").

TEST(MremapTest, InPlace_Copy) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_SHARED));
  EXPECT_THAT(Mremap(m.ptr(), 0, kPageSize, 0, nullptr),
              PosixErrorIs(ENOMEM, _));
}

TEST(MremapTest, MayMove_Copy) {
  Mapping const m =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_SHARED));

  // Remainder of this test executes in a subprocess to ensure that if mremap
  // incorrectly removes m, it is not remapped by another thread.
  const auto rest = [&] {
    void* ptr = mremap(m.ptr(), 0, kPageSize, MREMAP_MAYMOVE, nullptr);
    MaybeSave();
    TEST_PCHECK_MSG(ptr != MAP_FAILED, "mremap failed");
    TEST_CHECK(ptr != m.ptr());
    TEST_CHECK(IsMapped(m.addr()));
    TEST_CHECK(IsMapped(reinterpret_cast<uintptr_t>(ptr)));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

TEST(MremapTest, MustMove_Copy) {
  Mapping const src =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_SHARED));
  Mapping const dst =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));

  // Remainder of this test executes in a subprocess to ensure that if mremap
  // incorrectly removes src, it is not remapped by another thread.
  const auto rest = [&] {
    void* ptr = mremap(src.ptr(), 0, kPageSize, MREMAP_MAYMOVE | MREMAP_FIXED,
                       dst.ptr());
    MaybeSave();
    TEST_PCHECK_MSG(ptr != MAP_FAILED, "mremap failed");
    TEST_CHECK(ptr == dst.ptr());
    TEST_CHECK(IsMapped(src.addr()));
    TEST_CHECK(IsMapped(dst.addr()));
  };
  EXPECT_THAT(InForkedProcess(rest), IsPosixErrorOkAndHolds(0));
}

void ExpectAllBytesAre(absl::string_view v, char c) {
  for (size_t i = 0; i < v.size(); i++) {
    ASSERT_EQ(v[i], c) << "at offset " << i;
  }
}

TEST(MremapTest, ExpansionPreservesCOWPagesAndExposesNewFilePages) {
  // Create a file with 3 pages. The first is filled with 'a', the second is
  // filled with 'b', and the third is filled with 'c'.
  TempPath const file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));
  ASSERT_THAT(WriteFd(fd.get(), std::string(kPageSize, 'a').c_str(), kPageSize),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(WriteFd(fd.get(), std::string(kPageSize, 'b').c_str(), kPageSize),
              SyscallSucceedsWithValue(kPageSize));
  ASSERT_THAT(WriteFd(fd.get(), std::string(kPageSize, 'c').c_str(), kPageSize),
              SyscallSucceedsWithValue(kPageSize));

  // Create a private mapping of the first 2 pages, and fill the second page
  // with 'd'.
  Mapping const src = ASSERT_NO_ERRNO_AND_VALUE(Mmap(nullptr, 2 * kPageSize,
                                                     PROT_READ | PROT_WRITE,
                                                     MAP_PRIVATE, fd.get(), 0));
  memset(reinterpret_cast<void*>(src.addr() + kPageSize), 'd', kPageSize);
  MaybeSave();

  // Move the mapping while expanding it to 3 pages. The resulting mapping
  // should contain the original first page of the file (filled with 'a'),
  // followed by the private copy of the second page (filled with 'd'), followed
  // by the newly-mapped third page of the file (filled with 'c').
  Mapping const dst = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(3 * kPageSize, PROT_NONE, MAP_PRIVATE));
  ASSERT_THAT(Mremap(src.ptr(), 2 * kPageSize, 3 * kPageSize,
                     MREMAP_MAYMOVE | MREMAP_FIXED, dst.ptr()),
              IsPosixErrorOkAndHolds(dst.ptr()));
  auto const v = dst.view();
  ExpectAllBytesAre(v.substr(0, kPageSize), 'a');
  ExpectAllBytesAre(v.substr(kPageSize, kPageSize), 'd');
  ExpectAllBytesAre(v.substr(2 * kPageSize, kPageSize), 'c');
}

TEST(MremapDeathTest, SharedAnon) {
  SetupGvisorDeathTest();

  // Reserve 4 pages of address space.
  Mapping const reserved = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(4 * kPageSize, PROT_NONE, MAP_PRIVATE));

  // Create a 2-page shared anonymous mapping at the beginning of the
  // reservation. Fill the first page with 'a' and the second with 'b'.
  Mapping const m = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(reserved.ptr(), 2 * kPageSize, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
  memset(m.ptr(), 'a', kPageSize);
  memset(reinterpret_cast<void*>(m.addr() + kPageSize), 'b', kPageSize);
  MaybeSave();

  // Shrink the mapping to 1 page in-place.
  ASSERT_THAT(Mremap(m.ptr(), 2 * kPageSize, kPageSize, 0, m.ptr()),
              IsPosixErrorOkAndHolds(m.ptr()));

  // Expand the mapping to 3 pages, moving it forward by 1 page in the process
  // since the old and new mappings can't overlap.
  void* const new_m = reinterpret_cast<void*>(m.addr() + kPageSize);
  ASSERT_THAT(Mremap(m.ptr(), kPageSize, 3 * kPageSize,
                     MREMAP_MAYMOVE | MREMAP_FIXED, new_m),
              IsPosixErrorOkAndHolds(new_m));

  // The first 2 pages of the mapping should still contain the data we wrote
  // (i.e. shrinking should not have discarded the second page's data), while
  // touching the third page should raise SIGBUS.
  auto const v =
      absl::string_view(static_cast<char const*>(new_m), 3 * kPageSize);
  ExpectAllBytesAre(v.substr(0, kPageSize), 'a');
  ExpectAllBytesAre(v.substr(kPageSize, kPageSize), 'b');
  EXPECT_EXIT(ExpectAllBytesAre(v.substr(2 * kPageSize, kPageSize), '\0'),
              ::testing::KilledBySignal(SIGBUS), "");
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
