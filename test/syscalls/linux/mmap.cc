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
#include <linux/magic.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

using ::testing::Gt;

namespace gvisor {
namespace testing {

namespace {

PosixErrorOr<int64_t> VirtualMemorySize() {
  ASSIGN_OR_RETURN_ERRNO(auto contents, GetContents("/proc/self/statm"));
  std::vector<std::string> parts = absl::StrSplit(contents, ' ');
  if (parts.empty()) {
    return PosixError(EINVAL, "Unable to parse /proc/self/statm");
  }
  ASSIGN_OR_RETURN_ERRNO(auto pages, Atoi<int64_t>(parts[0]));
  return pages * getpagesize();
}

class MMapTest : public ::testing::Test {
 protected:
  // Unmap mapping, if one was made.
  void TearDown() override {
    if (addr_) {
      EXPECT_THAT(Unmap(), SyscallSucceeds());
    }
  }

  // Remembers mapping, so it can be automatically unmapped.
  uintptr_t Map(uintptr_t addr, size_t length, int prot, int flags, int fd,
                off_t offset) {
    void* ret =
        mmap(reinterpret_cast<void*>(addr), length, prot, flags, fd, offset);

    if (ret != MAP_FAILED) {
      addr_ = ret;
      length_ = length;
    }

    return reinterpret_cast<uintptr_t>(ret);
  }

  // Unmap previous mapping
  int Unmap() {
    if (!addr_) {
      return -1;
    }

    int ret = munmap(addr_, length_);

    addr_ = nullptr;
    length_ = 0;

    return ret;
  }

  // Msync the mapping.
  int Msync() { return msync(addr_, length_, MS_SYNC); }

  // Mlock the mapping.
  int Mlock() { return mlock(addr_, length_); }

  // Munlock the mapping.
  int Munlock() { return munlock(addr_, length_); }

  int Protect(uintptr_t addr, size_t length, int prot) {
    return mprotect(reinterpret_cast<void*>(addr), length, prot);
  }

  void* addr_ = nullptr;
  size_t length_ = 0;
};

// Matches if arg contains the same contents as string str.
MATCHER_P(EqualsMemory, str, "") {
  if (0 == memcmp(arg, str.c_str(), str.size())) {
    return true;
  }

  *result_listener << "Memory did not match. Got:\n"
                   << absl::BytesToHexString(
                          std::string(static_cast<char*>(arg), str.size()))
                   << "Want:\n"
                   << absl::BytesToHexString(str);
  return false;
}

// We can't map pipes, but for different reasons.
TEST_F(MMapTest, MapPipe) {
  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  EXPECT_THAT(Map(0, kPageSize, PROT_READ, MAP_PRIVATE, fds[0], 0),
              SyscallFailsWithErrno(ENODEV));
  EXPECT_THAT(Map(0, kPageSize, PROT_READ, MAP_PRIVATE, fds[1], 0),
              SyscallFailsWithErrno(EACCES));
  ASSERT_THAT(close(fds[0]), SyscallSucceeds());
  ASSERT_THAT(close(fds[1]), SyscallSucceeds());
}

// It's very common to mmap /dev/zero because anonymous mappings aren't part
// of POSIX although they are widely supported. So a zero initialized memory
// region would actually come from a "file backed" /dev/zero mapping.
TEST_F(MMapTest, MapDevZeroShared) {
  // This test will verify that we're able to map a page backed by /dev/zero
  // as MAP_SHARED.
  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));

  // Test that we can create a RW SHARED mapping of /dev/zero.
  ASSERT_THAT(
      Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, dev_zero.get(), 0),
      SyscallSucceeds());
}

TEST_F(MMapTest, MapDevZeroPrivate) {
  // This test will verify that we're able to map a page backed by /dev/zero
  // as MAP_PRIVATE.
  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));

  // Test that we can create a RW SHARED mapping of /dev/zero.
  ASSERT_THAT(
      Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, dev_zero.get(), 0),
      SyscallSucceeds());
}

TEST_F(MMapTest, MapDevZeroNoPersistence) {
  // This test will verify that two independent mappings of /dev/zero do not
  // appear to reference the same "backed file."

  const FileDescriptor dev_zero1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));
  const FileDescriptor dev_zero2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));

  ASSERT_THAT(
      Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, dev_zero1.get(), 0),
      SyscallSucceeds());

  // Create a second mapping via the second /dev/zero fd.
  void* psec_map = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                        dev_zero2.get(), 0);
  ASSERT_THAT(reinterpret_cast<intptr_t>(psec_map), SyscallSucceeds());

  // Always unmap.
  auto cleanup_psec_map = Cleanup(
      [&] { EXPECT_THAT(munmap(psec_map, kPageSize), SyscallSucceeds()); });

  // Verify that we have independently addressed pages.
  ASSERT_NE(psec_map, addr_);

  std::string buf_zero(kPageSize, 0x00);
  std::string buf_ones(kPageSize, 0xFF);

  // Verify the first is actually all zeros after mmap.
  EXPECT_THAT(addr_, EqualsMemory(buf_zero));

  // Let's fill in the first mapping with 0xFF.
  memcpy(addr_, buf_ones.data(), kPageSize);

  // Verify that the memcpy actually stuck in the page.
  EXPECT_THAT(addr_, EqualsMemory(buf_ones));

  // Verify that it didn't affect the second page which should be all zeros.
  EXPECT_THAT(psec_map, EqualsMemory(buf_zero));
}

TEST_F(MMapTest, MapDevZeroSharedMultiplePages) {
  // This will test that we're able to map /dev/zero over multiple pages.
  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));

  // Test that we can create a RW SHARED mapping of /dev/zero.
  ASSERT_THAT(Map(0, kPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                  dev_zero.get(), 0),
              SyscallSucceeds());

  std::string buf_zero(kPageSize * 2, 0x00);
  std::string buf_ones(kPageSize * 2, 0xFF);

  // Verify the two pages are actually all zeros after mmap.
  EXPECT_THAT(addr_, EqualsMemory(buf_zero));

  // Fill out the pages with all ones.
  memcpy(addr_, buf_ones.data(), kPageSize * 2);

  // Verify that the memcpy actually stuck in the pages.
  EXPECT_THAT(addr_, EqualsMemory(buf_ones));
}

TEST_F(MMapTest, MapDevZeroSharedFdNoPersistence) {
  // This test will verify that two independent mappings of /dev/zero do not
  // appear to reference the same "backed file" even when mapped from the
  // same initial fd.
  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));

  ASSERT_THAT(
      Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, dev_zero.get(), 0),
      SyscallSucceeds());

  // Create a second mapping via the same fd.
  void* psec_map = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                        dev_zero.get(), 0);
  ASSERT_THAT(reinterpret_cast<int64_t>(psec_map), SyscallSucceeds());

  // Always unmap.
  auto cleanup_psec_map = Cleanup(
      [&] { ASSERT_THAT(munmap(psec_map, kPageSize), SyscallSucceeds()); });

  // Verify that we have independently addressed pages.
  ASSERT_NE(psec_map, addr_);

  std::string buf_zero(kPageSize, 0x00);
  std::string buf_ones(kPageSize, 0xFF);

  // Verify the first is actually all zeros after mmap.
  EXPECT_THAT(addr_, EqualsMemory(buf_zero));

  // Let's fill in the first mapping with 0xFF.
  memcpy(addr_, buf_ones.data(), kPageSize);

  // Verify that the memcpy actually stuck in the page.
  EXPECT_THAT(addr_, EqualsMemory(buf_ones));

  // Verify that it didn't affect the second page which should be all zeros.
  EXPECT_THAT(psec_map, EqualsMemory(buf_zero));
}

TEST_F(MMapTest, MapDevZeroSegfaultAfterUnmap) {
  SetupGvisorDeathTest();

  // This test will verify that we're able to map a page backed by /dev/zero
  // as MAP_SHARED and after it's unmapped any access results in a SIGSEGV.
  // This test is redundant but given the special nature of /dev/zero mappings
  // it doesn't hurt.
  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));

  const auto rest = [&] {
    // Test that we can create a RW SHARED mapping of /dev/zero.
    TEST_PCHECK(Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                    dev_zero.get(),
                    0) != reinterpret_cast<uintptr_t>(MAP_FAILED));

    // Confirm that accesses after the unmap result in a SIGSEGV.
    //
    // N.B. We depend on this process being single-threaded to ensure there
    // can't be another mmap to map addr before the dereference below.
    void* addr_saved = addr_;  // Unmap resets addr_.
    TEST_PCHECK(Unmap() == 0);
    *reinterpret_cast<volatile int*>(addr_saved) = 0xFF;
  };

  EXPECT_THAT(InForkedProcess(rest),
              IsPosixErrorOkAndHolds(W_EXITCODE(0, SIGSEGV)));
}

TEST_F(MMapTest, MapDevZeroUnaligned) {
  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDWR));
  const size_t size = kPageSize + kPageSize / 2;
  const std::string buf_zero(size, 0x00);

  ASSERT_THAT(
      Map(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_zero.get(), 0),
      SyscallSucceeds());
  EXPECT_THAT(addr_, EqualsMemory(buf_zero));
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  ASSERT_THAT(
      Map(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, dev_zero.get(), 0),
      SyscallSucceeds());
  EXPECT_THAT(addr_, EqualsMemory(buf_zero));
}

// We can't map _some_ character devices.
TEST_F(MMapTest, MapCharDevice) {
  const FileDescriptor cdevfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/random", 0, 0));
  EXPECT_THAT(Map(0, kPageSize, PROT_READ, MAP_PRIVATE, cdevfd.get(), 0),
              SyscallFailsWithErrno(ENODEV));
}

// We can't map directories.
TEST_F(MMapTest, MapDirectory) {
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(GetAbsoluteTestTmpdir(), 0, 0));
  EXPECT_THAT(Map(0, kPageSize, PROT_READ, MAP_PRIVATE, dirfd.get(), 0),
              SyscallFailsWithErrno(ENODEV));
}

// We can map *something*
TEST_F(MMapTest, MapAnything) {
  EXPECT_THAT(Map(0, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceedsWithValue(Gt(0)));
}

// Map length < PageSize allowed
TEST_F(MMapTest, SmallMap) {
  EXPECT_THAT(Map(0, 128, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());
}

// Hint address doesn't break anything.
// Note: there is no requirement we actually get the hint address
TEST_F(MMapTest, HintAddress) {
  EXPECT_THAT(
      Map(0x30000000, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());
}

// MAP_FIXED gives us exactly the requested address
TEST_F(MMapTest, MapFixed) {
  EXPECT_THAT(Map(0x30000000, kPageSize, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0),
              SyscallSucceedsWithValue(0x30000000));
}

// 64-bit addresses work too
#ifdef __x86_64__
TEST_F(MMapTest, MapFixed64) {
  EXPECT_THAT(Map(0x300000000000, kPageSize, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0),
              SyscallSucceedsWithValue(0x300000000000));
}
#endif

// MAP_STACK allowed.
// There isn't a good way to verify it did anything.
TEST_F(MMapTest, MapStack) {
  EXPECT_THAT(Map(0, kPageSize, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0),
              SyscallSucceeds());
}

// MAP_LOCKED allowed.
// There isn't a good way to verify it did anything.
TEST_F(MMapTest, MapLocked) {
  EXPECT_THAT(Map(0, kPageSize, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0),
              SyscallSucceeds());
}

// MAP_PRIVATE or MAP_SHARED must be passed
TEST_F(MMapTest, NotPrivateOrShared) {
  EXPECT_THAT(Map(0, kPageSize, PROT_NONE, MAP_ANONYMOUS, -1, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Only one of MAP_PRIVATE or MAP_SHARED may be passed
TEST_F(MMapTest, PrivateAndShared) {
  EXPECT_THAT(Map(0, kPageSize, PROT_NONE,
                  MAP_PRIVATE | MAP_SHARED | MAP_ANONYMOUS, -1, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(MMapTest, FixedAlignment) {
  // Addr must be page aligned (MAP_FIXED)
  EXPECT_THAT(Map(0x30000001, kPageSize, PROT_NONE,
                  MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Non-MAP_FIXED address does not need to be page aligned
TEST_F(MMapTest, NonFixedAlignment) {
  EXPECT_THAT(
      Map(0x30000001, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());
}

// Length = 0 results in EINVAL.
TEST_F(MMapTest, InvalidLength) {
  EXPECT_THAT(Map(0, 0, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallFailsWithErrno(EINVAL));
}

// Bad fd not allowed.
TEST_F(MMapTest, BadFd) {
  EXPECT_THAT(Map(0, kPageSize, PROT_NONE, MAP_PRIVATE, 999, 0),
              SyscallFailsWithErrno(EBADF));
}

// Mappings are writable.
TEST_F(MMapTest, ProtWrite) {
  uint64_t addr;
  constexpr uint8_t kFirstWord[] = {42, 42, 42, 42};

  EXPECT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());

  // This shouldn't cause a SIGSEGV.
  memset(reinterpret_cast<void*>(addr), 42, kPageSize);

  // The written data should actually be there.
  EXPECT_EQ(
      0, memcmp(reinterpret_cast<void*>(addr), kFirstWord, sizeof(kFirstWord)));
}

// "Write-only" mappings are writable *and* readable.
TEST_F(MMapTest, ProtWriteOnly) {
  uint64_t addr;
  constexpr uint8_t kFirstWord[] = {42, 42, 42, 42};

  EXPECT_THAT(
      addr = Map(0, kPageSize, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());

  // This shouldn't cause a SIGSEGV.
  memset(reinterpret_cast<void*>(addr), 42, kPageSize);

  // The written data should actually be there.
  EXPECT_EQ(
      0, memcmp(reinterpret_cast<void*>(addr), kFirstWord, sizeof(kFirstWord)));
}

// "Write-only" mappings are readable.
//
// This is distinct from above to ensure the page is accessible even if the
// initial fault is a write fault.
TEST_F(MMapTest, ProtWriteOnlyReadable) {
  uint64_t addr;
  constexpr uint64_t kFirstWord = 0;

  EXPECT_THAT(
      addr = Map(0, kPageSize, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());

  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), &kFirstWord,
                      sizeof(kFirstWord)));
}

// Mappings are writable after mprotect from PROT_NONE to PROT_READ|PROT_WRITE.
TEST_F(MMapTest, ProtectProtWrite) {
  uint64_t addr;
  constexpr uint8_t kFirstWord[] = {42, 42, 42, 42};

  EXPECT_THAT(
      addr = Map(0, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());

  ASSERT_THAT(Protect(addr, kPageSize, PROT_READ | PROT_WRITE),
              SyscallSucceeds());

  // This shouldn't cause a SIGSEGV.
  memset(reinterpret_cast<void*>(addr), 42, kPageSize);

  // The written data should actually be there.
  EXPECT_EQ(
      0, memcmp(reinterpret_cast<void*>(addr), kFirstWord, sizeof(kFirstWord)));
}

// SIGSEGV raised when reading PROT_NONE memory
TEST_F(MMapTest, ProtNoneDeath) {
  SetupGvisorDeathTest();

  uintptr_t addr;

  ASSERT_THAT(
      addr = Map(0, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());

  EXPECT_EXIT(*reinterpret_cast<volatile int*>(addr),
              ::testing::KilledBySignal(SIGSEGV), "");
}

// SIGSEGV raised when writing PROT_READ only memory
TEST_F(MMapTest, ReadOnlyDeath) {
  SetupGvisorDeathTest();

  uintptr_t addr;

  ASSERT_THAT(
      addr = Map(0, kPageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceeds());

  EXPECT_EXIT(*reinterpret_cast<volatile int*>(addr) = 42,
              ::testing::KilledBySignal(SIGSEGV), "");
}

// Writable mapping mprotect'd to read-only should not be writable.
TEST_F(MMapTest, MprotectReadOnlyDeath) {
  SetupGvisorDeathTest();

  uintptr_t addr;

  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());

  volatile int* val = reinterpret_cast<int*>(addr);

  // Copy to ensure page is mapped in.
  *val = 42;

  ASSERT_THAT(Protect(addr, kPageSize, PROT_READ), SyscallSucceeds());

  // Now it shouldn't be writable.
  EXPECT_EXIT(*val = 0, ::testing::KilledBySignal(SIGSEGV), "");
}

// Verify that calling mprotect an address that's not page aligned fails.
TEST_F(MMapTest, MprotectNotPageAligned) {
  uintptr_t addr;

  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());
  ASSERT_THAT(Protect(addr + 1, kPageSize - 1, PROT_READ),
              SyscallFailsWithErrno(EINVAL));
}

// Verify that calling mprotect with an absurdly huge length fails.
TEST_F(MMapTest, MprotectHugeLength) {
  uintptr_t addr;

  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());
  ASSERT_THAT(Protect(addr, static_cast<size_t>(-1), PROT_READ),
              SyscallFailsWithErrno(ENOMEM));
}

#if defined(__x86_64__) || defined(__i386__)
// This code is equivalent in 32 and 64-bit mode
const uint8_t machine_code[] = {
    0xb8, 0x2a, 0x00, 0x00, 0x00,  // movl $42, %eax
    0xc3,                          // retq
};

// PROT_EXEC allows code execution
TEST_F(MMapTest, ProtExec) {
  uintptr_t addr;
  uint32_t (*func)(void);

  EXPECT_THAT(addr = Map(0, kPageSize, PROT_EXEC | PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());

  memcpy(reinterpret_cast<void*>(addr), machine_code, sizeof(machine_code));

  func = reinterpret_cast<uint32_t (*)(void)>(addr);

  EXPECT_EQ(42, func());
}

// No PROT_EXEC disallows code execution
TEST_F(MMapTest, NoProtExecDeath) {
  SetupGvisorDeathTest();

  uintptr_t addr;
  uint32_t (*func)(void);

  EXPECT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());

  memcpy(reinterpret_cast<void*>(addr), machine_code, sizeof(machine_code));

  func = reinterpret_cast<uint32_t (*)(void)>(addr);

  EXPECT_EXIT(func(), ::testing::KilledBySignal(SIGSEGV), "");
}
#endif

TEST_F(MMapTest, NoExceedLimitData) {
  void* prevbrk;
  void* target_brk;
  struct rlimit setlim;

  prevbrk = sbrk(0);
  ASSERT_NE(-1, reinterpret_cast<intptr_t>(prevbrk));
  target_brk = reinterpret_cast<char*>(prevbrk) + 1;

  setlim.rlim_cur = RLIM_INFINITY;
  setlim.rlim_max = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_DATA, &setlim), SyscallSucceeds());
  EXPECT_THAT(brk(target_brk), SyscallSucceedsWithValue(0));
}

TEST_F(MMapTest, ExceedLimitData) {
  // To unit test this more precisely, we'd need access to the mm's start_brk
  // and end_brk, which we don't have direct access to :/
  void* prevbrk;
  void* target_brk;
  struct rlimit setlim;

  prevbrk = sbrk(0);
  ASSERT_NE(-1, reinterpret_cast<intptr_t>(prevbrk));
  target_brk = reinterpret_cast<char*>(prevbrk) + 8192;

  setlim.rlim_cur = 0;
  setlim.rlim_max = RLIM_INFINITY;
  // Set RLIMIT_DATA very low so any subsequent brk() calls fail.
  // Reset RLIMIT_DATA during teardown step.
  ASSERT_THAT(setrlimit(RLIMIT_DATA, &setlim), SyscallSucceeds());
  EXPECT_THAT(brk(target_brk), SyscallFailsWithErrno(ENOMEM));
  // Teardown step...
  setlim.rlim_cur = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_DATA, &setlim), SyscallSucceeds());
}

TEST_F(MMapTest, ExceedLimitDataPrlimit) {
  // To unit test this more precisely, we'd need access to the mm's start_brk
  // and end_brk, which we don't have direct access to :/
  void* prevbrk;
  void* target_brk;
  struct rlimit setlim;

  prevbrk = sbrk(0);
  ASSERT_NE(-1, reinterpret_cast<intptr_t>(prevbrk));
  target_brk = reinterpret_cast<char*>(prevbrk) + 8192;

  setlim.rlim_cur = 0;
  setlim.rlim_max = RLIM_INFINITY;
  // Set RLIMIT_DATA very low so any subsequent brk() calls fail.
  // Reset RLIMIT_DATA during teardown step.
  ASSERT_THAT(prlimit(0, RLIMIT_DATA, &setlim, nullptr), SyscallSucceeds());
  EXPECT_THAT(brk(target_brk), SyscallFailsWithErrno(ENOMEM));
  // Teardown step...
  setlim.rlim_cur = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_DATA, &setlim), SyscallSucceeds());
}

TEST_F(MMapTest, ExceedLimitDataPrlimitPID) {
  // To unit test this more precisely, we'd need access to the mm's start_brk
  // and end_brk, which we don't have direct access to :/
  void* prevbrk;
  void* target_brk;
  struct rlimit setlim;

  prevbrk = sbrk(0);
  ASSERT_NE(-1, reinterpret_cast<intptr_t>(prevbrk));
  target_brk = reinterpret_cast<char*>(prevbrk) + 8192;

  setlim.rlim_cur = 0;
  setlim.rlim_max = RLIM_INFINITY;
  // Set RLIMIT_DATA very low so any subsequent brk() calls fail.
  // Reset RLIMIT_DATA during teardown step.
  ASSERT_THAT(prlimit(syscall(__NR_gettid), RLIMIT_DATA, &setlim, nullptr),
              SyscallSucceeds());
  EXPECT_THAT(brk(target_brk), SyscallFailsWithErrno(ENOMEM));
  // Teardown step...
  setlim.rlim_cur = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_DATA, &setlim), SyscallSucceeds());
}

TEST_F(MMapTest, NoExceedLimitAS) {
  constexpr uint64_t kAllocBytes = 200 << 20;
  // Add some headroom to the AS limit in case of e.g. unexpected stack
  // expansion.
  constexpr uint64_t kExtraASBytes = kAllocBytes + (20 << 20);
  static_assert(kAllocBytes < kExtraASBytes,
                "test depends on allocation not exceeding AS limit");

  auto vss = ASSERT_NO_ERRNO_AND_VALUE(VirtualMemorySize());
  struct rlimit setlim;
  setlim.rlim_cur = vss + kExtraASBytes;
  setlim.rlim_max = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_AS, &setlim), SyscallSucceeds());
  EXPECT_THAT(
      Map(0, kAllocBytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallSucceedsWithValue(Gt(0)));
}

TEST_F(MMapTest, ExceedLimitAS) {
  constexpr uint64_t kAllocBytes = 200 << 20;
  // Add some headroom to the AS limit in case of e.g. unexpected stack
  // expansion.
  constexpr uint64_t kExtraASBytes = 20 << 20;
  static_assert(kAllocBytes > kExtraASBytes,
                "test depends on allocation exceeding AS limit");

  auto vss = ASSERT_NO_ERRNO_AND_VALUE(VirtualMemorySize());
  struct rlimit setlim;
  setlim.rlim_cur = vss + kExtraASBytes;
  setlim.rlim_max = RLIM_INFINITY;
  ASSERT_THAT(setrlimit(RLIMIT_AS, &setlim), SyscallSucceeds());
  EXPECT_THAT(
      Map(0, kAllocBytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
      SyscallFailsWithErrno(ENOMEM));
}

// Tests that setting an anonymous mmap to PROT_NONE doesn't free the memory.
TEST_F(MMapTest, SettingProtNoneDoesntFreeMemory) {
  uintptr_t addr;
  constexpr uint8_t kFirstWord[] = {42, 42, 42, 42};

  EXPECT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceedsWithValue(Gt(0)));

  memset(reinterpret_cast<void*>(addr), 42, kPageSize);

  ASSERT_THAT(Protect(addr, kPageSize, PROT_NONE), SyscallSucceeds());
  ASSERT_THAT(Protect(addr, kPageSize, PROT_READ | PROT_WRITE),
              SyscallSucceeds());

  // The written data should still be there.
  EXPECT_EQ(
      0, memcmp(reinterpret_cast<void*>(addr), kFirstWord, sizeof(kFirstWord)));
}

constexpr char kFileContents[] = "Hello World!";

class MMapFileTest : public MMapTest {
 protected:
  FileDescriptor fd_;
  std::string filename_;

  // Open a file for read/write
  void SetUp() override {
    MMapTest::SetUp();

    filename_ = NewTempAbsPath();
    fd_ = ASSERT_NO_ERRNO_AND_VALUE(Open(filename_, O_CREAT | O_RDWR, 0644));

    // Extend file so it can be written once mapped. Deliberately make the file
    // only half a page in size, so we can test what happens when we access the
    // second half.
    // Use ftruncate(2) once the sentry supports it.
    char zero = 0;
    size_t count = 0;
    do {
      const DisableSave ds;  // saving 2048 times is slow and useless.
      Write(&zero, 1), SyscallSucceedsWithValue(1);
    } while (++count < (kPageSize / 2));
    ASSERT_THAT(lseek(fd_.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  }

  // Close and delete file
  void TearDown() override {
    MMapTest::TearDown();
    fd_.reset();  // Make sure the files is closed before we unlink it.
    ASSERT_THAT(unlink(filename_.c_str()), SyscallSucceeds());
  }

  ssize_t Read(char* buf, size_t count) {
    ssize_t len = 0;
    do {
      ssize_t ret = read(fd_.get(), buf, count);
      if (ret < 0) {
        return ret;
      } else if (ret == 0) {
        return len;
      }

      len += ret;
      buf += ret;
    } while (len < static_cast<ssize_t>(count));

    return len;
  }

  ssize_t Write(const char* buf, size_t count) {
    ssize_t len = 0;
    do {
      ssize_t ret = write(fd_.get(), buf, count);
      if (ret < 0) {
        return ret;
      } else if (ret == 0) {
        return len;
      }

      len += ret;
      buf += ret;
    } while (len < static_cast<ssize_t>(count));

    return len;
  }
};

// MAP_POPULATE allowed.
// There isn't a good way to verify it actually did anything.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, MapPopulate) {
  ASSERT_THAT(
      Map(0, kPageSize, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd_.get(), 0),
      SyscallSucceeds());
}

// MAP_POPULATE on a short file.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, MapPopulateShort) {
  ASSERT_THAT(Map(0, 2 * kPageSize, PROT_READ, MAP_PRIVATE | MAP_POPULATE,
                  fd_.get(), 0),
              SyscallSucceeds());
}

// Read contents from mapped file.
TEST_F(MMapFileTest, Read) {
  size_t len = strlen(kFileContents);
  ASSERT_EQ(len, Write(kFileContents, len));

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_PRIVATE, fd_.get(), 0),
              SyscallSucceeds());

  EXPECT_THAT(reinterpret_cast<char*>(addr),
              EqualsMemory(std::string(kFileContents)));
}

// Map at an offset.
TEST_F(MMapFileTest, MapOffset) {
  ASSERT_THAT(lseek(fd_.get(), kPageSize, SEEK_SET), SyscallSucceeds());

  size_t len = strlen(kFileContents);
  ASSERT_EQ(len, Write(kFileContents, len));

  uintptr_t addr;
  ASSERT_THAT(
      addr = Map(0, kPageSize, PROT_READ, MAP_PRIVATE, fd_.get(), kPageSize),
      SyscallSucceeds());

  EXPECT_THAT(reinterpret_cast<char*>(addr),
              EqualsMemory(std::string(kFileContents)));
}

TEST_F(MMapFileTest, MapOffsetBeyondEnd) {
  SetupGvisorDeathTest();

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd_.get(), 10 * kPageSize),
              SyscallSucceeds());

  // Touching the memory causes SIGBUS.
  size_t len = strlen(kFileContents);
  EXPECT_EXIT(std::copy(kFileContents, kFileContents + len,
                        reinterpret_cast<volatile char*>(addr)),
              ::testing::KilledBySignal(SIGBUS), "");
}

// Verify mmap fails when sum of length and offset overflows.
TEST_F(MMapFileTest, MapLengthPlusOffsetOverflows) {
  const size_t length = static_cast<size_t>(-kPageSize);
  const off_t offset = kPageSize;
  ASSERT_THAT(Map(0, length, PROT_READ, MAP_PRIVATE, fd_.get(), offset),
              SyscallFailsWithErrno(ENOMEM));
}

// MAP_PRIVATE PROT_WRITE is allowed on read-only FDs.
TEST_F(MMapFileTest, WritePrivateOnReadOnlyFd) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename_, O_RDONLY));

  uintptr_t addr;
  EXPECT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd.get(), 0),
              SyscallSucceeds());

  // Touch the page to ensure the kernel didn't lie about writability.
  size_t len = strlen(kFileContents);
  std::copy(kFileContents, kFileContents + len,
            reinterpret_cast<volatile char*>(addr));
}

// MAP_PRIVATE PROT_READ is not allowed on write-only FDs.
TEST_F(MMapFileTest, ReadPrivateOnWriteOnlyFd) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename_, O_WRONLY));

  uintptr_t addr;
  EXPECT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_PRIVATE, fd.get(), 0),
              SyscallFailsWithErrno(EACCES));
}

// MAP_SHARED PROT_WRITE not allowed on read-only FDs.
TEST_F(MMapFileTest, WriteSharedOnReadOnlyFd) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename_, O_RDONLY));

  uintptr_t addr;
  EXPECT_THAT(
      addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0),
      SyscallFailsWithErrno(EACCES));
}

// MAP_SHARED PROT_READ not allowed on write-only FDs.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, ReadSharedOnWriteOnlyFd) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename_, O_WRONLY));

  uintptr_t addr;
  EXPECT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_SHARED, fd.get(), 0),
              SyscallFailsWithErrno(EACCES));
}

// MAP_SHARED PROT_WRITE not allowed on write-only FDs.
// The FD must always be readable.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, WriteSharedOnWriteOnlyFd) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(filename_, O_WRONLY));

  uintptr_t addr;
  EXPECT_THAT(addr = Map(0, kPageSize, PROT_WRITE, MAP_SHARED, fd.get(), 0),
              SyscallFailsWithErrno(EACCES));
}

// Overwriting the contents of a file mapped MAP_SHARED PROT_READ
// should cause the new data to be reflected in the mapping.
TEST_F(MMapFileTest, ReadSharedConsistentWithOverwrite) {
  // Start from scratch.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Expand the file to two pages and dirty them.
  std::string bufA(kPageSize, 'a');
  ASSERT_THAT(Write(bufA.c_str(), bufA.size()),
              SyscallSucceedsWithValue(bufA.size()));
  std::string bufB(kPageSize, 'b');
  ASSERT_THAT(Write(bufB.c_str(), bufB.size()),
              SyscallSucceedsWithValue(bufB.size()));

  // Map the page.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // Check that the mapping contains the right file data.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), bufA.c_str(), kPageSize));
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr + kPageSize), bufB.c_str(),
                      kPageSize));

  // Start at the beginning of the file.
  ASSERT_THAT(lseek(fd_.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Swap the write pattern.
  ASSERT_THAT(Write(bufB.c_str(), bufB.size()),
              SyscallSucceedsWithValue(bufB.size()));
  ASSERT_THAT(Write(bufA.c_str(), bufA.size()),
              SyscallSucceedsWithValue(bufA.size()));

  // Check that the mapping got updated.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), bufB.c_str(), kPageSize));
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr + kPageSize), bufA.c_str(),
                      kPageSize));
}

// Partially overwriting a file mapped MAP_SHARED PROT_READ should be reflected
// in the mapping.
TEST_F(MMapFileTest, ReadSharedConsistentWithPartialOverwrite) {
  // Start from scratch.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Expand the file to two pages and dirty them.
  std::string bufA(kPageSize, 'a');
  ASSERT_THAT(Write(bufA.c_str(), bufA.size()),
              SyscallSucceedsWithValue(bufA.size()));
  std::string bufB(kPageSize, 'b');
  ASSERT_THAT(Write(bufB.c_str(), bufB.size()),
              SyscallSucceedsWithValue(bufB.size()));

  // Map the page.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // Check that the mapping contains the right file data.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), bufA.c_str(), kPageSize));
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr + kPageSize), bufB.c_str(),
                      kPageSize));

  // Start at the beginning of the file.
  ASSERT_THAT(lseek(fd_.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Do a partial overwrite, spanning both pages.
  std::string bufC(kPageSize + (kPageSize / 2), 'c');
  ASSERT_THAT(Write(bufC.c_str(), bufC.size()),
              SyscallSucceedsWithValue(bufC.size()));

  // Check that the mapping got updated.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), bufC.c_str(),
                      kPageSize + (kPageSize / 2)));
  EXPECT_EQ(0,
            memcmp(reinterpret_cast<void*>(addr + kPageSize + (kPageSize / 2)),
                   bufB.c_str(), kPageSize / 2));
}

// Overwriting a file mapped MAP_SHARED PROT_READ should be reflected in the
// mapping and the file.
TEST_F(MMapFileTest, ReadSharedConsistentWithWriteAndFile) {
  // Start from scratch.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Expand the file to two full pages and dirty it.
  std::string bufA(2 * kPageSize, 'a');
  ASSERT_THAT(Write(bufA.c_str(), bufA.size()),
              SyscallSucceedsWithValue(bufA.size()));

  // Map only the first page.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // Prepare to overwrite the file contents.
  ASSERT_THAT(lseek(fd_.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Overwrite everything, beyond the mapped portion.
  std::string bufB(2 * kPageSize, 'b');
  ASSERT_THAT(Write(bufB.c_str(), bufB.size()),
              SyscallSucceedsWithValue(bufB.size()));

  // What the mapped portion should now look like.
  std::string bufMapped(kPageSize, 'b');

  // Expect that the mapped portion is consistent.
  EXPECT_EQ(
      0, memcmp(reinterpret_cast<void*>(addr), bufMapped.c_str(), kPageSize));

  // Prepare to read the entire file contents.
  ASSERT_THAT(lseek(fd_.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Expect that the file was fully updated.
  std::vector<char> bufFile(2 * kPageSize);
  ASSERT_THAT(Read(bufFile.data(), bufFile.size()),
              SyscallSucceedsWithValue(bufFile.size()));
  // Cast to void* to avoid EXPECT_THAT assuming bufFile.data() is a
  // NUL-terminated C std::string. EXPECT_THAT will try to print a char* as a C
  // std::string, possibly overruning the buffer.
  EXPECT_THAT(reinterpret_cast<void*>(bufFile.data()), EqualsMemory(bufB));
}

// Write data to mapped file.
TEST_F(MMapFileTest, WriteShared) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  size_t len = strlen(kFileContents);
  memcpy(reinterpret_cast<void*>(addr), kFileContents, len);

  // The file may not actually be updated until munmap is called.
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  std::vector<char> buf(len);
  ASSERT_THAT(Read(buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  // Cast to void* to avoid EXPECT_THAT assuming buf.data() is a
  // NUL-terminated C string. EXPECT_THAT will try to print a char* as a C
  // string, possibly overruning the buffer.
  EXPECT_THAT(reinterpret_cast<void*>(buf.data()),
              EqualsMemory(std::string(kFileContents)));
}

// Write data to portion of mapped page beyond the end of the file.
// These writes are not reflected in the file.
TEST_F(MMapFileTest, WriteSharedBeyondEnd) {
  // The file is only half of a page. We map an entire page. Writes to the
  // end of the mapping must not be reflected in the file.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // First half; this is reflected in the file.
  std::string first(kPageSize / 2, 'A');
  memcpy(reinterpret_cast<void*>(addr), first.c_str(), first.size());

  // Second half; this is not reflected in the file.
  std::string second(kPageSize / 2, 'B');
  memcpy(reinterpret_cast<void*>(addr + kPageSize / 2), second.c_str(),
         second.size());

  // The file may not actually be updated until munmap is called.
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  // Big enough to fit the entire page, if the writes are mistakenly written to
  // the file.
  std::vector<char> buf(kPageSize);

  // Only the first half is in the file.
  ASSERT_THAT(Read(buf.data(), buf.size()),
              SyscallSucceedsWithValue(first.size()));
  // Cast to void* to avoid EXPECT_THAT assuming buf.data() is a
  // NUL-terminated C string. EXPECT_THAT will try to print a char* as a C
  // NUL-terminated C std::string. EXPECT_THAT will try to print a char* as a C
  // std::string, possibly overruning the buffer.
  EXPECT_THAT(reinterpret_cast<void*>(buf.data()), EqualsMemory(first));
}

// The portion of a mapped page that becomes part of the file after a truncate
// is reflected in the file.
TEST_F(MMapFileTest, WriteSharedTruncateUp) {
  // The file is only half of a page. We map an entire page. Writes to the
  // end of the mapping must not be reflected in the file.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // First half; this is reflected in the file.
  std::string first(kPageSize / 2, 'A');
  memcpy(reinterpret_cast<void*>(addr), first.c_str(), first.size());

  // Second half; this is not reflected in the file now (see
  // WriteSharedBeyondEnd), but will be after the truncate.
  std::string second(kPageSize / 2, 'B');
  memcpy(reinterpret_cast<void*>(addr + kPageSize / 2), second.c_str(),
         second.size());

  // Extend the file to a full page. The second half of the page will be
  // reflected in the file.
  EXPECT_THAT(ftruncate(fd_.get(), kPageSize), SyscallSucceeds());

  // The file may not actually be updated until munmap is called.
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  // The whole page is in the file.
  std::vector<char> buf(kPageSize);
  ASSERT_THAT(Read(buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  // Cast to void* to avoid EXPECT_THAT assuming buf.data() is a
  // NUL-terminated C string. EXPECT_THAT will try to print a char* as a C
  // string, possibly overruning the buffer.
  EXPECT_THAT(reinterpret_cast<void*>(buf.data()), EqualsMemory(first));
  EXPECT_THAT(reinterpret_cast<void*>(buf.data() + kPageSize / 2),
              EqualsMemory(second));
}

TEST_F(MMapFileTest, ReadSharedTruncateDownThenUp) {
  // Start from scratch.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Expand the file to a full page and dirty it.
  std::string buf(kPageSize, 'a');
  ASSERT_THAT(Write(buf.c_str(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Map the page.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // Check that the memory contains he file data.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), buf.c_str(), kPageSize));

  // Truncate down, then up.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());
  EXPECT_THAT(ftruncate(fd_.get(), kPageSize), SyscallSucceeds());

  // Check that the memory was zeroed.
  std::string zeroed(kPageSize, '\0');
  EXPECT_EQ(0,
            memcmp(reinterpret_cast<void*>(addr), zeroed.c_str(), kPageSize));

  // The file may not actually be updated until msync is called.
  ASSERT_THAT(Msync(), SyscallSucceeds());

  // Prepare to read the entire file contents.
  ASSERT_THAT(lseek(fd_.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));

  // Expect that the file is fully updated.
  std::vector<char> bufFile(kPageSize);
  ASSERT_THAT(Read(bufFile.data(), bufFile.size()),
              SyscallSucceedsWithValue(bufFile.size()));
  EXPECT_EQ(0, memcmp(bufFile.data(), zeroed.c_str(), kPageSize));
}

TEST_F(MMapFileTest, WriteSharedTruncateDownThenUp) {
  // The file is only half of a page. We map an entire page. Writes to the
  // end of the mapping must not be reflected in the file.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // First half; this will be deleted by truncate(0).
  std::string first(kPageSize / 2, 'A');
  memcpy(reinterpret_cast<void*>(addr), first.c_str(), first.size());

  // Truncate down, then up.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());
  EXPECT_THAT(ftruncate(fd_.get(), kPageSize), SyscallSucceeds());

  // The whole page is zeroed in memory.
  std::string zeroed(kPageSize, '\0');
  EXPECT_EQ(0,
            memcmp(reinterpret_cast<void*>(addr), zeroed.c_str(), kPageSize));

  // The file may not actually be updated until munmap is called.
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  // The whole file is also zeroed.
  std::vector<char> buf(kPageSize);
  ASSERT_THAT(Read(buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  // Cast to void* to avoid EXPECT_THAT assuming buf.data() is a
  // NUL-terminated C string. EXPECT_THAT will try to print a char* as a C
  // string, possibly overruning the buffer.
  EXPECT_THAT(reinterpret_cast<void*>(buf.data()), EqualsMemory(zeroed));
}

TEST_F(MMapFileTest, ReadSharedTruncateSIGBUS) {
  SetupGvisorDeathTest();

  // Start from scratch.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Expand the file to a full page and dirty it.
  std::string buf(kPageSize, 'a');
  ASSERT_THAT(Write(buf.c_str(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Map the page.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // Check that the mapping contains the file data.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), buf.c_str(), kPageSize));

  // Truncate down.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Accessing the truncated region should cause a SIGBUS.
  std::vector<char> in(kPageSize);
  EXPECT_EXIT(
      std::copy(reinterpret_cast<volatile char*>(addr),
                reinterpret_cast<volatile char*>(addr) + kPageSize, in.data()),
      ::testing::KilledBySignal(SIGBUS), "");
}

TEST_F(MMapFileTest, WriteSharedTruncateSIGBUS) {
  SetupGvisorDeathTest();

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // Touch the memory to be sure it really is mapped.
  size_t len = strlen(kFileContents);
  memcpy(reinterpret_cast<void*>(addr), kFileContents, len);

  // Truncate down.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Accessing the truncated file should cause a SIGBUS.
  EXPECT_EXIT(std::copy(kFileContents, kFileContents + len,
                        reinterpret_cast<volatile char*>(addr)),
              ::testing::KilledBySignal(SIGBUS), "");
}

TEST_F(MMapFileTest, ReadSharedTruncatePartialPage) {
  // Start from scratch.
  EXPECT_THAT(ftruncate(fd_.get(), 0), SyscallSucceeds());

  // Dirty the file.
  std::string buf(kPageSize, 'a');
  ASSERT_THAT(Write(buf.c_str(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));

  // Map a page.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // Truncate to half of the page.
  EXPECT_THAT(ftruncate(fd_.get(), kPageSize / 2), SyscallSucceeds());

  // First half of the page untouched.
  EXPECT_EQ(0,
            memcmp(reinterpret_cast<void*>(addr), buf.data(), kPageSize / 2));

  // Second half is zeroed.
  std::string zeroed(kPageSize / 2, '\0');
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr + kPageSize / 2),
                      zeroed.c_str(), kPageSize / 2));
}

// Page can still be accessed and contents are intact after truncating a partial
// page.
TEST_F(MMapFileTest, WriteSharedTruncatePartialPage) {
  // Expand the file to a full page.
  EXPECT_THAT(ftruncate(fd_.get(), kPageSize), SyscallSucceeds());

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // Fill the entire page.
  std::string contents(kPageSize, 'A');
  memcpy(reinterpret_cast<void*>(addr), contents.c_str(), contents.size());

  // Truncate half of the page.
  EXPECT_THAT(ftruncate(fd_.get(), kPageSize / 2), SyscallSucceeds());

  // First half of the page untouched.
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr), contents.c_str(),
                      kPageSize / 2));

  // Second half zeroed.
  std::string zeroed(kPageSize / 2, '\0');
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(addr + kPageSize / 2),
                      zeroed.c_str(), kPageSize / 2));
}

// MAP_PRIVATE writes are not carried through to the underlying file.
TEST_F(MMapFileTest, WritePrivate) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd_.get(), 0),
              SyscallSucceeds());

  size_t len = strlen(kFileContents);
  memcpy(reinterpret_cast<void*>(addr), kFileContents, len);

  // The file should not be updated, but if it mistakenly is, it may not be
  // until after munmap is called.
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  std::vector<char> buf(len);
  ASSERT_THAT(Read(buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  // Cast to void* to avoid EXPECT_THAT assuming buf.data() is a
  // NUL-terminated C string. EXPECT_THAT will try to print a char* as a C
  // string, possibly overruning the buffer.
  EXPECT_THAT(reinterpret_cast<void*>(buf.data()),
              EqualsMemory(std::string(len, '\0')));
}

// SIGBUS raised when writing past end of file to a private mapping.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, SigBusDeathWritePrivate) {
  SetupGvisorDeathTest();

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd_.get(), 0),
              SyscallSucceeds());

  // MMapFileTest makes a file kPageSize/2 long. The entire first page will be
  // accessible. Write just beyond that.
  size_t len = strlen(kFileContents);
  EXPECT_EXIT(std::copy(kFileContents, kFileContents + len,
                        reinterpret_cast<volatile char*>(addr + kPageSize)),
              ::testing::KilledBySignal(SIGBUS), "");
}

// SIGBUS raised when reading past end of file on a shared mapping.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, SigBusDeathReadShared) {
  SetupGvisorDeathTest();

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // MMapFileTest makes a file kPageSize/2 long. The entire first page will be
  // accessible. Read just beyond that.
  std::vector<char> in(kPageSize);
  EXPECT_EXIT(
      std::copy(reinterpret_cast<volatile char*>(addr + kPageSize),
                reinterpret_cast<volatile char*>(addr + kPageSize) + kPageSize,
                in.data()),
      ::testing::KilledBySignal(SIGBUS), "");
}

// SIGBUS raised when reading past end of file on a shared mapping.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, SigBusDeathWriteShared) {
  SetupGvisorDeathTest();

  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // MMapFileTest makes a file kPageSize/2 long. The entire first page will be
  // accessible. Write just beyond that.
  size_t len = strlen(kFileContents);
  EXPECT_EXIT(std::copy(kFileContents, kFileContents + len,
                        reinterpret_cast<volatile char*>(addr + kPageSize)),
              ::testing::KilledBySignal(SIGBUS), "");
}

// Tests that SIGBUS is not raised when writing to a file-mapped page before
// EOF, even if part of the mapping extends beyond EOF.
TEST_F(MMapFileTest, NoSigBusOnPagesBeforeEOF) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd_.get(), 0),
              SyscallSucceeds());

  // The test passes if this survives.
  size_t len = strlen(kFileContents);
  std::copy(kFileContents, kFileContents + len,
            reinterpret_cast<volatile char*>(addr));
}

// Tests that SIGBUS is not raised when writing to a file-mapped page containing
// EOF, *after* the EOF for a private mapping.
TEST_F(MMapFileTest, NoSigBusOnPageContainingEOFWritePrivate) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd_.get(), 0),
              SyscallSucceeds());

  // The test passes if this survives. (Technically addr+kPageSize/2 is already
  // beyond EOF, but +1 to check for fencepost errors.)
  size_t len = strlen(kFileContents);
  std::copy(kFileContents, kFileContents + len,
            reinterpret_cast<volatile char*>(addr + (kPageSize / 2) + 1));
}

// Tests that SIGBUS is not raised when reading from a file-mapped page
// containing EOF, *after* the EOF for a shared mapping.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, NoSigBusOnPageContainingEOFReadShared) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());

  // The test passes if this survives. (Technically addr+kPageSize/2 is already
  // beyond EOF, but +1 to check for fencepost errors.)
  auto* start = reinterpret_cast<volatile char*>(addr + (kPageSize / 2) + 1);
  size_t len = strlen(kFileContents);
  std::vector<char> in(len);
  std::copy(start, start + len, in.data());
}

// Tests that SIGBUS is not raised when writing to a file-mapped page containing
// EOF, *after* the EOF for a shared mapping.
//
// FIXME(b/37222275): Parameterize.
TEST_F(MMapFileTest, NoSigBusOnPageContainingEOFWriteShared) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  // The test passes if this survives. (Technically addr+kPageSize/2 is already
  // beyond EOF, but +1 to check for fencepost errors.)
  size_t len = strlen(kFileContents);
  std::copy(kFileContents, kFileContents + len,
            reinterpret_cast<volatile char*>(addr + (kPageSize / 2) + 1));
}

// Tests that reading from writable shared file-mapped pages succeeds.
//
// On most platforms this is trivial, but when the file is mapped via the sentry
// page cache (which does not yet support writing to shared mappings), a bug
// caused reads to fail unnecessarily on such mappings.
TEST_F(MMapFileTest, ReadingWritableSharedFilePageSucceeds) {
  uintptr_t addr;
  size_t len = strlen(kFileContents);

  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  std::vector<char> buf(kPageSize);
  // The test passes if this survives.
  std::copy(reinterpret_cast<volatile char*>(addr),
            reinterpret_cast<volatile char*>(addr) + len, buf.data());
}

// Tests that EFAULT is returned when invoking a syscall that requires the OS to
// read past end of file (resulting in a fault in sentry context in the gVisor
// case).
TEST_F(MMapFileTest, InternalSigBus) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                         fd_.get(), 0),
              SyscallSucceeds());

  // This depends on the fact that gVisor implements pipes internally.
  int pipefd[2];
  ASSERT_THAT(pipe(pipefd), SyscallSucceeds());
  EXPECT_THAT(
      write(pipefd[1], reinterpret_cast<void*>(addr + kPageSize), kPageSize),
      SyscallFailsWithErrno(EFAULT));

  EXPECT_THAT(close(pipefd[0]), SyscallSucceeds());
  EXPECT_THAT(close(pipefd[1]), SyscallSucceeds());
}

// Like InternalSigBus, but test the WriteZerosAt path by reading from
// /dev/zero to a shared mapping (so that the SIGBUS isn't caught during
// copy-on-write breaking).
TEST_F(MMapFileTest, InternalSigBusZeroing) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());

  const FileDescriptor dev_zero =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));
  EXPECT_THAT(read(dev_zero.get(), reinterpret_cast<void*>(addr + kPageSize),
                   kPageSize),
              SyscallFailsWithErrno(EFAULT));
}

// Checks that mmaps with a length of uint64_t(-PAGE_SIZE + 1) or greater do not
// induce a sentry panic (due to "rounding up" to 0).
TEST_F(MMapTest, HugeLength) {
  EXPECT_THAT(Map(0, static_cast<uint64_t>(-kPageSize + 1), PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallFailsWithErrno(ENOMEM));
}

// Tests for a specific gVisor MM caching bug.
TEST_F(MMapTest, AccessCOWInvalidatesCachedSegments) {
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(f.path(), O_RDWR));
  auto zero_fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/zero", O_RDONLY));

  // Get a two-page private mapping and fill it with 1s.
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, 2 * kPageSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
              SyscallSucceeds());
  memset(addr_, 1, 2 * kPageSize);
  MaybeSave();

  // Fork to make the mapping copy-on-write.
  pid_t const pid = fork();
  if (pid == 0) {
    // The child process waits for the parent to SIGKILL it.
    while (true) {
      pause();
    }
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  auto cleanup_child = Cleanup([&] {
    EXPECT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
    int status;
    EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  });

  // Induce a read-only Access of the first page of the mapping, which will not
  // cause a copy. The usermem.Segment should be cached.
  ASSERT_THAT(PwriteFd(fd.get(), addr_, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));

  // Induce a writable Access of both pages of the mapping. This should
  // invalidate the cached Segment.
  ASSERT_THAT(PreadFd(zero_fd.get(), addr_, 2 * kPageSize, 0),
              SyscallSucceedsWithValue(2 * kPageSize));

  // Induce a read-only Access of the first page of the mapping again. It should
  // read the 0s that were stored in the mapping by the read from /dev/zero. If
  // the read failed to invalidate the cached Segment, it will instead read the
  // 1s in the stale page.
  ASSERT_THAT(PwriteFd(fd.get(), addr_, kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));
  std::vector<char> buf(kPageSize);
  ASSERT_THAT(PreadFd(fd.get(), buf.data(), kPageSize, 0),
              SyscallSucceedsWithValue(kPageSize));
  for (size_t i = 0; i < kPageSize; i++) {
    ASSERT_EQ(0, buf[i]) << "at offset " << i;
  }
}

TEST_F(MMapTest, NoReserve) {
  const size_t kSize = 10 * 1 << 20;  // 10M
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kSize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0),
              SyscallSucceeds());
  EXPECT_GT(addr, 0);

  // Check that every page can be read/written. Technically, writing to memory
  // could SIGSEGV in case there is no more memory available. In gVisor it
  // would never happen though because NORESERVE is ignored. In Linux, it's
  // possible to fail, but allocation is small enough that it's highly likely
  // to succeed.
  for (size_t j = 0; j < kSize; j += kPageSize) {
    EXPECT_EQ(0, reinterpret_cast<char*>(addr)[j]);
    reinterpret_cast<char*>(addr)[j] = j;
  }
}

// Map more than the gVisor page-cache map unit (64k) and ensure that
// it is consistent with reading from the file.
TEST_F(MMapFileTest, Bug38498194) {
  // Choose a sufficiently large map unit.
  constexpr int kSize = 4 * 1024 * 1024;
  EXPECT_THAT(ftruncate(fd_.get(), kSize), SyscallSucceeds());

  // Map a large enough region so that multiple internal segments
  // are created to back the mapping.
  uintptr_t addr;
  ASSERT_THAT(
      addr = Map(0, kSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_.get(), 0),
      SyscallSucceeds());

  std::vector<char> expect(kSize, 'a');
  std::copy(expect.data(), expect.data() + expect.size(),
            reinterpret_cast<volatile char*>(addr));

  // Trigger writeback for gVisor. In Linux pages stay cached until
  // it can't hold onto them anymore.
  ASSERT_THAT(Unmap(), SyscallSucceeds());

  std::vector<char> buf(kSize);
  ASSERT_THAT(Read(buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
  EXPECT_EQ(buf, expect) << std::string(buf.data(), buf.size());
}

// Tests that reading from a file to a memory mapping of the same file does not
// deadlock.
TEST_F(MMapFileTest, SelfRead) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd_.get(), 0),
              SyscallSucceeds());
  EXPECT_THAT(Read(reinterpret_cast<char*>(addr), kPageSize / 2),
              SyscallSucceedsWithValue(kPageSize / 2));
  // The resulting file contents are poorly-specified and irrelevant.
}

// Tests that writing to a file from a memory mapping of the same file does not
// deadlock.
TEST_F(MMapFileTest, SelfWrite) {
  uintptr_t addr;
  ASSERT_THAT(addr = Map(0, kPageSize, PROT_READ, MAP_SHARED, fd_.get(), 0),
              SyscallSucceeds());
  EXPECT_THAT(Write(reinterpret_cast<char*>(addr), kPageSize / 2),
              SyscallSucceedsWithValue(kPageSize / 2));
  // The resulting file contents are poorly-specified and irrelevant.
}

TEST(MMapDeathTest, TruncateAfterCOWBreak) {
  SetupGvisorDeathTest();

  // Create and map a single-page file.
  auto const temp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  auto const fd = ASSERT_NO_ERRNO_AND_VALUE(Open(temp_file.path(), O_RDWR));
  ASSERT_THAT(ftruncate(fd.get(), kPageSize), SyscallSucceeds());
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0));

  // Write to this mapping, causing the page to be copied for write.
  memset(mapping.ptr(), 'a', mapping.len());
  MaybeSave();  // Trigger a co-operative save cycle.

  // Truncate the file and expect it to invalidate the copied page.
  ASSERT_THAT(ftruncate(fd.get(), 0), SyscallSucceeds());
  EXPECT_EXIT(*reinterpret_cast<volatile char*>(mapping.ptr()),
              ::testing::KilledBySignal(SIGBUS), "");
}

// Regression test for #147.
TEST(MMapNoFixtureTest, MapReadOnlyAfterCreateWriteOnly) {
  std::string filename = NewTempAbsPath();

  // We have to create the file O_RDONLY to reproduce the bug because
  // fsgofer.localFile.Create() silently upgrades O_WRONLY to O_RDWR, causing
  // the cached "write-only" FD to be read/write and therefore usable by mmap().
  auto const ro_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(filename, O_RDONLY | O_CREAT | O_EXCL, 0666));

  // Get a write-only FD for the same file, which should be ignored by mmap()
  // (but isn't in #147).
  auto const wo_fd = ASSERT_NO_ERRNO_AND_VALUE(Open(filename, O_WRONLY));
  ASSERT_THAT(ftruncate(wo_fd.get(), kPageSize), SyscallSucceeds());

  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, kPageSize, PROT_READ, MAP_SHARED, ro_fd.get(), 0));
  std::vector<char> buf(kPageSize);
  // The test passes if this survives.
  std::copy(static_cast<char*>(mapping.ptr()),
            static_cast<char*>(mapping.endptr()), buf.data());
}

// Conditional on MAP_32BIT.
#ifdef __x86_64__

TEST(MMapNoFixtureTest, Map32Bit) {
  auto const mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE | MAP_32BIT));
  EXPECT_LT(mapping.addr(), static_cast<uintptr_t>(1) << 32);
  EXPECT_LE(mapping.endaddr(), static_cast<uintptr_t>(1) << 32);
}

#endif  // defined(__x86_64__)

}  // namespace

}  // namespace testing
}  // namespace gvisor
