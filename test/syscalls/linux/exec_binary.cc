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

#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <algorithm>
#include <functional>
#include <iterator>
#include <tuple>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/proc_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

using ::testing::AnyOf;
using ::testing::Eq;

#ifndef __x86_64__
// The assembly stub and ELF internal details must be ported to other arches.
#error "Test only supported on x86-64"
#endif  // __x86_64__

// amd64 stub that calls PTRACE_TRACEME and sends itself SIGSTOP.
const char kPtraceCode[] = {
    // movq $101, %rax  /* ptrace */
    '\x48',
    '\xc7',
    '\xc0',
    '\x65',
    '\x00',
    '\x00',
    '\x00',
    // movq $0, %rsi  /* PTRACE_TRACEME */
    '\x48',
    '\xc7',
    '\xc6',
    '\x00',
    '\x00',
    '\x00',
    '\x00',
    // movq $0, %rdi
    '\x48',
    '\xc7',
    '\xc7',
    '\x00',
    '\x00',
    '\x00',
    '\x00',
    // movq $0, %rdx
    '\x48',
    '\xc7',
    '\xc2',
    '\x00',
    '\x00',
    '\x00',
    '\x00',
    // movq $0, %r10
    '\x49',
    '\xc7',
    '\xc2',
    '\x00',
    '\x00',
    '\x00',
    '\x00',
    // syscall
    '\x0f',
    '\x05',

    // movq $39, %rax  /* getpid */
    '\x48',
    '\xc7',
    '\xc0',
    '\x27',
    '\x00',
    '\x00',
    '\x00',
    // syscall
    '\x0f',
    '\x05',

    // movq %rax, %rdi  /* pid */
    '\x48',
    '\x89',
    '\xc7',
    // movq $62, %rax  /* kill */
    '\x48',
    '\xc7',
    '\xc0',
    '\x3e',
    '\x00',
    '\x00',
    '\x00',
    // movq $19, %rsi  /* SIGSTOP */
    '\x48',
    '\xc7',
    '\xc6',
    '\x13',
    '\x00',
    '\x00',
    '\x00',
    // syscall
    '\x0f',
    '\x05',
};

// Size of a syscall instruction.
constexpr int kSyscallSize = 2;

// This test suite tests executable loading in the kernel (ELF and interpreter
// scripts).

// Parameterized ELF types for 64 and 32 bit.
template <int Size>
struct ElfTypes;

template <>
struct ElfTypes<64> {
  typedef Elf64_Ehdr ElfEhdr;
  typedef Elf64_Phdr ElfPhdr;
};

template <>
struct ElfTypes<32> {
  typedef Elf32_Ehdr ElfEhdr;
  typedef Elf32_Phdr ElfPhdr;
};

template <int Size>
struct ElfBinary {
  using ElfEhdr = typename ElfTypes<Size>::ElfEhdr;
  using ElfPhdr = typename ElfTypes<Size>::ElfPhdr;

  ElfEhdr header = {};
  std::vector<ElfPhdr> phdrs;
  std::vector<char> data;

  // UpdateOffsets updates p_offset, p_vaddr in all phdrs to account for the
  // space taken by the header and phdrs.
  //
  // It also updates header.e_phnum and adds the offset to header.e_entry to
  // account for the headers residing in the first PT_LOAD segment.
  //
  // Before calling UpdateOffsets each of those fields should be the appropriate
  // offset into data.
  void UpdateOffsets() {
    size_t offset = sizeof(header) + phdrs.size() * sizeof(ElfPhdr);
    header.e_entry += offset;
    header.e_phnum = phdrs.size();
    for (auto& p : phdrs) {
      p.p_offset += offset;
      p.p_vaddr += offset;
    }
  }

  // AddInterpreter adds a PT_INTERP segment with the passed contents.
  //
  // A later call to UpdateOffsets is required to make the new phdr valid.
  void AddInterpreter(std::vector<char> contents) {
    const int start = data.size();
    data.insert(data.end(), contents.begin(), contents.end());
    const int size = data.size() - start;

    ElfPhdr phdr = {};
    phdr.p_type = PT_INTERP;
    phdr.p_offset = start;
    phdr.p_filesz = size;
    phdr.p_memsz = size;
    // "If [PT_INTERP] is present, it must precede any loadable segment entry."
    phdrs.insert(phdrs.begin(), phdr);
  }

  // Writes the header, phdrs, and data to fd.
  PosixError Write(int fd) const {
    int ret = WriteFd(fd, &header, sizeof(header));
    if (ret < 0) {
      return PosixError(errno, "failed to write header");
    } else if (ret != sizeof(header)) {
      return PosixError(EIO, absl::StrCat("short write of header: ", ret));
    }

    for (auto const& p : phdrs) {
      ret = WriteFd(fd, &p, sizeof(p));
      if (ret < 0) {
        return PosixError(errno, "failed to write phdr");
      } else if (ret != sizeof(p)) {
        return PosixError(EIO, absl::StrCat("short write of phdr: ", ret));
      }
    }

    ret = WriteFd(fd, data.data(), data.size());
    if (ret < 0) {
      return PosixError(errno, "failed to write data");
    } else if (ret != static_cast<int>(data.size())) {
      return PosixError(EIO, absl::StrCat("short write of data: ", ret));
    }

    return NoError();
  }
};

// Creates a new temporary executable ELF file in parent with elf as the
// contents.
template <int Size>
PosixErrorOr<TempPath> CreateElfWith(absl::string_view parent,
                                     ElfBinary<Size> const& elf) {
  ASSIGN_OR_RETURN_ERRNO(
      auto file, TempPath::CreateFileWith(parent, absl::string_view(), 0755));
  ASSIGN_OR_RETURN_ERRNO(auto fd, Open(file.path(), O_RDWR));
  RETURN_IF_ERRNO(elf.Write(fd.get()));
  return std::move(file);
}

// Creates a new temporary executable ELF file with elf as the contents.
template <int Size>
PosixErrorOr<TempPath> CreateElfWith(ElfBinary<Size> const& elf) {
  return CreateElfWith(GetAbsoluteTestTmpdir(), elf);
}

// Wait for pid to stop, and assert that it stopped via SIGSTOP.
PosixError WaitStopped(pid_t pid) {
  int status;
  int ret = RetryEINTR(waitpid)(pid, &status, 0);
  MaybeSave();
  if (ret < 0) {
    return PosixError(errno, "wait failed");
  } else if (ret != pid) {
    return PosixError(ESRCH, absl::StrCat("wait got ", ret, " want ", pid));
  }

  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
    return PosixError(EINVAL,
                      absl::StrCat("pid did not SIGSTOP; status = ", status));
  }

  return NoError();
}

// Returns a valid ELF that PTRACE_TRACEME and SIGSTOPs itself.
//
// UpdateOffsets must be called before writing this ELF.
ElfBinary<64> StandardElf() {
  ElfBinary<64> elf;
  elf.header.e_ident[EI_MAG0] = ELFMAG0;
  elf.header.e_ident[EI_MAG1] = ELFMAG1;
  elf.header.e_ident[EI_MAG2] = ELFMAG2;
  elf.header.e_ident[EI_MAG3] = ELFMAG3;
  elf.header.e_ident[EI_CLASS] = ELFCLASS64;
  elf.header.e_ident[EI_DATA] = ELFDATA2LSB;
  elf.header.e_ident[EI_VERSION] = EV_CURRENT;
  elf.header.e_type = ET_EXEC;
  elf.header.e_machine = EM_X86_64;
  elf.header.e_version = EV_CURRENT;
  elf.header.e_phoff = sizeof(elf.header);
  elf.header.e_phentsize = sizeof(decltype(elf)::ElfPhdr);

  // TODO: Always include a PT_GNU_STACK segment to
  // disable executable stacks. With this omitted the stack (and all PROT_READ)
  // mappings should be executable, but gVisor doesn't support that.
  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_GNU_STACK;
  phdr.p_flags = PF_R | PF_W;
  elf.phdrs.push_back(phdr);

  phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_offset = 0;
  phdr.p_vaddr = 0x40000;
  phdr.p_filesz = sizeof(kPtraceCode);
  phdr.p_memsz = phdr.p_filesz;
  elf.phdrs.push_back(phdr);

  elf.header.e_entry = phdr.p_vaddr;

  elf.data.assign(kPtraceCode, kPtraceCode + sizeof(kPtraceCode));

  return elf;
}

// Test that a trivial binary executes.
TEST(ElfTest, Execute) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  // Ensure it made it to SIGSTOP.
  ASSERT_NO_ERRNO(WaitStopped(child));

  struct user_regs_struct regs;
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());
  // RIP is just beyond the final syscall instruction.
  EXPECT_EQ(regs.rip, elf.header.e_entry + sizeof(kPtraceCode));

  EXPECT_THAT(child, ContainsMappings(std::vector<ProcMapsEntry>({
                         {0x40000, 0x41000, true, false, true, true, 0, 0, 0, 0,
                          file.path().c_str()},
                     })));
}

// StandardElf without data completes execve, but faults once running.
TEST(ElfTest, MissingText) {
  ElfBinary<64> elf = StandardElf();
  elf.data.clear();
  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  // It runs off the end of the zeroes filling the end of the page.
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) << status;
}

// Typical ELF with a data + bss segment
TEST(ElfTest, DataSegment) {
  ElfBinary<64> elf = StandardElf();

  // Create a standard ELF, but extend to 1.5 pages. The second page will be the
  // beginning of a multi-page data + bss segment.
  elf.data.resize(kPageSize + kPageSize / 2);

  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_W;
  phdr.p_offset = kPageSize;
  phdr.p_vaddr = 0x41000;
  phdr.p_filesz = kPageSize / 2;
  // The header is going to push vaddr up by a few hundred bytes. Keep p_memsz a
  // bit less than 2 pages so this mapping doesn't extend beyond 0x43000.
  phdr.p_memsz = 2 * kPageSize - kPageSize / 2;
  elf.phdrs.push_back(phdr);

  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  EXPECT_THAT(
      child, ContainsMappings(std::vector<ProcMapsEntry>({
                 // text page.
                 {0x40000, 0x41000, true, false, true, true, 0, 0, 0, 0,
                  file.path().c_str()},
                 // data + bss page from file.
                 {0x41000, 0x42000, true, true, false, true, kPageSize, 0, 0, 0,
                  file.path().c_str()},
                 // bss page from anon.
                 {0x42000, 0x43000, true, true, false, true, 0, 0, 0, 0, ""},
             })));
}

// Linux will allow PT_LOAD segments to overlap.
TEST(ElfTest, DirectlyOverlappingSegments) {
  // NOTE: see PIEOutOfOrderSegments.
  SKIP_IF(IsRunningOnGvisor());

  ElfBinary<64> elf = StandardElf();

  // Same as the StandardElf mapping.
  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_LOAD;
  // Add PF_W so we can differentiate this mapping from the first.
  phdr.p_flags = PF_R | PF_W | PF_X;
  phdr.p_offset = 0;
  phdr.p_vaddr = 0x40000;
  phdr.p_filesz = sizeof(kPtraceCode);
  phdr.p_memsz = phdr.p_filesz;
  elf.phdrs.push_back(phdr);

  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  EXPECT_THAT(child, ContainsMappings(std::vector<ProcMapsEntry>({
                         {0x40000, 0x41000, true, true, true, true, 0, 0, 0, 0,
                          file.path().c_str()},
                     })));
}

// Linux allows out-of-order PT_LOAD segments.
TEST(ElfTest, OutOfOrderSegments) {
  // NOTE: see PIEOutOfOrderSegments.
  SKIP_IF(IsRunningOnGvisor());

  ElfBinary<64> elf = StandardElf();

  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_offset = 0;
  phdr.p_vaddr = 0x20000;
  phdr.p_filesz = sizeof(kPtraceCode);
  phdr.p_memsz = phdr.p_filesz;
  elf.phdrs.push_back(phdr);

  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  EXPECT_THAT(child, ContainsMappings(std::vector<ProcMapsEntry>({
                         {0x20000, 0x21000, true, false, true, true, 0, 0, 0, 0,
                          file.path().c_str()},
                         {0x40000, 0x41000, true, false, true, true, 0, 0, 0, 0,
                          file.path().c_str()},
                     })));
}

// header.e_phoff is bound the end of the file.
TEST(ElfTest, OutOfBoundsPhdrs) {
  ElfBinary<64> elf = StandardElf();
  elf.header.e_phoff = 0x100000;
  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  // On Linux 3.11, this caused EIO. On newer Linux, it causes ENOEXEC.
  EXPECT_THAT(execve_errno, AnyOf(Eq(ENOEXEC), Eq(EIO)));
}

// Claim there is a phdr beyond the end of the file, but don't include it.
TEST(ElfTest, MissingPhdr) {
  ElfBinary<64> elf = StandardElf();

  // Clear data so the file ends immediately after the phdrs.
  // N.B. Per ElfTest.MissingData, StandardElf without data completes execve
  // without error.
  elf.data.clear();
  elf.UpdateOffsets();

  // Claim that there is another phdr just beyond the end of the file. Of
  // course, it isn't accessible.
  elf.header.e_phnum++;

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  // On Linux 3.11, this caused EIO. On newer Linux, it causes ENOEXEC.
  EXPECT_THAT(execve_errno, AnyOf(Eq(ENOEXEC), Eq(EIO)));
}

// No headers at all, just the ELF magic.
TEST(ElfTest, MissingHeader) {
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileMode(0755));
  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  const char kElfMagic[] = {0x7f, 'E', 'L', 'F'};

  ASSERT_THAT(WriteFd(fd.get(), &kElfMagic, sizeof(kElfMagic)),
              SyscallSucceeds());
  fd.reset();

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, ENOEXEC);
}

// Load a PIE ELF with a data + bss segment.
TEST(ElfTest, PIE) {
  ElfBinary<64> elf = StandardElf();

  elf.header.e_type = ET_DYN;

  // Create a standard ELF, but extend to 1.5 pages. The second page will be the
  // beginning of a multi-page data + bss segment.
  elf.data.resize(kPageSize + kPageSize / 2);

  elf.header.e_entry = 0x0;

  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_W;
  phdr.p_offset = kPageSize;
  // Put the data segment at a bit of an offset.
  phdr.p_vaddr = 0x20000;
  phdr.p_filesz = kPageSize / 2;
  // The header is going to push vaddr up by a few hundred bytes. Keep p_memsz a
  // bit less than 2 pages so this mapping doesn't extend beyond 0x43000.
  phdr.p_memsz = 2 * kPageSize - kPageSize / 2;
  elf.phdrs.push_back(phdr);

  elf.UpdateOffsets();

  // The first segment really needs to start at 0 for a normal PIE binary, and
  // thus includes the headers.
  const uint64_t offset = elf.phdrs[1].p_offset;
  elf.phdrs[1].p_offset = 0x0;
  elf.phdrs[1].p_vaddr = 0x0;
  elf.phdrs[1].p_filesz += offset;
  elf.phdrs[1].p_memsz += offset;

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  // RIP tells us which page the first segment was loaded into.
  struct user_regs_struct regs;
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());

  const uint64_t load_addr = regs.rip & ~(kPageSize - 1);

  EXPECT_THAT(child, ContainsMappings(std::vector<ProcMapsEntry>({
                         // text page.
                         {load_addr, load_addr + 0x1000, true, false, true,
                          true, 0, 0, 0, 0, file.path().c_str()},
                         // data + bss page from file.
                         {load_addr + 0x20000, load_addr + 0x21000, true, true,
                          false, true, kPageSize, 0, 0, 0, file.path().c_str()},
                         // bss page from anon.
                         {load_addr + 0x21000, load_addr + 0x22000, true, true,
                          false, true, 0, 0, 0, 0, ""},
                     })));
}

// PIE binary with a non-zero start address.
//
// This is non-standard for a PIE binary, but valid. The binary is still loaded
// at an arbitrary address, not the first PT_LOAD vaddr.
//
// N.B. Linux changed this behavior in d1fd836dcf00d2028c700c7e44d2c23404062c90.
// Previously, with "randomization" enabled, PIE binaries with a non-zero start
// address would be be loaded at the address they specified because mmap was
// passed the load address, which wasn't 0 as expected.
//
// This change is present in kernel v4.1+.
TEST(ElfTest, PIENonZeroStart) {
  // gVisor has the newer behavior.
  if (!IsRunningOnGvisor()) {
    auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major < 4 || (version.major == 4 && version.minor < 1));
  }

  ElfBinary<64> elf = StandardElf();

  elf.header.e_type = ET_DYN;

  // Create a standard ELF, but extend to 1.5 pages. The second page will be the
  // beginning of a multi-page data + bss segment.
  elf.data.resize(kPageSize + kPageSize / 2);

  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_W;
  phdr.p_offset = kPageSize;
  // Put the data segment at a bit of an offset.
  phdr.p_vaddr = 0x60000;
  phdr.p_filesz = kPageSize / 2;
  // The header is going to push vaddr up by a few hundred bytes. Keep p_memsz a
  // bit less than 2 pages so this mapping doesn't extend beyond 0x43000.
  phdr.p_memsz = 2 * kPageSize - kPageSize / 2;
  elf.phdrs.push_back(phdr);

  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  // RIP tells us which page the first segment was loaded into.
  struct user_regs_struct regs;
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());

  const uint64_t load_addr = regs.rip & ~(kPageSize - 1);

  // The ELF is loaded at an arbitrary address, not the first PT_LOAD vaddr.
  //
  // N.B. this is technically flaky, but Linux is *extremely* unlikely to pick
  // this as the start address, as it searches from the top down.
  EXPECT_NE(load_addr, 0x40000);

  EXPECT_THAT(child, ContainsMappings(std::vector<ProcMapsEntry>({
                         // text page.
                         {load_addr, load_addr + 0x1000, true, false, true,
                          true, 0, 0, 0, 0, file.path().c_str()},
                         // data + bss page from file.
                         {load_addr + 0x20000, load_addr + 0x21000, true, true,
                          false, true, kPageSize, 0, 0, 0, file.path().c_str()},
                         // bss page from anon.
                         {load_addr + 0x21000, load_addr + 0x22000, true, true,
                          false, true, 0, 0, 0, 0, ""},
                     })));
}

TEST(ElfTest, PIEOutOfOrderSegments) {
  // TODO: This triggers a bug in Linux where it computes the size
  // of the binary as 0x20000 - 0x40000 = 0xfffffffffffe0000, which obviously
  // fails to map.
  //
  // We test gVisor's behavior (of rejecting the binary) because I assert that
  // Linux is wrong and needs to be fixed.
  SKIP_IF(!IsRunningOnGvisor());

  ElfBinary<64> elf = StandardElf();

  elf.header.e_type = ET_DYN;

  // Create a standard ELF, but extend to 1.5 pages. The second page will be the
  // beginning of a multi-page data + bss segment.
  elf.data.resize(kPageSize + kPageSize / 2);

  decltype(elf)::ElfPhdr phdr = {};
  phdr.p_type = PT_LOAD;
  phdr.p_flags = PF_R | PF_W;
  phdr.p_offset = kPageSize;
  // Put the data segment *before* the first segment.
  phdr.p_vaddr = 0x20000;
  phdr.p_filesz = kPageSize / 2;
  // The header is going to push vaddr up by a few hundred bytes. Keep p_memsz a
  // bit less than 2 pages so this mapping doesn't extend beyond 0x43000.
  phdr.p_memsz = 2 * kPageSize - kPageSize / 2;
  elf.phdrs.push_back(phdr);

  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, ENOEXEC);
}

// Standard dynamically linked binary with an ELF interpreter.
TEST(ElfTest, ELFInterpreter) {
  ElfBinary<64> interpreter = StandardElf();
  interpreter.header.e_type = ET_DYN;
  interpreter.header.e_entry = 0x0;
  interpreter.UpdateOffsets();

  // The first segment really needs to start at 0 for a normal PIE binary, and
  // thus includes the headers.
  uint64_t const offset = interpreter.phdrs[1].p_offset;
  interpreter.phdrs[1].p_offset = 0x0;
  interpreter.phdrs[1].p_vaddr = 0x0;
  interpreter.phdrs[1].p_filesz += offset;
  interpreter.phdrs[1].p_memsz += offset;

  TempPath interpreter_file =
      ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(interpreter));

  ElfBinary<64> binary = StandardElf();

  // Append the interpreter path.
  int const interp_data_start = binary.data.size();
  for (char const c : interpreter_file.path()) {
    binary.data.push_back(c);
  }
  // NUL-terminate.
  binary.data.push_back(0);
  int const interp_data_size = binary.data.size() - interp_data_start;

  decltype(binary)::ElfPhdr phdr = {};
  phdr.p_type = PT_INTERP;
  phdr.p_offset = interp_data_start;
  phdr.p_filesz = interp_data_size;
  phdr.p_memsz = interp_data_size;
  // "If [PT_INTERP] is present, it must precede any loadable segment entry."
  //
  // However, Linux allows it anywhere, so we just stick it at the end to make
  // sure out-of-order PT_INTERP is OK.
  binary.phdrs.push_back(phdr);

  binary.UpdateOffsets();

  TempPath binary_file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(binary));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      binary_file.path(), {binary_file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  // RIP tells us which page the first segment of the interpreter was loaded
  // into.
  struct user_regs_struct regs;
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());

  const uint64_t interp_load_addr = regs.rip & ~(kPageSize - 1);

  EXPECT_THAT(child,
              ContainsMappings(std::vector<ProcMapsEntry>({
                  // Main binary
                  {0x40000, 0x41000, true, false, true, true, 0, 0, 0, 0,
                   binary_file.path().c_str()},
                  // Interpreter
                  {interp_load_addr, interp_load_addr + 0x1000, true, false,
                   true, true, 0, 0, 0, 0, interpreter_file.path().c_str()},
              })));
}

// Test parameter to ElfInterpterStaticTest cases. The first item is a suffix to
// add to the end of the interpreter path in the PT_INTERP segment and the
// second is the expected execve(2) errno.
using ElfInterpreterStaticParam = std::tuple<std::vector<char>, int>;

class ElfInterpreterStaticTest
    : public ::testing::TestWithParam<ElfInterpreterStaticParam> {};

// Statically linked ELF with a statically linked ELF interpreter.
TEST_P(ElfInterpreterStaticTest, Test) {
  const std::vector<char> segment_suffix = std::get<0>(GetParam());
  const int expected_errno = std::get<1>(GetParam());

  ElfBinary<64> interpreter = StandardElf();
  interpreter.UpdateOffsets();
  TempPath interpreter_file =
      ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(interpreter));

  ElfBinary<64> binary = StandardElf();
  // The PT_LOAD segment conflicts with the interpreter's PT_LOAD segment. The
  // interpreter's will be mapped directly over the binary's.

  // Interpreter path plus the parameterized suffix in the PT_INTERP segment.
  const std::string path = interpreter_file.path();
  std::vector<char> segment(path.begin(), path.end());
  segment.insert(segment.end(), segment_suffix.begin(), segment_suffix.end());
  binary.AddInterpreter(segment);

  binary.UpdateOffsets();

  TempPath binary_file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(binary));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      binary_file.path(), {binary_file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, expected_errno);

  if (expected_errno == 0) {
    ASSERT_NO_ERRNO(WaitStopped(child));

    EXPECT_THAT(child, ContainsMappings(std::vector<ProcMapsEntry>({
                           // Interpreter.
                           {0x40000, 0x41000, true, false, true, true, 0, 0, 0,
                            0, interpreter_file.path().c_str()},
                       })));
  }
}

INSTANTIATE_TEST_SUITE_P(
    Cases, ElfInterpreterStaticTest,
    ::testing::ValuesIn({
        // Simple NUL-terminator to run the interpreter as normal.
        std::make_tuple(std::vector<char>({'\0'}), 0),
        // Add some garbage to the segment followed by a NUL-terminator. This is
        // ignored.
        std::make_tuple(std::vector<char>({'\0', 'b', '\0'}), 0),
        // Add some garbage to the segment without a NUL-terminator. Linux will
        // reject
        // this.
        std::make_tuple(std::vector<char>({'\0', 'b'}), ENOEXEC),
    }));

// Test parameter to ElfInterpterBadPathTest cases. The first item is the
// contents of the PT_INTERP segment and the second is the expected execve(2)
// errno.
using ElfInterpreterBadPathParam = std::tuple<std::vector<char>, int>;

class ElfInterpreterBadPathTest
    : public ::testing::TestWithParam<ElfInterpreterBadPathParam> {};

TEST_P(ElfInterpreterBadPathTest, Test) {
  const std::vector<char> segment = std::get<0>(GetParam());
  const int expected_errno = std::get<1>(GetParam());

  ElfBinary<64> binary = StandardElf();
  binary.AddInterpreter(segment);
  binary.UpdateOffsets();

  TempPath binary_file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(binary));

  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      binary_file.path(), {binary_file.path()}, {}, nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, expected_errno);
}

INSTANTIATE_TEST_SUITE_P(
    Cases, ElfInterpreterBadPathTest,
    ::testing::ValuesIn({
        // NUL-terminated fake path in the PT_INTERP segment.
        std::make_tuple(std::vector<char>({'/', 'f', '/', 'b', '\0'}), ENOENT),
        // ELF interpreter not NUL-terminated.
        std::make_tuple(std::vector<char>({'/', 'f', '/', 'b'}), ENOEXEC),
        // ELF interpreter path omitted entirely.
        //
        // fs/binfmt_elf.c:load_elf_binary returns ENOEXEC if p_filesz is < 2
        // bytes.
        std::make_tuple(std::vector<char>({'\0'}), ENOEXEC),
        // ELF interpreter path = "\0".
        //
        // fs/binfmt_elf.c:load_elf_binary returns ENOEXEC if p_filesz is < 2
        // bytes, so add an extra byte to pass that check.
        //
        // load_elf_binary -> open_exec -> do_open_execat fails to check that
        // name != '\0' before calling do_filp_open, which thus opens the
        // working directory. do_open_execat returns EACCES because the
        // directory is not a regular file.
        std::make_tuple(std::vector<char>({'\0', '\0'}), EACCES),
    }));

// Relative path to ELF interpreter.
TEST(ElfTest, ELFInterpreterRelative) {
  ElfBinary<64> interpreter = StandardElf();
  interpreter.header.e_type = ET_DYN;
  interpreter.header.e_entry = 0x0;
  interpreter.UpdateOffsets();

  // The first segment really needs to start at 0 for a normal PIE binary, and
  // thus includes the headers.
  uint64_t const offset = interpreter.phdrs[1].p_offset;
  interpreter.phdrs[1].p_offset = 0x0;
  interpreter.phdrs[1].p_vaddr = 0x0;
  interpreter.phdrs[1].p_filesz += offset;
  interpreter.phdrs[1].p_memsz += offset;

  TempPath interpreter_file =
      ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(interpreter));
  auto cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
  auto interpreter_relative =
      ASSERT_NO_ERRNO_AND_VALUE(GetRelativePath(cwd, interpreter_file.path()));

  ElfBinary<64> binary = StandardElf();

  // NUL-terminated path in the PT_INTERP segment.
  std::vector<char> segment(interpreter_relative.begin(),
                            interpreter_relative.end());
  segment.push_back(0);
  binary.AddInterpreter(segment);

  binary.UpdateOffsets();

  TempPath binary_file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(binary));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      binary_file.path(), {binary_file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  // RIP tells us which page the first segment of the interpreter was loaded
  // into.
  struct user_regs_struct regs;
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());

  const uint64_t interp_load_addr = regs.rip & ~(kPageSize - 1);

  EXPECT_THAT(child,
              ContainsMappings(std::vector<ProcMapsEntry>({
                  // Main binary
                  {0x40000, 0x41000, true, false, true, true, 0, 0, 0, 0,
                   binary_file.path().c_str()},
                  // Interpreter
                  {interp_load_addr, interp_load_addr + 0x1000, true, false,
                   true, true, 0, 0, 0, 0, interpreter_file.path().c_str()},
              })));
}

// ELF interpreter architecture doesn't match the binary.
TEST(ElfTest, ELFInterpreterWrongArch) {
  ElfBinary<64> interpreter = StandardElf();
  interpreter.header.e_machine = EM_PPC64;
  interpreter.header.e_type = ET_DYN;
  interpreter.header.e_entry = 0x0;
  interpreter.UpdateOffsets();

  // The first segment really needs to start at 0 for a normal PIE binary, and
  // thus includes the headers.
  uint64_t const offset = interpreter.phdrs[1].p_offset;
  interpreter.phdrs[1].p_offset = 0x0;
  interpreter.phdrs[1].p_vaddr = 0x0;
  interpreter.phdrs[1].p_filesz += offset;
  interpreter.phdrs[1].p_memsz += offset;

  TempPath interpreter_file =
      ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(interpreter));

  ElfBinary<64> binary = StandardElf();

  // NUL-terminated path in the PT_INTERP segment.
  const std::string path = interpreter_file.path();
  std::vector<char> segment(path.begin(), path.end());
  segment.push_back(0);
  binary.AddInterpreter(segment);

  binary.UpdateOffsets();

  TempPath binary_file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(binary));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec(
      binary_file.path(), {binary_file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, ELIBBAD);
}

// No execute permissions on the binary.
TEST(ElfTest, NoExecute) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  ASSERT_THAT(chmod(file.path().c_str(), 0644), SyscallSucceeds());

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, EACCES);
}

// Execute, but no read permissions on the binary works just fine.
TEST(ElfTest, NoRead) {
  // TODO: gVisor's backing filesystem may prevent the
  // sentry from reading the executable.
  SKIP_IF(IsRunningOnGvisor());

  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  ASSERT_THAT(chmod(file.path().c_str(), 0111), SyscallSucceeds());

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  ASSERT_NO_ERRNO(WaitStopped(child));

  // TODO: A task with a non-readable executable is marked
  // non-dumpable, preventing access to proc files. gVisor does not implement
  // this behavior.
}

// No execute permissions on the ELF interpreter.
TEST(ElfTest, ElfInterpreterNoExecute) {
  ElfBinary<64> interpreter = StandardElf();
  interpreter.header.e_type = ET_DYN;
  interpreter.header.e_entry = 0x0;
  interpreter.UpdateOffsets();

  // The first segment really needs to start at 0 for a normal PIE binary, and
  // thus includes the headers.
  uint64_t const offset = interpreter.phdrs[1].p_offset;
  interpreter.phdrs[1].p_offset = 0x0;
  interpreter.phdrs[1].p_vaddr = 0x0;
  interpreter.phdrs[1].p_filesz += offset;
  interpreter.phdrs[1].p_memsz += offset;

  TempPath interpreter_file =
      ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(interpreter));

  ElfBinary<64> binary = StandardElf();

  // NUL-terminated path in the PT_INTERP segment.
  const std::string path = interpreter_file.path();
  std::vector<char> segment(path.begin(), path.end());
  segment.push_back(0);
  binary.AddInterpreter(segment);

  binary.UpdateOffsets();

  TempPath binary_file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(binary));

  ASSERT_THAT(chmod(interpreter_file.path().c_str(), 0644), SyscallSucceeds());

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(interpreter_file.path(), {interpreter_file.path()}, {},
                  &child, &execve_errno));
  EXPECT_EQ(execve_errno, EACCES);
}

// Execute a basic interpreter script.
TEST(InterpreterScriptTest, Execute) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", binary.path()), 0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  EXPECT_NO_ERRNO(WaitStopped(child));
}

// Whitespace after #!.
TEST(InterpreterScriptTest, Whitespace) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#! \t  \t", binary.path()), 0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  EXPECT_NO_ERRNO(WaitStopped(child));
}

// Interpreter script is missing execute permission.
TEST(InterpreterScriptTest, InterpreterScriptNoExecute) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", binary.path()), 0644));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, EACCES);
}

// Binary interpreter script refers to is missing execute permission.
TEST(InterpreterScriptTest, BinaryNoExecute) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  ASSERT_THAT(chmod(binary.path().c_str(), 0644), SyscallSucceeds());

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", binary.path()), 0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, EACCES);
}

// Linux will load interpreter scripts five levels deep, but no more.
TEST(InterpreterScriptTest, MaxRecursion) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  TempPath script1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      "/tmp", absl::StrCat("#!", binary.path()), 0755));
  TempPath script2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      "/tmp", absl::StrCat("#!", script1.path()), 0755));
  TempPath script3 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      "/tmp", absl::StrCat("#!", script2.path()), 0755));
  TempPath script4 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      "/tmp", absl::StrCat("#!", script3.path()), 0755));
  TempPath script5 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      "/tmp", absl::StrCat("#!", script4.path()), 0755));
  TempPath script6 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      "/tmp", absl::StrCat("#!", script5.path()), 0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script6.path(), {script6.path()}, {}, &child, &execve_errno));
  // Too many levels of recursion.
  EXPECT_EQ(execve_errno, ELOOP);

  // The next level up is OK.
  auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script5.path(), {script5.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  EXPECT_NO_ERRNO(WaitStopped(child));
}

// Interpreter script with a relative path.
TEST(InterpreterScriptTest, RelativePath) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  auto cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
  auto binary_relative =
      ASSERT_NO_ERRNO_AND_VALUE(GetRelativePath(cwd, binary.path()));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", binary_relative), 0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  EXPECT_NO_ERRNO(WaitStopped(child));
}

// Interpreter script with .. in a path component.
TEST(InterpreterScriptTest, UncleanPath) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!/tmp/../", binary.path()),
      0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  EXPECT_NO_ERRNO(WaitStopped(child));
}

// Passed interpreter script is a symlink.
TEST(InterpreterScriptTest, Symlink) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  // Use /tmp explicitly to ensure the path is short enough.
  TempPath binary = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith("/tmp", elf));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", binary.path()), 0755));

  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(GetAbsoluteTestTmpdir(), script.path()));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(link.path(), {link.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  EXPECT_NO_ERRNO(WaitStopped(child));
}

// Interpreter script points to a symlink loop.
TEST(InterpreterScriptTest, SymlinkLoop) {
  std::string const link1 = NewTempAbsPathInDir("/tmp");
  std::string const link2 = NewTempAbsPathInDir("/tmp");

  ASSERT_THAT(symlink(link2.c_str(), link1.c_str()), SyscallSucceeds());
  auto remove_link1 = Cleanup(
      [&link1] { EXPECT_THAT(unlink(link1.c_str()), SyscallSucceeds()); });

  ASSERT_THAT(symlink(link1.c_str(), link2.c_str()), SyscallSucceeds());
  auto remove_link2 = Cleanup(
      [&link2] { EXPECT_THAT(unlink(link2.c_str()), SyscallSucceeds()); });

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link1), 0755));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, ELOOP);
}

// Binary is a symlink loop.
TEST(ExecveTest, SymlinkLoop) {
  std::string const link1 = NewTempAbsPathInDir("/tmp");
  std::string const link2 = NewTempAbsPathInDir("/tmp");

  ASSERT_THAT(symlink(link2.c_str(), link1.c_str()), SyscallSucceeds());
  auto remove_link = Cleanup(
      [&link1] { EXPECT_THAT(unlink(link1.c_str()), SyscallSucceeds()); });

  ASSERT_THAT(symlink(link1.c_str(), link2.c_str()), SyscallSucceeds());
  auto remove_link2 = Cleanup(
      [&link2] { EXPECT_THAT(unlink(link2.c_str()), SyscallSucceeds()); });

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(link1, {link1}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, ELOOP);
}

// Binary is a directory.
TEST(ExecveTest, Directory) {
  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec("/tmp", {"/tmp"}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, EACCES);
}

// Pass a valid binary as a directory (extra / on the end).
TEST(ExecveTest, BinaryAsDirectory) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  std::string const path = absl::StrCat(file.path(), "/");

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(path, {path}, {}, &child, &execve_errno));
  EXPECT_EQ(execve_errno, ENOTDIR);
}

// The initial brk value is after the page at the end of the binary.
TEST(ExecveTest, BrkAfterBinary) {
  ElfBinary<64> elf = StandardElf();
  elf.UpdateOffsets();

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(CreateElfWith(elf));

  pid_t child;
  int execve_errno;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(file.path(), {file.path()}, {}, &child, &execve_errno));
  ASSERT_EQ(execve_errno, 0);

  // Ensure it made it to SIGSTOP.
  ASSERT_NO_ERRNO(WaitStopped(child));

  struct user_regs_struct regs;
  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());

  // RIP is just beyond the final syscall instruction. Rewind to execute a brk
  // syscall.
  regs.rip -= kSyscallSize;
  regs.rax = __NR_brk;
  regs.rdi = 0;
  ASSERT_THAT(ptrace(PTRACE_SETREGS, child, 0, &regs), SyscallSucceeds());

  // Resume the child, waiting for syscall entry.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child, 0, 0), SyscallSucceeds());
  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      << "status = " << status;

  // Execute the syscall.
  ASSERT_THAT(ptrace(PTRACE_SYSCALL, child, 0, 0), SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0),
              SyscallSucceedsWithValue(child));
  ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      << "status = " << status;

  ASSERT_THAT(ptrace(PTRACE_GETREGS, child, 0, &regs), SyscallSucceeds());

  // brk is after the text page.
  //
  // The kernel does brk randomization, so we can't be sure what the exact
  // address will be, but it is always beyond the final page in the binary.
  // i.e., it does not start immediately after memsz in the middle of a page.
  // Userspace may expect to use that space.
  EXPECT_GE(regs.rax, 0x41000);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
