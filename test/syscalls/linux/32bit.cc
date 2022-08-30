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

#include <string.h>
#include <sys/mman.h>

#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "test/util/memory_util.h"
#include "test/util/platform_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifdef __x86_64__

constexpr char kInt3 = '\xcc';
constexpr char kInt80[2] = {'\xcd', '\x80'};
constexpr char kSyscall[2] = {'\x0f', '\x05'};
constexpr char kSysenter[2] = {'\x0f', '\x34'};

void ExitGroup32(const char instruction[2], int code) {
  const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0));

  // Fill with INT 3 in case we execute too far.
  memset(m.ptr(), kInt3, m.len());

  // Copy in the actual instruction.
  memcpy(m.ptr(), instruction, 2);

  // We're playing *extremely* fast-and-loose with the various syscall ABIs
  // here, which we can more-or-less get away with since exit_group doesn't
  // return.
  //
  // SYSENTER expects the user stack in (%ebp) and arg6 in 0(%ebp). The kernel
  // will unconditionally dereference %ebp for arg6, so we must pass a valid
  // address or it will return EFAULT.
  //
  // SYSENTER also unconditionally returns to thread_info->sysenter_return which
  // is ostensibly a stub in the 32-bit VDSO. But a 64-bit binary doesn't have
  // the 32-bit VDSO mapped, so sysenter_return will simply be the value
  // inherited from the most recent 32-bit ancestor, or NULL if there is none.
  // As a result, return would not return from SYSENTER.
  asm volatile(
      "movl $252, %%eax\n"     // exit_group
      "movl %[code], %%ebx\n"  // code
      "movl %%edx, %%ebp\n"    // SYSENTER: user stack (use IP as a valid addr)
      "leaq -20(%%rsp), %%rsp\n"
      "movl $0x2b, 16(%%rsp)\n"  // SS = CPL3 data segment
      "movl $0,12(%%rsp)\n"      // ESP = nullptr (unused)
      "movl $0, 8(%%rsp)\n"      // EFLAGS
      "movl $0x23, 4(%%rsp)\n"   // CS = CPL3 32-bit code segment
      "movl %%edx, 0(%%rsp)\n"   // EIP
      "iretl\n"
      "int $3\n"
      :
      : [ code ] "m"(code), [ ip ] "d"(m.ptr())
      : "rax", "rbx");
}

constexpr int kExitCode = 42;

TEST(Syscall32Bit, Int80) {
  switch (PlatformSupport32Bit()) {
    case PlatformSupport::NotSupported:
      break;
    case PlatformSupport::Segfault:
      EXPECT_EXIT(ExitGroup32(kInt80, kExitCode),
                  ::testing::KilledBySignal(SIGSEGV), "");
      break;

    case PlatformSupport::Ignored:
      // Since the call is ignored, we'll hit the int3 trap.
      EXPECT_EXIT(ExitGroup32(kInt80, kExitCode),
                  ::testing::KilledBySignal(SIGTRAP), "");
      break;

    case PlatformSupport::Allowed:
      EXPECT_EXIT(ExitGroup32(kInt80, kExitCode), ::testing::ExitedWithCode(42),
                  "");
      break;
  }
}

TEST(Syscall32Bit, Sysenter) {
  if ((PlatformSupport32Bit() == PlatformSupport::Allowed ||
       PlatformSupport32Bit() == PlatformSupport::Ignored) &&
      GetCPUVendor() == CPUVendor::kAMD) {
    // SYSENTER is an illegal instruction in compatibility mode on AMD.
    EXPECT_EXIT(ExitGroup32(kSysenter, kExitCode),
                ::testing::KilledBySignal(SIGILL), "");
    return;
  }

  switch (PlatformSupport32Bit()) {
    case PlatformSupport::NotSupported:
      break;

    case PlatformSupport::Segfault:
      EXPECT_EXIT(ExitGroup32(kSysenter, kExitCode),
                  ::testing::KilledBySignal(SIGSEGV), "");
      break;

    case PlatformSupport::Ignored:
      // See above, except expected code is SIGSEGV.
      EXPECT_EXIT(ExitGroup32(kSysenter, kExitCode),
                  ::testing::KilledBySignal(SIGSEGV), "");
      break;

    case PlatformSupport::Allowed:
      EXPECT_EXIT(ExitGroup32(kSysenter, kExitCode),
                  ::testing::ExitedWithCode(42), "");
      break;
  }
}

class KilledByOneOfSignals {
 public:
  KilledByOneOfSignals(int signum1, int signum2)
      : signum1_(signum1), signum2_(signum2) {}
  bool operator()(int exit_status) const {
    if (!WIFSIGNALED(exit_status)) return false;
    int sig = WTERMSIG(exit_status);
    return sig == signum1_ || sig == signum2_;
  }

 private:
  const int signum1_, signum2_;
};

TEST(Syscall32Bit, Syscall) {
  if ((PlatformSupport32Bit() == PlatformSupport::Allowed ||
       PlatformSupport32Bit() == PlatformSupport::Ignored) &&
      GetCPUVendor() == CPUVendor::kIntel) {
    // SYSCALL is an illegal instruction in compatibility mode on Intel.
    EXPECT_EXIT(ExitGroup32(kSyscall, kExitCode),
                ::testing::KilledBySignal(SIGILL), "");
    return;
  }

  switch (PlatformSupport32Bit()) {
    case PlatformSupport::NotSupported:
      break;

    case PlatformSupport::Segfault:
      EXPECT_EXIT(ExitGroup32(kSyscall, kExitCode),
                  ::testing::KilledBySignal(SIGSEGV), "");
      break;

    case PlatformSupport::Ignored:
      // NOTE(b/241819530): SIGSEGV was returned due to a kernel bug that has
      // been fixed recently. Let's continue accept SIGSEGV while bad kernels
      // are running in prod.
      EXPECT_EXIT(ExitGroup32(kSyscall, kExitCode),
                  KilledByOneOfSignals(SIGTRAP, SIGSEGV), "");
      break;

    case PlatformSupport::Allowed:
      EXPECT_EXIT(ExitGroup32(kSyscall, kExitCode),
                  ::testing::ExitedWithCode(42), "");
      break;
  }
}

// Far call code called below.
//
// Input stack layout:
//
// %esp+12 lcall segment
// %esp+8  lcall address offset
// %esp+0  return address
//
// The lcall will enter compatibility mode and jump to the call address (the
// address of the lret). The lret will return to 64-bit mode at the retq, which
// will return to the external caller of this function.
//
// Since this enters compatibility mode, it must be mapped in a 32-bit region of
// address space and have a 32-bit stack pointer.
constexpr char kFarCall[] = {
    '\x67', '\xff', '\x5c', '\x24', '\x08',  // lcall *8(%esp)
    '\xc3',                                  // retq
    '\xcb',                                  // lret
};

void FarCall32() {
  const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      Mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0));

  // Fill with INT 3 in case we execute too far.
  memset(m.ptr(), kInt3, m.len());

  // 32-bit code.
  memcpy(m.ptr(), kFarCall, sizeof(kFarCall));

  // Use the end of the code page as its stack.
  uintptr_t stack = m.endaddr();

  uintptr_t lcall = m.addr();
  uintptr_t lret = m.addr() + sizeof(kFarCall) - 1;

  // N.B. We must save and restore RSP manually. GCC can do so automatically
  // with an "rsp" clobber, but clang cannot.
  asm volatile(
      // Place the address of lret (%edx) and the 32-bit code segment (0x23) on
      // the 32-bit stack for lcall.
      "subl $0x8, %%ecx\n"
      "movl $0x23, 4(%%ecx)\n"
      "movl %%edx, 0(%%ecx)\n"

      // Save the current stack and switch to 32-bit stack.
      "pushq %%rbp\n"
      "movq %%rsp, %%rbp\n"
      "movq %%rcx, %%rsp\n"

      // Run the lcall code.
      "callq *%%rbx\n"

      // Restore the old stack.
      "leaveq\n"
      : "+c"(stack)
      : "b"(lcall), "d"(lret));
}

TEST(Call32Bit, Disallowed) {
  switch (PlatformSupport32Bit()) {
    case PlatformSupport::NotSupported:
      break;

    case PlatformSupport::Segfault:
      EXPECT_EXIT(FarCall32(), ::testing::KilledBySignal(SIGSEGV), "");
      break;

    case PlatformSupport::Ignored:
      ABSL_FALLTHROUGH_INTENDED;
    case PlatformSupport::Allowed:
      // Shouldn't crash.
      FarCall32();
  }
}

#endif

}  // namespace

}  // namespace testing
}  // namespace gvisor
