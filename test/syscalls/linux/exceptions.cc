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

#include <signal.h>

#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/platform_util.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

#if defined(__x86_64__)
// Default value for the x87 FPU control word. See Intel SDM Vol 1, Ch 8.1.5
// "x87 FPU Control Word".
constexpr uint16_t kX87ControlWordDefault = 0x37f;

// Mask for the divide-by-zero exception.
constexpr uint16_t kX87ControlWordDiv0Mask = 1 << 2;

// Default value for the SSE control register (MXCSR). See Intel SDM Vol 1, Ch
// 11.6.4 "Initialization of SSE/SSE3 Extensions".
constexpr uint32_t kMXCSRDefault = 0x1f80;

// Mask for the divide-by-zero exception.
constexpr uint32_t kMXCSRDiv0Mask = 1 << 9;

// Flag for a pending divide-by-zero exception.
constexpr uint32_t kMXCSRDiv0Flag = 1 << 2;

void inline Halt() { asm("hlt\r\n"); }

void inline SetAlignmentCheck() {
  asm("subq $128, %%rsp\r\n"  // Avoid potential red zone clobber
      "pushf\r\n"
      "pop %%rax\r\n"
      "or $0x40000, %%rax\r\n"
      "push %%rax\r\n"
      "popf\r\n"
      "addq $128, %%rsp\r\n"
      :
      :
      : "ax");
}

void inline ClearAlignmentCheck() {
  asm("subq $128, %%rsp\r\n"  // Avoid potential red zone clobber
      "pushf\r\n"
      "pop %%rax\r\n"
      "mov $0x40000, %%rbx\r\n"
      "not %%rbx\r\n"
      "and %%rbx, %%rax\r\n"
      "push %%rax\r\n"
      "popf\r\n"
      "addq $128, %%rsp\r\n"
      :
      :
      : "ax", "bx");
}

void inline Int3Normal() { asm(".byte 0xcd, 0x03\r\n"); }

void inline Int3Compact() { asm(".byte 0xcc\r\n"); }

void InIOHelper(int width, int value) {
  EXPECT_EXIT(
      {
        switch (width) {
          case 1:
            asm volatile("inb %%dx, %%al" ::"d"(value) : "%eax");
            break;
          case 2:
            asm volatile("inw %%dx, %%ax" ::"d"(value) : "%eax");
            break;
          case 4:
            asm volatile("inl %%dx, %%eax" ::"d"(value) : "%eax");
            break;
          default:
            FAIL() << "invalid input width, only 1, 2 or 4 is allowed";
        }
      },
      ::testing::KilledBySignal(SIGSEGV), "");
}
#elif defined(__aarch64__)
void inline Halt() { asm("hlt #0\r\n"); }
#endif

TEST(ExceptionTest, Halt) {
  // In order to prevent the regular handler from messing with things (and
  // perhaps refaulting until some other signal occurs), we reset the handler to
  // the default action here and ensure that it dies correctly.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGSEGV, sa));

#if defined(__x86_64__)
  EXPECT_EXIT(Halt(), ::testing::KilledBySignal(SIGSEGV), "");
#elif defined(__aarch64__)
  EXPECT_EXIT(Halt(), ::testing::KilledBySignal(SIGILL), "");
#endif
}

#if defined(__x86_64__)
TEST(ExceptionTest, DivideByZero) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGFPE, sa));

  EXPECT_EXIT(
      {
        uint32_t remainder;
        uint32_t quotient;
        uint32_t divisor = 0;
        uint64_t value = 1;
        asm("divl 0(%2)\r\n"
            : "=d"(remainder), "=a"(quotient)
            : "r"(&divisor), "d"(value >> 32), "a"(value));
        TEST_CHECK(quotient > 0);  // Force dependency.
      },
      ::testing::KilledBySignal(SIGFPE), "");
}

// By default, x87 exceptions are masked and simply return a default value.
TEST(ExceptionTest, X87DivideByZeroMasked) {
  int32_t quotient;
  int32_t value = 1;
  int32_t divisor = 0;
  asm("fildl %[value]\r\n"
      "fidivl %[divisor]\r\n"
      "fistpl %[quotient]\r\n"
      : [ quotient ] "=m"(quotient)
      : [ value ] "m"(value), [ divisor ] "m"(divisor));

  EXPECT_EQ(quotient, INT32_MIN);
}

// When unmasked, division by zero raises SIGFPE.
TEST(ExceptionTest, X87DivideByZeroUnmasked) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGFPE, sa));

  EXPECT_EXIT(
      {
        // Clear the divide by zero exception mask.
        constexpr uint16_t kControlWord =
            kX87ControlWordDefault & ~kX87ControlWordDiv0Mask;

        int32_t quotient;
        int32_t value = 1;
        int32_t divisor = 0;
        asm volatile(
            "fldcw %[cw]\r\n"
            "fildl %[value]\r\n"
            "fidivl %[divisor]\r\n"
            "fistpl %[quotient]\r\n"
            : [ quotient ] "=m"(quotient)
            : [ cw ] "m"(kControlWord), [ value ] "m"(value),
              [ divisor ] "m"(divisor));
      },
      ::testing::KilledBySignal(SIGFPE), "");
}

// Pending exceptions in the x87 status register are not clobbered by syscalls.
TEST(ExceptionTest, X87StatusClobber) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGFPE, sa));

  EXPECT_EXIT(
      {
        // Clear the divide by zero exception mask.
        constexpr uint16_t kControlWord =
            kX87ControlWordDefault & ~kX87ControlWordDiv0Mask;

        int32_t quotient;
        int32_t value = 1;
        int32_t divisor = 0;
        asm volatile(
            "fildl %[value]\r\n"
            "fidivl %[divisor]\r\n"
            // Exception is masked, so it does not occur here.
            "fistpl %[quotient]\r\n"

            // SYS_getpid placed in rax by constraint.
            "syscall\r\n"

            // Unmask exception. The syscall didn't clobber the pending
            // exception, so now it can be raised.
            //
            // N.B. "a floating-point exception will be generated upon execution
            // of the *next* floating-point instruction".
            "fldcw %[cw]\r\n"
            "fwait\r\n"
            : [ quotient ] "=m"(quotient)
            : [ value ] "m"(value), [ divisor ] "m"(divisor), "a"(SYS_getpid),
              [ cw ] "m"(kControlWord)
            : "rcx", "r11");
      },
      ::testing::KilledBySignal(SIGFPE), "");
}

// By default, SSE exceptions are masked and simply return a default value.
TEST(ExceptionTest, SSEDivideByZeroMasked) {
  uint32_t status;
  int32_t quotient;
  int32_t value = 1;
  int32_t divisor = 0;
  asm("cvtsi2ssl %[value], %%xmm0\r\n"
      "cvtsi2ssl %[divisor], %%xmm1\r\n"
      "divss %%xmm1, %%xmm0\r\n"
      "cvtss2sil %%xmm0, %[quotient]\r\n"
      : [ quotient ] "=r"(quotient), [ status ] "=r"(status)
      : [ value ] "r"(value), [ divisor ] "r"(divisor)
      : "xmm0", "xmm1");

  EXPECT_EQ(quotient, INT32_MIN);
}

// When unmasked, division by zero raises SIGFPE.
TEST(ExceptionTest, SSEDivideByZeroUnmasked) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGFPE, sa));

  EXPECT_EXIT(
      {
        // Clear the divide by zero exception mask.
        constexpr uint32_t kMXCSR = kMXCSRDefault & ~kMXCSRDiv0Mask;

        int32_t quotient;
        int32_t value = 1;
        int32_t divisor = 0;
        asm volatile(
            "ldmxcsr %[mxcsr]\r\n"
            "cvtsi2ssl %[value], %%xmm0\r\n"
            "cvtsi2ssl %[divisor], %%xmm1\r\n"
            "divss %%xmm1, %%xmm0\r\n"
            "cvtss2sil %%xmm0, %[quotient]\r\n"
            : [ quotient ] "=r"(quotient)
            : [ mxcsr ] "m"(kMXCSR), [ value ] "r"(value),
              [ divisor ] "r"(divisor)
            : "xmm0", "xmm1");
      },
      ::testing::KilledBySignal(SIGFPE), "");
}

// Pending exceptions in the SSE status register are not clobbered by syscalls.
TEST(ExceptionTest, SSEStatusClobber) {
  uint32_t mxcsr;
  int32_t quotient;
  int32_t value = 1;
  int32_t divisor = 0;
  asm("cvtsi2ssl %[value], %%xmm0\r\n"
      "cvtsi2ssl %[divisor], %%xmm1\r\n"
      "divss %%xmm1, %%xmm0\r\n"
      // Exception is masked, so it does not occur here.
      "cvtss2sil %%xmm0, %[quotient]\r\n"

      // SYS_getpid placed in rax by constraint.
      "syscall\r\n"

      // Intel SDM Vol 1, Ch 10.2.3.1 "SIMD Floating-Point Mask and Flag Bits":
      // "If LDMXCSR or FXRSTOR clears a mask bit and sets the corresponding
      // exception flag bit, a SIMD floating-point exception will not be
      // generated as a result of this change. The unmasked exception will be
      // generated only upon the execution of the next SSE/SSE2/SSE3 instruction
      // that detects the unmasked exception condition."
      //
      // Though ambiguous, empirical evidence indicates that this means that
      // exception flags set in the status register will never cause an
      // exception to be raised; only a new exception condition will do so.
      //
      // Thus here we just check for the flag itself rather than trying to raise
      // the exception.
      "stmxcsr %[mxcsr]\r\n"
      : [ quotient ] "=r"(quotient), [ mxcsr ] "+m"(mxcsr)
      : [ value ] "r"(value), [ divisor ] "r"(divisor), "a"(SYS_getpid)
      : "xmm0", "xmm1", "rcx", "r11");

  EXPECT_TRUE(mxcsr & kMXCSRDiv0Flag);
}

TEST(ExceptionTest, IOAccessFault) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGSEGV, sa));

  InIOHelper(1, 0x0);
  InIOHelper(2, 0x7);
  InIOHelper(4, 0x6);
  InIOHelper(1, 0xffff);
  InIOHelper(2, 0xffff);
  InIOHelper(4, 0xfffd);
}

TEST(ExceptionTest, Alignment) {
  SetAlignmentCheck();
  ClearAlignmentCheck();
}

TEST(ExceptionTest, AlignmentHalt) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGSEGV, sa));

  // Reported upstream. We need to ensure that bad flags are cleared even in
  // fault paths. Set the alignment flag and then generate an exception.
  EXPECT_EXIT(
      {
        SetAlignmentCheck();
        Halt();
      },
      ::testing::KilledBySignal(SIGSEGV), "");
}

TEST(ExceptionTest, AlignmentCheck) {
  SKIP_IF(PlatformSupportAlignmentCheck() != PlatformSupport::Allowed);

  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGBUS, sa));

  EXPECT_EXIT(
      {
        char array[16];
        SetAlignmentCheck();
        for (int i = 0; i < 8; i++) {
          // At least 7/8 offsets will be unaligned here.
          uint64_t* ptr = reinterpret_cast<uint64_t*>(&array[i]);
          asm("mov %0, 0(%0)\r\n" : : "r"(ptr) : "ax");
        }
      },
      ::testing::KilledBySignal(SIGBUS), "");
}

TEST(ExceptionTest, Int3Normal) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGTRAP, sa));

  EXPECT_EXIT(Int3Normal(), ::testing::KilledBySignal(SIGTRAP), "");
}

TEST(ExceptionTest, Int3Compact) {
  // See above.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGTRAP, sa));

  EXPECT_EXIT(Int3Compact(), ::testing::KilledBySignal(SIGTRAP), "");
}
#endif

}  // namespace testing
}  // namespace gvisor
