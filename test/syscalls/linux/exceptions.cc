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

#include <signal.h>

#include "gtest/gtest.h"
#include "test/util/logging.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

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

TEST(ExceptionTest, Halt) {
  // In order to prevent the regular handler from messing with things (and
  // perhaps refaulting until some other signal occurs), we reset the handler to
  // the default action here and ensure that it dies correctly.
  struct sigaction sa = {};
  sa.sa_handler = SIG_DFL;
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGSEGV, sa));

  EXPECT_EXIT(Halt(), ::testing::KilledBySignal(SIGSEGV), "");
}

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

}  // namespace testing
}  // namespace gvisor
