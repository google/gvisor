// Copyright 2026 The gVisor Authors.
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

// Tests for ARM64 pointer authentication (FEAT_PAuth).
// Ensures that applications using PAC work properly in gVisor.

#include <stdint.h>

#include <string>

#include "gtest/gtest.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

// CallWithSignedReturnAddress calls fn with its own return address signed on
// the stack.
extern "C" void CallWithSignedReturnAddress(void (*fn)());
asm(R"(
    .text
    .p2align 2
    .globl CallWithSignedReturnAddress
    .type CallWithSignedReturnAddress, %function
CallWithSignedReturnAddress:
    hint #25                    // PACIASP
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    blr x0
    ldp x29, x30, [sp], #16
    hint #29                    // AUTIASP
    ret
    .size CallWithSignedReturnAddress, .-CallWithSignedReturnAddress
)");

namespace gvisor {
namespace testing {

namespace {

// An arbitrary user pointer.
constexpr uint64_t kPointer = 0x0000aaaa12345678;
constexpr uint64_t kModifier = 0x1234;

uint64_t SignIA(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #8" : "+r"(x17) : "r"(x16));  // PACIA1716
  return x17;
}

uint64_t AuthIA(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #12" : "+r"(x17) : "r"(x16));  // AUTIA1716
  return x17;
}

uint64_t SignIB(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #10" : "+r"(x17) : "r"(x16));  // PACIB1716
  return x17;
}

uint64_t AuthIB(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #14" : "+r"(x17) : "r"(x16));  // AUTIB1716
  return x17;
}

// PlatformSupported returns true on platforms that currently have working PAC.
bool PlatformSupported() {
  const std::string platform = GvisorPlatform();
  return platform == Platform::kNative || platform == Platform::kSystrap ||
         platform == Platform::kKVM;
}

// HostKernelSupported returns false for old host kernels that should not be
// tested with PAC.
bool HostKernelSupported(const KernelVersion& version) {
  return IsRunningOnGvisor() &&
         (version.major > 5 || (version.major == 5 && version.minor >= 13));
}

// HasFeatPAuth returns true if the CPU implements FEAT_PAuth.
bool HasFeatPAuth() {
  PosixErrorOr<int> status = InForkedProcess([] {
    asm volatile(".inst 0xdac143e0" ::: "x0");  // XPACI X0
  });
  return status.ok() && status.ValueOrDie() == 0;
}

// SignSaveAuthenticate signs pointers, saves and restores, and checks that the
// pointers still authenticate. Should be run in a subprocess as this will crash
// the process if it fails.
void SignSaveAuthenticate() {
  const uint64_t ia = SignIA(kPointer, kModifier);
  const uint64_t ib = SignIB(kPointer, kModifier);
  MaybeSave();
  TEST_CHECK_MSG(AuthIA(ia, kModifier) == kPointer,
                 "IA-signed pointer did not authenticate");
  TEST_CHECK_MSG(AuthIB(ib, kModifier) == kPointer,
                 "IB-signed pointer did not authenticate");
}

// SaveWithSignedReturnAddress saves and restores while a return address is
// signed on the stack. Should be run in a subprocess as this will crash the
// process if it fails.
void SaveWithSignedReturnAddress() { CallWithSignedReturnAddress(&MaybeSave); }

TEST(PointerAuthTest, SignedPointerSurvivesSaveRestore) {
  SKIP_IF(!PlatformSupported() || !HasFeatPAuth());
  SKIP_IF(
      !HostKernelSupported(ASSERT_NO_ERRNO_AND_VALUE(GetHostKernelVersion())));

  // A bit of a hack: look up the save configuration now so that MaybeSave is
  // async-signal-safe in a subprocess.
  IsRunningWithSaveRestore();

  EXPECT_THAT(InForkedProcess(SignSaveAuthenticate), IsPosixErrorOkAndHolds(0));
}

TEST(PointerAuthTest, SignedReturnAddressSurvivesSaveRestore) {
  SKIP_IF(!PlatformSupported() || !HasFeatPAuth());
  SKIP_IF(
      !HostKernelSupported(ASSERT_NO_ERRNO_AND_VALUE(GetHostKernelVersion())));

  IsRunningWithSaveRestore();

  EXPECT_THAT(InForkedProcess(SaveWithSignedReturnAddress),
              IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
