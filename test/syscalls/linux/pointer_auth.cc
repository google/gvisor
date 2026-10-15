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

#include <array>
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

constexpr std::array<uint64_t, 8> kPointers = {
    0x0000aaaa00001000, 0x0000aaaa00002000, 0x0000ffff12345678,
    0x0000123456789abc, 0x0000400000000000, 0x0000000000401000,
    0x00007fffdeadbeef, 0x0000555555554000,
};
constexpr uint64_t kModifier = 0x0000ffffcafe0000;

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

// PACDA, PACDB and PACGA are not HINT instructions; only use them after their
// respective pointer authentication feature is known to be available.
uint64_t SignDA(uint64_t ptr, uint64_t modifier) {
  register uint64_t x0 asm("x0") = ptr;
  register uint64_t x1 asm("x1") = modifier;
  asm volatile(".inst 0xdac10820" : "+r"(x0) : "r"(x1));  // PACDA x0, x1
  return x0;
}

uint64_t SignDB(uint64_t ptr, uint64_t modifier) {
  register uint64_t x0 asm("x0") = ptr;
  register uint64_t x1 asm("x1") = modifier;
  asm volatile(".inst 0xdac10c20" : "+r"(x0) : "r"(x1));  // PACDB x0, x1
  return x0;
}

uint64_t SignGA(uint64_t value, uint64_t modifier) {
  register uint64_t x0 asm("x0");
  register uint64_t x1 asm("x1") = value;
  register uint64_t x2 asm("x2") = modifier;
  asm volatile(".inst 0x9ac23020"
               : "=r"(x0)
               : "r"(x1), "r"(x2));  // PACGA x0, x1, x2
  return x0;
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

// HasFeatPACG returns true if the CPU implements generic pointer
// authentication.
bool HasFeatPACG() {
  PosixErrorOr<int> status = InForkedProcess(
      [] { static_cast<void>(SignGA(kPointers[0], kModifier)); });
  return status.ok() && status.ValueOrDie() == 0;
}

// PACEnabled returns whether address signing changes a pointer. A single
// signature can be zero by chance, so any of several pointers changing counts.
bool PACEnabled() {
  for (uint64_t ptr : kPointers) {
    if (SignIA(ptr, kModifier) != ptr) {
      return true;
    }
  }
  return false;
}

struct Signatures {
  std::array<uint64_t, kPointers.size()> ia, ib, da, db, ga;
};

// Sign signs pointers with every address key and, when available, the generic
// key. Signing is deterministic, so matching results require unchanged keys.
Signatures Sign(bool has_generic) {
  Signatures signatures = {};
  for (size_t i = 0; i < kPointers.size(); ++i) {
    signatures.ia[i] = SignIA(kPointers[i], kModifier);
    signatures.ib[i] = SignIB(kPointers[i], kModifier);
    signatures.da[i] = SignDA(kPointers[i], kModifier);
    signatures.db[i] = SignDB(kPointers[i], kModifier);
    if (has_generic) {
      signatures.ga[i] = SignGA(kPointers[i], kModifier);
    }
  }
  return signatures;
}

// SignSaveAuthenticate signs pointers, saves and restores, and checks that all
// keys remain unchanged and signed pointers still authenticate. It runs in a
// subprocess because failed authentication may fault with FEAT_FPAC.
void SignSaveAuthenticate(bool has_generic) {
  const Signatures before = Sign(has_generic);
  MaybeSave();
  const Signatures after = Sign(has_generic);
  for (size_t i = 0; i < kPointers.size(); ++i) {
    TEST_CHECK_MSG(after.ia[i] == before.ia[i], "APIA key changed");
    TEST_CHECK_MSG(after.ib[i] == before.ib[i], "APIB key changed");
    TEST_CHECK_MSG(after.da[i] == before.da[i], "APDA key changed");
    TEST_CHECK_MSG(after.db[i] == before.db[i], "APDB key changed");
    if (has_generic) {
      TEST_CHECK_MSG(after.ga[i] == before.ga[i], "APGA key changed");
    }
    TEST_CHECK_MSG(AuthIA(before.ia[i], kModifier) == kPointers[i],
                   "IA-signed pointer did not authenticate");
    TEST_CHECK_MSG(AuthIB(before.ib[i], kModifier) == kPointers[i],
                   "IB-signed pointer did not authenticate");
  }
}

// SaveWithSignedReturnAddress saves and restores while a return address is
// signed on the stack. Should be run in a subprocess as this will crash the
// process if it fails.
void SaveWithSignedReturnAddress() { CallWithSignedReturnAddress(&MaybeSave); }

TEST(PointerAuthTest, SignedPointerSurvivesSaveRestore) {
  SKIP_IF(!PlatformSupported() || !HasFeatPAuth());
  SKIP_IF(
      !HostKernelSupported(ASSERT_NO_ERRNO_AND_VALUE(GetHostKernelVersion())));
  SKIP_IF(!PACEnabled());

  // A bit of a hack: look up the save configuration now so that MaybeSave is
  // async-signal-safe in a subprocess.
  IsRunningWithSaveRestore();

  const bool has_generic = HasFeatPACG();
  EXPECT_THAT(
      InForkedProcess([has_generic] { SignSaveAuthenticate(has_generic); }),
      IsPosixErrorOkAndHolds(0));
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
