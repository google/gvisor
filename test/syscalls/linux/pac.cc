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

#include <stdint.h>

#include <array>

#include "gtest/gtest.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifdef __aarch64__

// PACIA1716, PACIB1716, AUTIA1716 and AUTIB1716 are in the HINT space, so they
// execute as NOPs when pointer authentication is not available or enabled.

uint64_t PacIA(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #8" : "+r"(x17) : "r"(x16));  // PACIA1716
  return x17;
}

uint64_t PacIB(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #10" : "+r"(x17) : "r"(x16));  // PACIB1716
  return x17;
}

uint64_t AutIA(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #12" : "+r"(x17) : "r"(x16));  // AUTIA1716
  return x17;
}

uint64_t AutIB(uint64_t ptr, uint64_t modifier) {
  register uint64_t x17 asm("x17") = ptr;
  register uint64_t x16 asm("x16") = modifier;
  asm volatile("hint #14" : "+r"(x17) : "r"(x16));  // AUTIB1716
  return x17;
}

// PACDA, PACDB and PACGA are not HINT instructions; only use them once PAC is
// known to be available. They are encoded directly so the assembler does not
// need to accept Armv8.3 instructions.

uint64_t PacDA(uint64_t ptr, uint64_t modifier) {
  register uint64_t x0 asm("x0") = ptr;
  register uint64_t x1 asm("x1") = modifier;
  asm volatile(".inst 0xdac10820" : "+r"(x0) : "r"(x1));  // PACDA x0, x1
  return x0;
}

uint64_t PacDB(uint64_t ptr, uint64_t modifier) {
  register uint64_t x0 asm("x0") = ptr;
  register uint64_t x1 asm("x1") = modifier;
  asm volatile(".inst 0xdac10c20" : "+r"(x0) : "r"(x1));  // PACDB x0, x1
  return x0;
}

uint64_t PacGA(uint64_t value, uint64_t modifier) {
  register uint64_t x0 asm("x0");
  register uint64_t x1 asm("x1") = value;
  register uint64_t x2 asm("x2") = modifier;
  asm volatile(".inst 0x9ac23020"
               : "=r"(x0)
               : "r"(x1), "r"(x2));  // PACGA x0, x1, x2
  return x0;
}

constexpr std::array<uint64_t, 8> kPointers = {
    0x0000aaaa00001000, 0x0000aaaa00002000, 0x0000ffff12345678,
    0x0000123456789abc, 0x0000400000000000, 0x0000000000401000,
    0x00007fffdeadbeef, 0x0000555555554000,
};
constexpr uint64_t kModifier = 0x0000ffffcafe0000;

// PacEnabled returns whether signing changes a pointer. A single signature can
// be zero by chance, so any of several pointers changing counts.
bool PacEnabled() {
  for (uint64_t ptr : kPointers) {
    if (PacIA(ptr, kModifier) != ptr) {
      return true;
    }
  }
  return false;
}

struct Signatures {
  std::array<uint64_t, kPointers.size()> ia, ib, da, db, ga;
};

// Sign signs each of kPointers with the IA, IB, DA and DB keys, and computes
// a PACGA code over it with the GA key, all with kModifier. Signing computes a
// code from the pointer, the modifier and the key, and stores it in the unused
// high bits of the pointer. It is deterministic, so signing the same pointers
// again gives the same results exactly when the keys are unchanged.
Signatures Sign() {
  Signatures s;
  for (size_t i = 0; i < kPointers.size(); i++) {
    s.ia[i] = PacIA(kPointers[i], kModifier);
    s.ib[i] = PacIB(kPointers[i], kModifier);
    s.da[i] = PacDA(kPointers[i], kModifier);
    s.db[i] = PacDB(kPointers[i], kModifier);
    s.ga[i] = PacGA(kPointers[i], kModifier);
  }
  return s;
}

// Pointer authentication keys are per-process state. Pointers signed before a
// checkpoint must still authenticate after restore.
TEST(PointerAuthTest, KeysSurviveSaveRestore) {
  SKIP_IF(IsRunningOnGvisor() && GvisorPlatform() != Platform::kSystrap);
  SKIP_IF(!PacEnabled());

  const Signatures before = Sign();
  for (int i = 0; i < 3; i++) {
    MaybeSave();
  }
  const Signatures after = Sign();

  for (size_t i = 0; i < kPointers.size(); i++) {
    EXPECT_EQ(after.ia[i], before.ia[i]) << "APIA key changed";
    EXPECT_EQ(after.ib[i], before.ib[i]) << "APIB key changed";
    EXPECT_EQ(after.da[i], before.da[i]) << "APDA key changed";
    EXPECT_EQ(after.db[i], before.db[i]) << "APDB key changed";
    EXPECT_EQ(after.ga[i], before.ga[i]) << "APGA key changed";
  }
  // Authenticate the pointers signed before the checkpoint, as returning
  // through a signed return address does. Authentication recomputes the code
  // with the current key; if it matches, the code is removed and the original
  // pointer is returned. If it does not match, the CPU either faults (with
  // FEAT_FPAC) or returns a pointer with error bits set, so the result no
  // longer equals the original pointer.
  for (size_t i = 0; i < kPointers.size(); i++) {
    EXPECT_EQ(AutIA(before.ia[i], kModifier), kPointers[i]);
    EXPECT_EQ(AutIB(before.ib[i], kModifier), kPointers[i]);
  }
}

#else

TEST(PointerAuthTest, KeysSurviveSaveRestore) {
  GTEST_SKIP() << "pointer authentication is arm64-only";
}

#endif  // __aarch64__

}  // namespace

}  // namespace testing
}  // namespace gvisor
