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

#include <elf.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <iterator>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

std::string PrintClockId(::testing::TestParamInfo<clockid_t> info) {
  switch (info.param) {
    case CLOCK_MONOTONIC:
      return "CLOCK_MONOTONIC";
    case CLOCK_BOOTTIME:
      return "CLOCK_BOOTTIME";
    default:
      return absl::StrCat(info.param);
  }
}

class MonotonicVDSOClockTest : public ::testing::TestWithParam<clockid_t> {};

TEST_P(MonotonicVDSOClockTest, IsCorrect) {
  // The VDSO implementation of clock_gettime() uses the TSC. On KVM, sentry and
  // application TSCs can be very desynchronized; see
  // sentry/platform/kvm/kvm.vCPU.setSystemTime().
  SKIP_IF(GvisorPlatform() == Platform::kKVM);

  // Check that when we alternate readings from the clock_gettime syscall and
  // the VDSO's implementation, we observe the combined sequence as being
  // monotonic, including across a checkpoint and restore halfway through.
  struct timespec tvdso, tsys;
  absl::Time vdso_time, sys_time;
  ASSERT_THAT(syscall(SYS_clock_gettime, GetParam(), &tsys), SyscallSucceeds());
  sys_time = absl::TimeFromTimespec(tsys);
  auto save = absl::Now() + absl::Seconds(5);
  auto end = absl::InfiniteFuture();
  while (absl::Now() < end) {
    if (absl::Now() >= save) {
      MaybeSave();
      save = absl::InfiniteFuture();
      end = absl::Now() + absl::Seconds(5);
    }
    ASSERT_THAT(clock_gettime(GetParam(), &tvdso), SyscallSucceeds());
    vdso_time = absl::TimeFromTimespec(tvdso);
    EXPECT_LE(sys_time, vdso_time);
    ASSERT_THAT(syscall(SYS_clock_gettime, GetParam(), &tsys),
                SyscallSucceeds());
    sys_time = absl::TimeFromTimespec(tsys);
    EXPECT_LE(vdso_time, sys_time);
  }
}

INSTANTIATE_TEST_SUITE_P(ClockGettime, MonotonicVDSOClockTest,
                         ::testing::Values(CLOCK_MONOTONIC, CLOCK_BOOTTIME),
                         PrintClockId);

// Makes the clock_gettime system call fail with EPERM in the calling thread.
// Async-signal-safe.
void BlockClockGettimeSyscall() {
  TEST_PCHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
  struct sock_filter filter[] = {
      // A = seccomp_data.arch
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 4),
#if defined(__x86_64__)
      // if (A != AUDIT_ARCH_X86_64) goto kill
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 4),
#elif defined(__aarch64__)
      // if (A != AUDIT_ARCH_AARCH64) goto kill
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 4),
#else
#error "Unknown architecture"
#endif
      // A = seccomp_data.nr
      BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0),
      // if (A != SYS_clock_gettime) goto allow
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 1),
      // return EPERM
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      // allow: return SECCOMP_RET_ALLOW
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      // kill: return SECCOMP_RET_KILL
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  };
  struct sock_fprog prog;
  prog.len = std::size(filter);
  prog.filter = filter;
  TEST_PCHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0);
}

// Returns the address of the function `name` in the VDSO, or nullptr if there
// is none.
void* VDSOFunction(const char* name) {
  const uintptr_t base = getauxval(AT_SYSINFO_EHDR);
  if (base == 0) {
    return nullptr;
  }
  // The VDSO is mapped from its first PT_LOAD segment, at file offset 0, and
  // the whole file is mapped, so file offsets are offsets from base.
  const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
  const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(base + ehdr->e_phoff);
  const Elf64_Phdr* load = nullptr;
  for (int i = 0; i < ehdr->e_phnum && load == nullptr; i++) {
    if (phdrs[i].p_type == PT_LOAD) {
      load = &phdrs[i];
    }
  }
  if (load == nullptr || load->p_offset != 0) {
    return nullptr;
  }
  const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff);
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdrs[i].sh_type != SHT_DYNSYM) {
      continue;
    }
    const auto* syms =
        reinterpret_cast<const Elf64_Sym*>(base + shdrs[i].sh_offset);
    const char* strtab =
        reinterpret_cast<const char*>(base + shdrs[shdrs[i].sh_link].sh_offset);
    for (Elf64_Xword j = 0; j < shdrs[i].sh_size / sizeof(Elf64_Sym); j++) {
      if (syms[j].st_shndx != SHN_UNDEF &&
          strcmp(strtab + syms[j].st_name, name) == 0) {
        return reinterpret_cast<void*>(base + syms[j].st_value - load->p_vaddr);
      }
    }
  }
  return nullptr;
}

// Check that the VDSO reads the clock without making a system call.
TEST(VDSOClockTest, NoSyscall) {
  // On Linux, whether the VDSO makes a system call depends on the host's clock
  // source.
  SKIP_IF(!IsRunningOnGvisor());

  // Call the VDSO directly, since libc may not use it (e.g. static glibc before
  // 2.31).
#if defined(__x86_64__)
  constexpr char kClockGettime[] = "__vdso_clock_gettime";
#elif defined(__aarch64__)
  constexpr char kClockGettime[] = "__kernel_clock_gettime";
#else
#error "Unknown architecture"
#endif
  using ClockGettimeFn = int (*)(clockid_t, struct timespec*);
  const auto vdso_clock_gettime =
      reinterpret_cast<ClockGettimeFn>(VDSOFunction(kClockGettime));
  ASSERT_NE(vdso_clock_gettime, nullptr);

  EXPECT_THAT(InForkedProcess([vdso_clock_gettime] {
                BlockClockGettimeSyscall();
                // The VDSO makes a system call until the sandbox kernel has
                // calibrated its clocks, shortly after it starts or restores.
                for (int i = 0; i < 1000; i++) {
                  struct timespec ts;
                  // The VDSO returns -errno rather than setting errno.
                  const int ret = vdso_clock_gettime(CLOCK_MONOTONIC, &ts);
                  if (ret == 0) {
                    _exit(0);
                  }
                  TEST_CHECK(ret == -EPERM);
                  absl::SleepFor(absl::Milliseconds(10));
                }
                _exit(1);
              }),
              IsPosixErrorOkAndHolds(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
