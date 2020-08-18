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

#include <sys/syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {
#ifdef __x86_64__
// get_kernel_syms is not supported in Linux > 2.6, and not implemented in
// gVisor.
constexpr uint32_t kNotImplementedSyscall = SYS_get_kernel_syms;
#elif __aarch64__
// Use the last of arch_specific_syscalls which are not implemented on arm64.
constexpr uint32_t kNotImplementedSyscall = __NR_arch_specific_syscall + 15;
#endif

TEST(BadSyscallTest, NotImplemented) {
  EXPECT_THAT(syscall(kNotImplementedSyscall), SyscallFailsWithErrno(ENOSYS));
}

TEST(BadSyscallTest, NegativeOne) {
  EXPECT_THAT(syscall(-1), SyscallFailsWithErrno(ENOSYS));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
