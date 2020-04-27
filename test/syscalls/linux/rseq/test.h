// Copyright 2019 The gVisor Authors.
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

#ifndef GVISOR_TEST_SYSCALLS_LINUX_RSEQ_TEST_H_
#define GVISOR_TEST_SYSCALLS_LINUX_RSEQ_TEST_H_

namespace gvisor {
namespace testing {

// Test cases supported by rseq binary.

inline constexpr char kRseqTestUnaligned[] = "unaligned";
inline constexpr char kRseqTestRegister[] = "register";
inline constexpr char kRseqTestDoubleRegister[] = "double-register";
inline constexpr char kRseqTestRegisterUnregister[] = "register-unregister";
inline constexpr char kRseqTestUnregisterDifferentPtr[] =
    "unregister-different-ptr";
inline constexpr char kRseqTestUnregisterDifferentSignature[] =
    "unregister-different-signature";
inline constexpr char kRseqTestCPU[] = "cpu";
inline constexpr char kRseqTestAbort[] = "abort";
inline constexpr char kRseqTestAbortBefore[] = "abort-before";
inline constexpr char kRseqTestAbortSignature[] = "abort-signature";
inline constexpr char kRseqTestAbortPreCommit[] = "abort-precommit";
inline constexpr char kRseqTestAbortClearsCS[] = "abort-clears-cs";
inline constexpr char kRseqTestInvalidAbortClearsCS[] =
    "invalid-abort-clears-cs";

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_LINUX_RSEQ_TEST_H_
