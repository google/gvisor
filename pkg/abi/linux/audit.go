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

package linux

// Audit numbers identify different system call APIs, from <uapi/linux/audit.h>
const (
	// AUDIT_ARCH_X86_64 identifies AMD64.
	AUDIT_ARCH_X86_64 = 0xc000003e
	// AUDIT_ARCH_AARCH64 identifies ARM64.
	AUDIT_ARCH_AARCH64 = 0xc00000b7
	// AUDIT_ARCH_LOONGARCH64 identifies LoongArch64.
	// EM_LOONGARCH (258) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
	AUDIT_ARCH_LOONGARCH64 = 0xc0000102
)
