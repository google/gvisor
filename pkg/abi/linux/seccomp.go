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

package linux

// Seccomp constants taken from <linux/seccomp.h>.
const (
	SECCOMP_MODE_NONE   = 0
	SECCOMP_MODE_FILTER = 2

	SECCOMP_RET_KILL  = 0x00000000
	SECCOMP_RET_TRAP  = 0x00030000
	SECCOMP_RET_ERRNO = 0x00050000
	SECCOMP_RET_TRACE = 0x7ff00000
	SECCOMP_RET_ALLOW = 0x7fff0000

	SECCOMP_RET_ACTION = 0x7fff0000
	SECCOMP_RET_DATA   = 0x0000ffff

	SECCOMP_SET_MODE_FILTER   = 1
	SECCOMP_FILTER_FLAG_TSYNC = 1
)

const (
	// AUDIT_ARCH_X86_64 is taken from <linux/audit.h>.
	AUDIT_ARCH_X86_64 = 0xc000003e
)
