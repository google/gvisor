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

package slimvm

// SlimVM exit reasons (matching SLIMVM_RET_* in slimvm kernel module).
const (
	_SLIMVM_EXIT_EXCEPTION       = 0x1
	_SLIMVM_EXIT_IO              = 0x2
	_SLIMVM_EXIT_HYPERCALL       = 0x3
	_SLIMVM_EXIT_DEBUG           = 0x4
	_SLIMVM_EXIT_HLT             = 0x5
	_SLIMVM_EXIT_MMIO            = 0x6
	_SLIMVM_EXIT_IRQ_WINDOW_OPEN = 0x7
	_SLIMVM_EXIT_SHUTDOWN        = 0x8
	_SLIMVM_EXIT_FAIL_ENTRY      = 0x9
	_SLIMVM_EXIT_INTR            = 0xa
	_SLIMVM_EXIT_INTERNAL_ERROR  = 0x11
	_SLIMVM_EXIT_MSR_WRITE       = 0x20
)

// SlimVM limits.
const (
	_SLIMVM_NR_VCPUS         = 0x800
	_SLIMVM_NR_INTERRUPTS    = 0x100
	_SLIMVM_NR_CPUID_ENTRIES = 0x100
)
