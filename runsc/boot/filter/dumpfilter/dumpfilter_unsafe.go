// Copyright 2023 The gVisor Authors.
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

// dumpfilter dumps the seccomp-bpf program used by the Sentry.
package main

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/bpf"
)

// InstructionsToBytecode returns raw the BPF bytecode for the given program.
func InstructionsToBytecode(insns []bpf.Instruction) string {
	bytePointer := (*byte)(unsafe.Pointer(&insns[0]))
	return unsafe.String(bytePointer, len(insns)*int(unsafe.Sizeof(bpf.Instruction{})))
}
