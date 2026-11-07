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

//go:build arm64
// +build arm64

package platform

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/usermem"
)

// TryCPUIDEmulate checks for an MRS of an ID register, arm64's equivalent of
// CPUID, and performs emulation.
//
// Linux emulates these reads for applications, which trap as undefined
// instructions before Armv8.4 and as trapped MRS instructions after. The
// instruction is read from memory, so either trap works.
func TryCPUIDEmulate(ctx context.Context, mm MemoryManager, ac *arch.Context64) bool {
	s := ac.StateData()
	var inst [4]byte
	tasklessCtx := emulationContext{
		taskWrapper: taskWrapper{ctx},
	}
	if _, err := mm.CopyIn(&tasklessCtx, hostarch.Addr(s.Regs.Pc), inst[:], usermem.IOOpts{
		IgnorePermissions: true,
	}); err != nil {
		return false
	}
	rt, value, ok := cpuid.FromContext(ctx).EmulateIDRegisterRead(binary.LittleEndian.Uint32(inst[:]))
	if !ok {
		return false
	}
	if rt != 31 { // Register 31 is XZR here, which discards the value.
		s.Regs.Regs[rt] = value
	}
	s.Regs.Pc += uint64(len(inst))
	return true
}
