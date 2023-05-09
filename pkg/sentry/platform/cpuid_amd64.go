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

//go:build amd64
// +build amd64

package platform

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/usermem"
)

// taskWrapper wraps a context.Context.
type taskWrapper struct {
	context.Context
}

// emulationContext is used for emulation.
//
// It wraps an existing context but prioritizes resolution via context.NoTask,
// since the task state should not be modified during emulation. However, we
// allow logging and other operations to be directed to the correct task.
type emulationContext struct {
	taskWrapper
	context.NoTask
}

// TryCPUIDEmulate checks for a CPUID instruction and performs emulation.
func TryCPUIDEmulate(ctx context.Context, mm MemoryManager, ac *arch.Context64) bool {
	s := ac.StateData()
	inst := make([]byte, len(arch.CPUIDInstruction))
	tasklessCtx := emulationContext{
		taskWrapper: taskWrapper{ctx},
	}
	if _, err := mm.CopyIn(&tasklessCtx, hostarch.Addr(s.Regs.Rip), inst, usermem.IOOpts{
		IgnorePermissions:  true,
		AddressSpaceActive: true,
	}); err != nil {
		return false
	}
	if !bytes.Equal(inst, arch.CPUIDInstruction[:]) {
		return false
	}
	fs := cpuid.FromContext(ctx)
	out := fs.Function.Query(cpuid.In{
		Eax: uint32(s.Regs.Rax),
		Ecx: uint32(s.Regs.Rcx),
	})
	s.Regs.Rax = uint64(out.Eax)
	s.Regs.Rbx = uint64(out.Ebx)
	s.Regs.Rcx = uint64(out.Ecx)
	s.Regs.Rdx = uint64(out.Edx)
	s.Regs.Rip += uint64(len(inst))
	return true
}
