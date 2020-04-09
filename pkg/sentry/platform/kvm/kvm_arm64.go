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

// +build arm64

package kvm

import (
	"syscall"
)

type kvmOneReg struct {
	id   uint64
	addr uint64
}

const KVM_NR_SPSR = 5

type userFpsimdState struct {
	vregs    [64]uint64
	fpsr     uint32
	fpcr     uint32
	reserved [2]uint32
}

type userRegs struct {
	Regs    syscall.PtraceRegs
	sp_el1  uint64
	elr_el1 uint64
	spsr    [KVM_NR_SPSR]uint64
	fpRegs  userFpsimdState
}

// updateGlobalOnce does global initialization. It has to be called only once.
func updateGlobalOnce(fd int) error {
	physicalInit()
	err := updateSystemValues(int(fd))
	updateVectorTable()
	return err
}
