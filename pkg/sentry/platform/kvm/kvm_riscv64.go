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

//go:build riscv64
// +build riscv64

package kvm

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

type kvmOneReg struct {
	id   uint64
	addr uint64
}

// riscv64HypercallMMIOBase is MMIO base address used to dispatch hypercalls.
var riscv64HypercallMMIOBase uintptr

type userRegs struct {
	Regs    arch.Registers
	Sstatus uint64
}

type exception struct {
	sErrPending    uint8
	sErrHasEsr     uint8
	extDabtPending uint8
	pad            [5]uint8
	sErrEsr        uint64
}

type kvmVcpuEvents struct {
	exception
	rsvd [12]uint32
}

// updateGlobalOnce does global initialization. It has to be called only once.
func updateGlobalOnce(fd int) error {
	err := updateSystemValues(int(fd))
	ring0.Init()
	physicalInit()
	// The linux.Task represents the possible largest task size, which the UserspaceSize shouldn't be larger than.
	if linux.TaskSize < ring0.UserspaceSize {
		return fmt.Errorf("gVisor doesn't support 3-level page tables on KVM platform.")
	}
	return err
}
