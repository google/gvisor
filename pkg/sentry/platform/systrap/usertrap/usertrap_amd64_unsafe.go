// Copyright 2020 The gVisor Authors.
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

package usertrap

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/usermem"
)

// addTrapLocked constructs a trampoline for a specified syscall.
//
// mm.UserTrap.Lock has to be taken.
func (s *State) addTrapLocked(ctx context.Context, ac *arch.Context64, mm memoryManager, sysno uint32) (uint64, error) {
	trapAddr, err := s.newTrapLocked(ctx, mm)
	if err != nil {
		return 0, err
	}

	// First eight bytes is an address which points to the 9th byte, they
	// are used as an argument for the jmp instruction.
	//
	// Then here is the code of the syscall trampoline.
	// First, we need to lock the sysmsg struct by setting StatePrep. This
	// is used to synchronise with sighandler which uses the same struct
	// sysmsg. And we need to guarantee that the current thread will not be
	// interrupted in syshandler, because the sysmsg struct isn't saved on
	// S/R.
	// A thread stack can't be changed, so the call instruction can't be
	// used and we need to save the value of the instruction register and
	// generate a jmp instruction to syshandler:
	// mov    sysmsg.ThreadStatePrep, %gs:offset(msg.State)
	// movabs $ret_addr, %rax
	// mov    %rax,%gs:0x8  // msg.RetAddr
	// mov    sysno,%eax
	// jmpq   *%gs:0x10     // msg.Syshandler
	//
	// Switching to the syshandler stack is not done here but at the beginning of
	// __export_syshandler. A stack switch here is not idempotent, so it can't be part
	// of a restartable sequence.
	trap := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// msg.State = sysmsg.ThreadStatePrep
		/*08*/ 0x65, 0xc7, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov $X, %gs:OFFSET
		/*20*/ 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs $ret_addr, %rax
		/*30*/ 0x65, 0x48, 0x89, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, // mov    %rax,%gs:0x8
		/*39*/ 0xb8, 0x00, 0x00, 0x00, 0x00, // mov    sysno,%eax
		/*44*/ 0x65, 0xff, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, // jmpq *%gs:0x10
	}
	if len(trap) != trapCodeOffset+trapCodeSize {
		return 0, fmt.Errorf("the trampoline is %d bytes, but trapCodeOffset+trapCodeSize is %d", len(trap), trapCodeOffset+trapCodeSize)
	}
	binary.LittleEndian.PutUint64(trap[22:30], uint64(ac.IP()))
	binary.LittleEndian.PutUint32(trap[40:44], sysno)
	binary.LittleEndian.PutUint64(trap[:8], uint64(trapAddr)+trapCodeOffset)

	var msg *sysmsg.Msg
	binary.LittleEndian.PutUint32(trap[12:16], uint32(unsafe.Offsetof(msg.State)))
	binary.LittleEndian.PutUint32(trap[16:20], uint32(sysmsg.ThreadStatePrep))
	binary.LittleEndian.PutUint32(trap[35:39], uint32(unsafe.Offsetof(msg.RetAddr)))
	binary.LittleEndian.PutUint32(trap[48:52], uint32(unsafe.Offsetof(msg.Syshandler)))

	iocc := usermem.IOCopyContext{
		Ctx: ctx,
		IO:  mm,
		Opts: usermem.IOOpts{
			IgnorePermissions: true,
		},
	}
	_, err = primitive.CopyByteSliceOut(&iocc, trapAddr, trap[:])
	return uint64(trapAddr), err
}
