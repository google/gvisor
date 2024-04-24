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
	"math/rand"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// trapNR is the maximum number of traps what can fit in the trap table.
const trapNR = 256

// trapSize is the size of one trap.
const trapSize = 80

var (
	// jmpInst is the binary code of "jmp *addr".
	jmpInst          = [7]byte{0xff, 0x24, 0x25, 0, 0, 0, 0}
	jmpInstOpcodeLen = 3
	// faultInst is the single byte invalid instruction.
	faultInst = [1]byte{0x6}
	// faultInstOffset is the offset of the syscall instruction.
	faultInstOffset = uintptr(5)
)

type memoryManager interface {
	usermem.IO
	MMap(ctx context.Context, opts memmap.MMapOpts) (hostarch.Addr, error)
	FindVMAByName(ar hostarch.AddrRange, hint string) (hostarch.Addr, uint64, error)
}

// State represents the current state of the trap table.
//
// +stateify savable
type State struct {
	mu        sync.RWMutex `state:"nosave"`
	nextTrap  uint32
	tableAddr hostarch.Addr
}

// New returns the new state structure.
func New() *State {
	return &State{}
}

// +marshal
type header struct {
	nextTrap uint32
}

func (s *State) trapAddr(trap uint32) hostarch.Addr {
	return s.tableAddr + hostarch.Addr(trapSize*trap)
}

// newTrapLocked allocates a new trap entry.
//
// Preconditions: s.mu must be locked.
func (s *State) newTrapLocked(ctx context.Context, mm memoryManager) (hostarch.Addr, error) {
	var hdr header
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return 0, fmt.Errorf("no task found")
	}

	// s.nextTrap is zero if it isn't initialized. Here are three cases
	// when this can happen:
	//	* A usertrap vma has not been mapped yet.
	//	* The address space has been forked.
	//	* The address space has been restored.
	// nextTrap is saved on the usertrap vma to handle the third and second
	// cases.
	if s.nextTrap == 0 {
		addr, off, err := mm.FindVMAByName(trapTableAddrRange, tableHint)
		if off != 0 {
			return 0, fmt.Errorf("the usertrap vma has been overmounted")
		}
		if err != nil {
			// The usertrap table has not been mapped yet.
			addr := hostarch.Addr(rand.Int63n(int64(trapTableAddrRange.Length()-trapTableSize))).RoundDown() + trapTableAddrRange.Start
			ctx.Debugf("Map a usertrap vma at %x", addr)
			if err := loadUsertrap(ctx, mm, addr); err != nil {
				return 0, err
			}
			// The first cell in the table is used to save an index of a
			// next unused trap.
			s.nextTrap = 1
			s.tableAddr = addr
		} else if _, err := hdr.CopyIn(task.OwnCopyContext(usermem.IOOpts{AddressSpaceActive: false}), addr); err != nil {
			return 0, err
		} else {
			// Read an index of a next unused trap.
			s.nextTrap = hdr.nextTrap
			s.tableAddr = addr
		}
	}
	ctx.Debugf("Allocate a new trap: %p %d", s, s.nextTrap)
	if s.nextTrap >= trapNR {
		ctx.Warningf("No space in the trap table")
		return 0, fmt.Errorf("no space in the trap table")
	}
	trap := s.nextTrap
	s.nextTrap++

	// An entire trap has to be on the same page to avoid memory faults.
	addr := s.trapAddr(trap)
	if addr/hostarch.PageSize != (addr+trapSize)/hostarch.PageSize {
		trap = s.nextTrap
		s.nextTrap++
	}
	hdr = header{
		nextTrap: s.nextTrap,
	}
	if _, err := hdr.CopyOut(task.OwnCopyContext(usermem.IOOpts{IgnorePermissions: true}), s.tableAddr); err != nil {
		return 0, err
	}
	return s.trapAddr(trap), nil
}

// trapTableAddrRange is the range where a trap table can be placed.
//
// The value has to be below 2GB and the high two bytes has to be an invalid
// instruction.  In case of 0x60000, the high two bytes is 0x6. This is "push
// es" in x86 and the bad instruction on x64.
var trapTableAddrRange = hostarch.AddrRange{Start: 0x60000, End: 0x70000}

const (
	trapTableSize = hostarch.Addr(trapNR * trapSize)

	tableHint = "[usertrap]"
)

// LoadUsertrap maps the usertrap table into the address space.
func loadUsertrap(ctx context.Context, mm memoryManager, addr hostarch.Addr) error {
	size, _ := hostarch.Addr(trapTableSize).RoundUp()
	// Force is true because Addr is below MinUserAddress.
	_, err := mm.MMap(ctx, memmap.MMapOpts{
		Force:     true,
		Unmap:     true,
		Fixed:     true,
		Addr:      addr,
		Length:    uint64(size),
		Private:   true,
		Hint:      tableHint,
		MLockMode: memmap.MLockEager,
		Perms: hostarch.AccessType{
			Write:   false,
			Read:    true,
			Execute: true,
		},
		MaxPerms: hostarch.AccessType{
			Write:   true,
			Read:    true,
			Execute: true,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

// PatchSyscall changes the syscall instruction into a function call.
func (s *State) PatchSyscall(ctx context.Context, ac *arch.Context64, mm memoryManager) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return fmt.Errorf("no task found")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sysno := ac.SyscallNo()
	patchAddr := ac.IP() - uintptr(len(jmpInst))

	prevCode := make([]uint8, len(jmpInst))
	if _, err := primitive.CopyUint8SliceIn(task.OwnCopyContext(usermem.IOOpts{AddressSpaceActive: false}), hostarch.Addr(patchAddr), prevCode); err != nil {
		return err
	}

	// Check that another thread has not patched this syscall yet.
	// 0xb8 is the first byte of "mov sysno, %eax".
	if prevCode[0] == uint8(0xb8) {
		ctx.Debugf("Found the pattern at ip %x:sysno %d", patchAddr, sysno)

		trapAddr, err := s.addTrapLocked(ctx, ac, mm, uint32(sysno))
		if trapAddr == 0 || err != nil {
			ctx.Warningf("Failed to add a new trap: %v", err)
			return nil
		}

		// Replace "mov sysno, %eax; syscall" with "jmp trapAddr".
		newCode := make([]uint8, len(jmpInst))
		copy(newCode[:jmpInstOpcodeLen], jmpInst[:jmpInstOpcodeLen])
		binary.LittleEndian.PutUint32(newCode[jmpInstOpcodeLen:], uint32(trapAddr))

		ctx.Debugf("Apply the binary patch addr %x trap addr %x (%v -> %v)", patchAddr, trapAddr, prevCode, newCode)

		ignorePermContext := task.OwnCopyContext(usermem.IOOpts{IgnorePermissions: true})

		// The patch can't be applied atomically, so we need to
		// guarantee that in each moment other threads will read a
		// valid set of instructions, detect any inconsistent states
		// and restart the patched code if so.
		//
		// A subtle aspect is the address at which the user trap table
		// is always mapped which is 0x60000. The first byte of this is
		// 0x06 which is an invalid opcode. That’s why when we
		// overwrite all the bytes but the first 1 in the second step
		// it works fine since the jump address still writes a 0x6 at
		// the location of the first byte of syscall instruction that
		// we are removing and any threads reading the instructions
		// will still fault at the same place.
		//
		// Another subtle aspect is the second step is done using a
		// regular non-atomic write which means a thread decoding the
		// mov instruction could read a garbage value of the immediate
		// operand for the ‘mov sysyno, %eax” instruction. But it
		// doesn’t matter since we don’t change the first byte which is
		// the one that contains the opcode. Also since the thread will
		// fault on the 0x6 right after and will be restarted with the
		// patched code the mov reading a garbage immediate operand
		// doesn’t impact correctness.

		// The patch is applied in three steps:
		//
		// The first step is to replace the first byte of the syscall
		// instruction by one-byte invalid instruction (0x06), so that
		// other threads which have passed the mov instruction fault on
		// the invalid instruction and restart a patched code.
		faultInstB := primitive.ByteSlice(faultInst[:])
		if _, err := faultInstB.CopyOut(ignorePermContext, hostarch.Addr(patchAddr+faultInstOffset)); err != nil {
			return err
		}
		// The second step is to replace all bytes except the first one
		// which is the opcode of the mov instruction, so that the first
		// five bytes remain "mov XXX, %rax".
		if _, err := primitive.CopyUint8SliceOut(ignorePermContext, hostarch.Addr(patchAddr+1), newCode[1:]); err != nil {
			return err
		}
		// The final step is to replace the first byte of the patch.
		// After this point, all threads will read the valid jmp
		// instruction.
		if _, err := primitive.CopyUint8SliceOut(ignorePermContext, hostarch.Addr(patchAddr), newCode[0:1]); err != nil {
			return err
		}
	}
	return nil
}

// HandleFault handles a fault on a patched syscall instruction.
//
// When we replace a system call with a function call, we replace two
// instructions with one instruction. This means that here can be a thread
// which called the first instruction, then another thread applied a binary
// patch and the first thread calls the second instruction.
//
// To handle this case, the function call (jmp) instruction is constructed so
// that the first byte of the syscall instruction is changed with the one-byte
// invalid instruction (0x6).  And in case of the race, the first thread will
// fault on the invalid instruction and HandleFault will restart the function
// call.
func (s *State) HandleFault(ctx context.Context, ac *arch.Context64, mm memoryManager) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return fmt.Errorf("no task found")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	code := make([]uint8, len(jmpInst))
	ip := ac.IP() - faultInstOffset
	if _, err := primitive.CopyUint8SliceIn(task.OwnCopyContext(usermem.IOOpts{AddressSpaceActive: false}), hostarch.Addr(ip), code); err != nil {
		return err
	}

	for i := 0; i < jmpInstOpcodeLen; i++ {
		if code[i] != jmpInst[i] {
			return nil
		}
	}
	for i := 0; i < len(faultInst); i++ {
		if code[i+int(faultInstOffset)] != faultInst[i] {
			return nil
		}
	}

	regs := &ac.StateData().Regs
	if regs.Rax == uint64(unix.SYS_RESTART_SYSCALL) {
		// restart_syscall is usually set by the Sentry to restart a
		// system call after interruption by a stop signal. The Sentry
		// sets RAX and moves RIP back on the size of the syscall
		// instruction.
		//
		// RAX can't be set to SYS_RESTART_SYSCALL due to a race with
		// injecting a function call, because neither of the two first
		// bytes are equal to proper bytes of jmpInst.
		regs.Orig_rax = regs.Rax
		regs.Rip += arch.SyscallWidth
		return ErrFaultSyscall
	}

	ac.SetIP(ip)
	return ErrFaultRestart
}

// PreFork locks the trap table for reading. This call guarantees that the trap
// table will not be changed before the next PostFork call.
// +checklocksacquireread:s.mu
func (s *State) PreFork() {
	s.mu.RLock()
}

// PostFork unlocks the trap table.
// +checklocksreleaseread:s.mu
func (s *State) PostFork() {
	s.mu.RUnlock()
}
