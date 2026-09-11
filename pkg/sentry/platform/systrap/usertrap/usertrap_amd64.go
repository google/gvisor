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
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/rand"
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

const (
	// trapRetAddrOffset is the offset in a trap of the address at which the
	// patched syscall returns. It is the immediate operand of the "movabs
	// $ret_addr, %rax" instruction. See addTrapLocked.
	trapRetAddrOffset = 40

	// trapSysnoOffset is the offset in a trap of the number of the syscall
	// that the trap invokes. It is the immediate operand of the "mov sysno,
	// %eax" instruction. See addTrapLocked.
	trapSysnoOffset = 58
)

var (
	// jmpInst is the binary code of "jmp *addr".
	jmpInst          = [7]byte{0xff, 0x24, 0x25, 0, 0, 0, 0}
	jmpInstOpcodeLen = 3
	// movInstOpcode is the first byte of "mov sysno, %eax", i.e. the first
	// byte of a patchable syscall sequence.
	movInstOpcode = uint8(0xb8)
	// faultInst is the single byte invalid instruction.
	faultInst = [1]byte{0x6}
	// faultInstOffset is the offset of the syscall instruction.
	faultInstOffset = uintptr(5)
)

// tracerWarnLimiter limits how often the warning about attaching a tracer to a
// process with patched syscalls is logged. Without it, the warning is emitted
// on every syscall the traced process makes.
var tracerWarnLimiter = rate.NewLimiter(rate.Every(time.Minute), 1)

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
	disabled  bool
	// patches is a map of the patched syscall instruction address to its original syscall number.
	// Used to revert the patches when patching is disabled dynamically, and to restart instructions
	// if a thread faults on an instruction being unpatched.
	patches map[hostarch.Addr]uint32
}

// New returns the new state structure.
func New(disabled bool) *State {
	return &State{
		disabled: disabled,
		patches:  make(map[hostarch.Addr]uint32),
	}
}

// Disabled returns true if syscall patching has been disabled.
func (s *State) Disabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.disabled
}

// Disable disables future syscall patching.
func (s *State) Disable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disabled = true
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
		addr, off, err := mm.FindVMAByName(trapTableAddrRange, tableVMAName)
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
		} else if _, err := hdr.CopyIn(task.OwnCopyContext(usermem.IOOpts{}), addr); err != nil {
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

	tableVMAName = "[usertrap]"
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
		Name:      tableVMAName,
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

	// Check if syscall patching is disabled. This occurs if the user has disabled syscall patching
	// by setting the GS register for their own uses, meaning we cannot safely use it to store the
	// address of the usertrap table.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled {
		return nil
	}

	// Skip syscall patching when the task is being ptraced, because
	// single-stepping and other debugger features are incompatible with
	// the "syshandler" routine used to handle patched syscalls (see
	// syshandler_amd64.S). This incompatibility can result in inconsistent
	// process states and failures (e.g. SIGSEGV).
	// TODO(gvisor.dev/issue/11649): for a full fix we'd need to roll back
	//     existing patched syscalls, in case the traced program was patched
	//     before being traced (e.g. PTRACE_ATTACH on an already running
	//     process).
	if task.Tracer() != nil {
		if s.nextTrap > 0 && tracerWarnLimiter.Allow() {
			ctx.Warningf("LIKELY ERROR: Attached tracer to process with patched syscalls (traps %d)! Systrap is not fully compatible with ptrace/debuggers, program may die unexpectedly soon! Use `--systrap-disable-syscall-patching` as a workaround.", s.nextTrap)
		}
		return nil
	}

	sysno := ac.SyscallNo()
	patchAddr := ac.IP() - uintptr(len(jmpInst))

	prevCode := make([]uint8, len(jmpInst))
	if _, err := primitive.CopyUint8SliceIn(task, hostarch.Addr(patchAddr), prevCode); err != nil {
		return err
	}

	// Check that another thread has not patched this syscall yet.
	// 0xb8 is the first byte of "mov sysno, %eax".
	if prevCode[0] == movInstOpcode {
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

		// s.patches is initialized in New(), but check it just in case.
		if s.patches == nil {
			s.patches = make(map[hostarch.Addr]uint32)
		}
		s.patches[hostarch.Addr(patchAddr)] = uint32(sysno)
	}
	return nil
}

// loadTableLocked initializes s.tableAddr and s.nextTrap from the trap table
// mapped in mm. It returns false if the trap table has not been mapped, which
// means that no syscall has ever been patched in this address space.
//
// Preconditions: s.mu must be locked.
func (s *State) loadTableLocked(ctx context.Context, mm memoryManager) (bool, error) {
	// The usertrap table has already been mapped and initialized.
	if s.nextTrap != 0 {
		return true, nil
	}

	addr, off, err := mm.FindVMAByName(trapTableAddrRange, tableVMAName)
	// The usertrap vma does not exist.
	if err != nil {
		return false, nil
	}

	// The usertrap table should not be overmounted.
	if off != 0 {
		return false, fmt.Errorf("the usertrap vma has been overmounted")
	}

	var hdr header
	if _, err := hdr.CopyIn(&usermem.IOCopyContext{Ctx: ctx, IO: mm}, addr); err != nil {
		return false, err
	}

	// The table has been mapped but no trap has been allocated yet.
	if hdr.nextTrap == 0 {
		return false, nil
	}

	s.tableAddr = addr
	s.nextTrap = hdr.nextTrap
	return true, nil
}

// isPatchedWith returns true if code is a syscall that has been patched to
// jump to trapAddr.
func isPatchedWith(code []uint8, trapAddr hostarch.Addr) bool {
	// PatchSyscall writes the first byte of the jmp instruction last, so it
	// can still be the first byte of the original mov instruction if the
	// patch has been interrupted. Threads are redirected to trapAddr in both
	// cases; see HandleFault.
	if code[0] != jmpInst[0] && code[0] != movInstOpcode {
		return false
	}

	for i := 1; i < jmpInstOpcodeLen; i++ {
		if code[i] != jmpInst[i] {
			return false
		}
	}

	return binary.LittleEndian.Uint32(code[jmpInstOpcodeLen:]) == uint32(trapAddr)
}

// recoverPatchesLocked adds the patches that are recorded in the trap table,
// but not in s.patches, to s.patches.
//
// s.patches only contains the patches that have been applied through this
// State. An address space that has been forked or restored inherits both the
// patched application code and the trap table, but it gets a new State with an
// empty map, so the trap table is the only remaining record of these patches.
// Each trap contains the address at which the patched syscall returns and its
// syscall number, which is all that is needed to revert the patch.
//
// Preconditions: s.mu must be locked.
func (s *State) recoverPatchesLocked(ctx context.Context, mm memoryManager) error {
	ok, err := s.loadTableLocked(ctx, mm)
	if err != nil || !ok {
		return err
	}

	if s.patches == nil {
		s.patches = make(map[hostarch.Addr]uint32)
	}

	cc := &usermem.IOCopyContext{Ctx: ctx, IO: mm}
	trapBuf := make([]uint8, trapSize)
	code := make([]uint8, len(jmpInst))
	nextTrap := s.nextTrap
	if nextTrap > trapNR {
		nextTrap = trapNR
	}

	// The table header is the first entry in the table. Skip it.
	for trap := uint32(1); trap < nextTrap; trap++ {
		trapAddr := s.trapAddr(trap)
		if _, err := primitive.CopyUint8SliceIn(cc, trapAddr, trapBuf); err != nil {
			return err
		}

		// The first eight bytes of every trap point to its ninth byte. Some traps
		// are skipped by NewTrapLocked because they would cross a page boundary.
		if binary.LittleEndian.Uint64(trapBuf[:8]) != uint64(trapAddr)+8 {
			continue
		}

		retAddr := binary.LittleEndian.Uint64(trapBuf[trapRetAddrOffset:])
		// Protect against underflow.
		if retAddr < uint64(len(jmpInst)) {
			continue
		}

		// Check if the patch has already been restored.
		patchAddr := hostarch.Addr(retAddr - uint64(len(jmpInst)))
		if _, ok := s.patches[patchAddr]; ok {
			continue
		}

		// Copy the patch instruction.
		if _, err := primitive.CopyUint8SliceIn(cc, patchAddr, code); err != nil {
			continue
		}

		// Check if the patch is still installed.
		if !isPatchedWith(code, trapAddr) {
			continue
		}

		sysno := binary.LittleEndian.Uint32(trapBuf[trapSysnoOffset:])
		ctx.Debugf("Recovered binary patch addr %x trap addr %x (sysno %d)", patchAddr, trapAddr, sysno)
		s.patches[patchAddr] = sysno
	}
	return nil
}

// UnpatchSyscalls reverts all applied syscall patches to their original
// instructions and disables future syscall patching.
func (s *State) UnpatchSyscalls(ctx context.Context, mm memoryManager) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx == nil {
		return fmt.Errorf("no context provided")
	}
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return fmt.Errorf("no task found")
	}

	// This address space can contain patches that were applied before this
	// State was created (i.e. before it was forked or restored).
	// This seems expensive but it only happens once per address space.
	if err := s.recoverPatchesLocked(ctx, mm); err != nil {
		return err
	}

	if len(s.patches) == 0 {
		s.disabled = true
		return nil
	}

	ignorePermContext := task.OwnCopyContext(usermem.IOOpts{IgnorePermissions: true})

	// We recreate the original instruction using the sysno stored in the
	// patch map.
	for patchAddr, sysno := range s.patches {
		origCode := make([]byte, len(jmpInst))
		// 0xb8 is the opcode for "mov sysno, %eax".
		origCode[0] = movInstOpcode
		// The next 4 bytes are the sysno.
		binary.LittleEndian.PutUint32(origCode[1:5], sysno)
		// 0x0f05 is the opcode for the syscall instruction.
		origCode[5] = 0x0f
		origCode[6] = 0x05

		ctx.Debugf("Reverting binary patch addr %x (sysno %d)", patchAddr, sysno)

		// The patch can't be removed atomically, so we need to
		// guarantee that in each moment other threads will read a
		// valid set of instructions, detect any inconsistent states
		// and restart the unpatched code via HandleFault.
		//
		// The unpatch is applied in three steps:
		//
		// The first step is to replace the first byte of the jmp
		// instruction with a one-byte invalid instruction (0x06), so that
		// other threads which attempt to execute at patchAddr fault on
		// the invalid instruction and restart the unpatched code via HandleFault.
		faultInstB := primitive.ByteSlice(faultInst[:])
		if _, err := faultInstB.CopyOut(ignorePermContext, patchAddr); err != nil {
			ctx.Warningf("Failed to write faultInst when unpatching syscall at %x (sysno %d): %v", patchAddr, sysno, err)
			return err
		}

		// The second step is to replace all bytes except the first one
		// with the remainder of the original code, so that bytes 1..4
		// become the sysno and bytes 5..6 become the syscall opcode (0x0f05).
		// During this write, the first byte remains 0x06, ensuring any
		// racing threads fault on the invalid instruction.
		if _, err := primitive.CopyUint8SliceOut(ignorePermContext, hostarch.Addr(patchAddr+1), origCode[1:]); err != nil {
			ctx.Warningf("Failed to write remaining code when unpatching syscall at %x (sysno %d): %v", patchAddr, sysno, err)
			return err
		}

		// The final step is to restore the first byte of the original
		// instruction (0xb8, the opcode of "mov sysno, %eax").
		// After this point, all threads will read the valid
		// "mov sysno, %eax; syscall" instruction sequence.
		if _, err := primitive.CopyUint8SliceOut(ignorePermContext, patchAddr, origCode[0:1]); err != nil {
			ctx.Warningf("Failed to restore first byte when unpatching syscall at %x (sysno %d): %v", patchAddr, sysno, err)
			return err
		}
	}

	// Disable only after we ensure all patches have been reverted. Otherwise a fail could leave us
	// in a disabled state with patches still being active.
	s.disabled = true
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
//
// Similarly, when unpatching syscalls, the first byte of the jmp instruction is
// replaced with the invalid instruction (0x6) while the remaining bytes are
// restored. If a thread attempts to execute the unpatched instruction while
// unpatching is in progress, it faults on the invalid instruction, waits for
// unpatching to complete (via s.mu), and HandleFault restarts the original
// syscall instruction.
func (s *State) HandleFault(ctx context.Context, ac *arch.Context64, mm memoryManager) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return fmt.Errorf("no task found")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.disabled {
		// All patched syscalls have been unpatched. If the fault was at offset 0 during unpatching,
		// we need to restart the syscall.
		if _, ok := s.patches[hostarch.Addr(ac.IP())]; ok {
			ac.SetIP(ac.IP())
			return ErrFaultRestart
		}

		// If the fault was at offset 5 from an earlier uncomplete PatchSyscall() that was
		// replaced by an unpatch, we need to restart the syscall.
		if ac.IP() >= faultInstOffset {
			patchAddr := hostarch.Addr(ac.IP() - faultInstOffset)
			if _, ok := s.patches[patchAddr]; ok {
				regs := &ac.StateData().Regs
				if regs.Rax == uint64(unix.SYS_RESTART_SYSCALL) {
					regs.Orig_rax = regs.Rax
					regs.Rip += arch.SyscallWidth
					return ErrFaultSyscall
				}
				ac.SetIP(uintptr(patchAddr))
				return ErrFaultRestart
			}
		}
		return nil
	}

	if ac.IP() < faultInstOffset {
		return nil
	}

	code := make([]uint8, len(jmpInst))
	ip := ac.IP() - faultInstOffset
	if _, err := primitive.CopyUint8SliceIn(task, hostarch.Addr(ip), code); err != nil {
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
