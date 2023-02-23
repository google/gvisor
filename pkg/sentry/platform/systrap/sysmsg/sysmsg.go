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

// Package sysmsg provides a stub signal handler and a communication protocol
// between stub threads and the Sentry.
//
// Note that this package is allowlisted for use of sync/atomic.
//
// +checkalignedignore
package sysmsg

import (
	_ "embed"
	"fmt"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// LINT.IfChange
// Per-thread stack layout:
//
// *------------*
// | guard page |
// |------------|
// |            |
// |  sysstack  |
// |            |
// *------------*
// | guard page |
// |------------|
// |            |
// |     ^      |
// |    / \     |
// |     |      |
// |  altstack  |
// |------------|
// |   sysmsg   |
// *------------*
const (
	// PerThreadMemSize is the size of a per-thread memory region.
	PerThreadMemSize = 8 * hostarch.PageSize
	// GuardSize is the size of an unmapped region which is placed right
	// before the signal stack.
	GuardSize                   = hostarch.PageSize
	PerThreadPrivateStackOffset = GuardSize
	PerThreadPrivateStackSize   = 2 * hostarch.PageSize
	// PerThreadStackSharedSize is the size of a per-thread stack region.
	PerThreadSharedStackSize   = 4 * hostarch.PageSize
	PerThreadSharedStackOffset = 4 * hostarch.PageSize
	// MsgOffsetFromStack is the offset of the Msg structure on
	// the thread stack.
	MsgOffsetFromSharedStack = PerThreadMemSize - hostarch.PageSize - PerThreadSharedStackOffset
)

// StackAddrToMsg returns an address of a sysmsg structure.
func StackAddrToMsg(sp uintptr) uintptr {
	return sp + MsgOffsetFromSharedStack
}

// StackAddrToSyshandlerStack returns an address of a syshandler stack.
func StackAddrToSyshandlerStack(sp uintptr) uintptr {
	return sp + PerThreadPrivateStackOffset + PerThreadPrivateStackSize
}

// MsgToStackAddr returns a start address of a stack.
func MsgToStackAddr(msg uintptr) uintptr {
	return msg - MsgOffsetFromSharedStack
}

// State is used to store a state of Msg.
type State uint32

// Set atomicaly sets the state value.
func (s *State) Set(state State) {
	atomic.StoreUint32((*uint32)(s), uint32(state))
}

// Get returns the current state value.
//
//go:nosplit
func (s *State) Get() State {
	return State(atomic.LoadUint32((*uint32)(s)))
}

const (
	// StateNone is the invalid state that isn't used.
	StateNone State = iota
	// StateDone means that last event has been handled
	// and a stub thread can be resumed.
	StateDone
	// StateEvent means that there is a new event
	// which has to be handled by Sentry.
	StateEvent
	// StateSigact means that the Sentry requests the full state of the
	// stub thread.
	//
	// When a stub thread is in a syscall function call
	// (EventTypeSyscallTrap), the Sentry knows only syscall arguments
	// without a full set of registers and an FPU state. This is enough to
	// handle a system call, but in some cases like signal handling, the
	// Sentry needs to know the full state.
	StateSigact
	// StatePrep means that syshandler started filling the sysmsg struct.
	StatePrep
)

// EventType defines event types.
type EventType uint32

// Event types.
const (
	EventTypeNone EventType = iota
	EventTypeSyscall
	EventTypeFault
	// EventTypeSyscallTrap means that the syscall event is triggered from
	// a function call (syshandler).
	EventTypeSyscallTrap
	// EventTypeSyscallCanBePatched means that the syscall can be replaced
	// with a function call.
	EventTypeSyscallCanBePatched
)

// Msg contains the current state of the sysmsg thread.
type Msg struct {
	// The next batch of fields is used to call the syshandler stub
	// function. A system call can be replaced with a function call. When
	// a function call is executed, it can't change the current process
	// stack, so it needs to save stack and instruction registers, switch
	// on its syshandler stack and call the jmp instruction to the syshandler
	// address.
	//
	// Self is a pointer to itself in a process address space.
	Self uint64
	// RetAddr is a return address from the syshandler function.
	RetAddr uint64
	// Syshandler is an address of the syshandler function.
	Syshandler uint64
	// SyshandlerStack is an address of  the thread syshandler stack.
	SyshandlerStack uint64
	// AppStack is a value of the stack register before calling the syshandler function.
	AppStack uint64
	// interrupt is non-zero if there is a postponed interrupt.
	interrupt uint32
	// FaultJump is the size of a faulted instruction.
	FaultJump int32
	Type      EventType
	State     State

	Signo      int32
	Err        int32
	Line       int32
	debug      uint64
	Regs       linux.PtraceRegs
	fpState    uint64
	SignalInfo linux.SignalInfo
	// TLS is a pointer to a thread local storage.
	// It is is only populated on ARM64.
	TLS uint64

	// The fast path is the mode when a thread is polling msg->state to
	// wait for a required state instead of calling FUTEX_WAIT.
	//
	// If core tagging is supported by the kernel, the Sentry thread, and a
	// stub thread share the same cookie and run on two associated
	// hyper-threads. The thread which is polling msg->state calls the
	// pause instruction, so the second thread gets almost the entire core
	// to run its workload.
	//
	// If core tagging isn't supported, a polling thread calls sched_yield
	// to let other processes to run.

	// StubFastPath is set if a stub process uses the fast path to wait for
	// events.  Only the stub thread can set it before switching to the
	// sentry, but the Sentry can clear it.
	stubFastPath   uint32
	sentryFastPath uint32
	AckedEvents    uint32
}

// LINT.ThenChange(sysmsg.h)

// Init initializes the message.
func (m *Msg) Init() {
	m.Err = 0
	m.Line = -1
	m.stubFastPath = 0
	m.sentryFastPath = 1
}

// StubFastPath returns true if the stub thread in the polling mode.
func (m *Msg) StubFastPath() bool {
	return atomic.LoadUint32(&m.stubFastPath) != 0
}

// DisableStubFastPath disables the polling mode for the stub thread.
func (m *Msg) DisableStubFastPath() {
	atomic.StoreUint32(&m.stubFastPath, 0)
}

// EnableSentryFastPath enables the polling mode for the Sentry. It has to be
// called before switching controls to the stub process.
func (m *Msg) EnableSentryFastPath() {
	m.sentryFastPath = 1
}

// DisableSentryFastPath disables the polling mode for the Sentry.
func (m *Msg) DisableSentryFastPath() {
	atomic.StoreUint32(&m.sentryFastPath, 0)
}

// FPUStateOffset returns the offset of a saved FPU state to the msg.
func (m *Msg) FPUStateOffset() (uint64, error) {
	offset := m.fpState
	if int64(offset) > -MsgOffsetFromSharedStack && int64(offset) < 0 {
		return offset, nil
	}
	return 0, errors.New(errno.EFAULT, fmt.Sprintf("FPU offset has been corrupted: %x", offset))
}

func (m *Msg) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "sysmsg.Msg{msg: %x type %d", m.Self, m.Type)
	fmt.Fprintf(&b, " fault addr %x syscall %d", m.SignalInfo.Addr(), m.SignalInfo.Syscall())
	fmt.Fprintf(&b, " err %x line %d debug %x", m.Err, m.Line, m.debug)
	fmt.Fprintf(&b, " ip %x sp %x ret addr %x app stack %x", m.Regs.InstructionPointer(), m.Regs.StackPointer(), m.RetAddr, m.AppStack)
	fmt.Fprintf(&b, " signo: %d, siginfo: %+v", m.Signo, m.SignalInfo)
	b.WriteString("}")

	return b.String()
}

// SighandlerBlob contains the compiled code of the sysmsg signal handler.
//
//go:embed sighandler.built-in.bin
var SighandlerBlob []byte
