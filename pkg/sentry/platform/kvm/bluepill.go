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

package kvm

import (
	"fmt"
	"reflect"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// bluepill enters guest mode.
func bluepill(*vCPU)

// sighandler is the signal entry point.
func sighandler()

// dieTrampoline is the assembly trampoline. This calls dieHandler.
//
// This uses an architecture-specific calling convention, documented in
// dieArchSetup and the assembly implementation for dieTrampoline.
func dieTrampoline()

var (
	// bounceSignal is the signal used for bouncing KVM.
	//
	// We use SIGCHLD because it is not masked by the runtime, and
	// it will be ignored properly by other parts of the kernel.
	bounceSignal = unix.SIGCHLD

	// bounceSignalMask has only bounceSignal set.
	bounceSignalMask = uint64(1 << (uint64(bounceSignal) - 1))

	// bounce is the interrupt vector used to return to the kernel.
	bounce = uint32(ring0.VirtualizationException)

	// savedHandler is a pointer to the previous handler.
	//
	// This is called by bluepillHandler.
	savedHandler uintptr

	// dieTrampolineAddr is the address of dieTrampoline.
	dieTrampolineAddr uintptr
)

// redpill invokes a syscall with -1.
//
//go:nosplit
func redpill() {
	unix.RawSyscall(^uintptr(0), 0, 0, 0)
}

// dieHandler is called by dieTrampoline.
//
//go:nosplit
func dieHandler(c *vCPU) {
	throw(c.dieState.message)
}

// die is called to set the vCPU up to panic.
//
// This loads vCPU state, and sets up a call for the trampoline.
//
//go:nosplit
func (c *vCPU) die(context *arch.SignalContext64, msg string) {
	// Save the death message, which will be thrown.
	c.dieState.message = msg

	// Setup the trampoline.
	dieArchSetup(c, context, &c.dieState.guestRegs)
}

func init() {
	// Install the handler.
	if err := safecopy.ReplaceSignalHandler(bluepillSignal, reflect.ValueOf(sighandler).Pointer(), &savedHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for signal %d: %v", bluepillSignal, err))
	}

	// Extract the address for the trampoline.
	dieTrampolineAddr = reflect.ValueOf(dieTrampoline).Pointer()
}
