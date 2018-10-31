// Copyright 2018 Google LLC
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
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy"
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
	// savedHandler is a pointer to the previous handler.
	//
	// This is called by bluepillHandler.
	savedHandler uintptr

	// dieTrampolineAddr is the address of dieTrampoline.
	dieTrampolineAddr uintptr
)

// dieHandler is called by dieTrampoline.
//
//go:nosplit
func dieHandler(c *vCPU) {
	throw(c.dieMessage)
}

// die is called to set the vCPU up to panic.
//
// This loads vCPU state, and sets up a call for the trampoline.
//
//go:nosplit
func (c *vCPU) die(context *arch.SignalContext64, msg string) {
	// Save the death message, which will be thrown.
	c.dieMessage = msg

	// Reload all registers to have an accurate stack trace when we return
	// to host mode. This means that the stack should be unwound correctly.
	var guestRegs userRegs
	if errno := c.getUserRegisters(&guestRegs); errno != 0 {
		throw(msg)
	}

	// Setup the trampoline.
	dieArchSetup(c, context, &guestRegs)
}

func init() {
	// Install the handler.
	if err := safecopy.ReplaceSignalHandler(syscall.SIGSEGV, reflect.ValueOf(sighandler).Pointer(), &savedHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for signal %d: %v", syscall.SIGSEGV, err))
	}

	// Extract the address for the trampoline.
	dieTrampolineAddr = reflect.ValueOf(dieTrampoline).Pointer()
}
