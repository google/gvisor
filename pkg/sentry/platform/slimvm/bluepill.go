// Copyright 2026 The gVisor Authors.
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

package slimvm

import (
	"fmt"
	"syscall"

	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sighandling"
)

var (
	// bounceSignal is the signal used for bouncing the vCPU.
	//
	// We use SIGCHLD because it is not masked by the runtime, and
	// it will be ignored properly by other parts of the kernel.
	bounceSignal = syscall.SIGCHLD

	// bounce is the interrupt vector used to return to the kernel.
	bounce = uint32(ring0.VirtualizationException)

	// savedHandler is a pointer to the previous handler.
	//
	// This is called by bluepillHandler.
	savedHandler uintptr
)

// bluepill enters guest mode.
func bluepill(*vCPU)

// sighandler is the signal entry point.
func sighandler()

// Return the start address of the functions above.
//
// In Go 1.17+, Go references to assembly functions resolve to an ABIInternal
// wrapper function rather than the function itself. We must reference from
// assembly to get the ABI0 (i.e., primary) address.
func addrOfSighandler() uintptr

// redpillSyscall is syscall -1, used by SlimVM to transition to host.
const redpillSyscall = ^uintptr(0)

// redpill on amd64/arm64 invokes a syscall with -1.
//
//go:nosplit
func redpill() {
	hostsyscall.RawSyscallErrno(redpillSyscall, 0, 0, 0)
}

func saveSignalHandler() {
	// Install the handler.
	if err := sighandling.ReplaceSignalHandler(bluepillSignal, addrOfSighandler(), &savedHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for signal %d: %v", bluepillSignal, err))
	}
}
