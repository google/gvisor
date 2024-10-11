// Copyright 2024 The gVisor Authors.
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

package sigframe

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

func callWithSignalFrame(stack uintptr, handler uintptr, sigframe *arch.UContext64)

//go:linkname throw runtime.throw
func throw(s string)

// CallWithSignalFrame sets up a signal frame on the stack and executes a
// user-defined callback function within that context.
//
// Caller-save registers can be used for passing arguments to the handler.
// These registers must be pre-set within the signal frame.
//
//go:nosplit
func CallWithSignalFrame(signalStack *linux.SignalStack, handlerAddr uintptr, sigmask *linux.SignalSet, rax uint64) error {
	var oldSigMask linux.SignalSet
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_RT_SIGPROCMASK, linux.SIG_BLOCK,
		uintptr(unsafe.Pointer(sigmask)),
		uintptr(unsafe.Pointer(&oldSigMask)),
		linux.SignalSetSize,
		0, 0)
	if errno != 0 {
		return errno
	}
	const minStackSize = uintptr(hostarch.PageSize)
	ctxOffset := (unsafe.Sizeof(arch.UContext64{}) + 7) &^ 7

	if ctxOffset+minStackSize > uintptr(signalStack.Size) {
		return unix.ENOMEM
	}

	p := uintptr(signalStack.Addr + signalStack.Size)
	stack := p - ctxOffset
	sigframe := (*arch.UContext64)(unsafe.Pointer(stack))
	sigframe.MContext.Rax = rax
	sigframe.Stack = *signalStack
	sigframe.Sigset = oldSigMask
	sigframe.MContext.Fpstate = 0

	callWithSignalFrame(stack, handlerAddr, sigframe)
	return nil
}

// Sigreturn restores the thread state from the signal frame.
func Sigreturn(sigframeAddr *arch.UContext64)

func retjmp()
