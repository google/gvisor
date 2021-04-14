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

// Package safecopy provides an efficient implementation of functions to access
// memory that may result in SIGSEGV or SIGBUS being sent to the accessor.
package safecopy

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/syserror"
)

// SegvError is returned when a safecopy function receives SIGSEGV.
type SegvError struct {
	// Addr is the address at which the SIGSEGV occurred.
	Addr uintptr
}

// Error implements error.Error.
func (e SegvError) Error() string {
	return fmt.Sprintf("SIGSEGV at %#x", e.Addr)
}

// BusError is returned when a safecopy function receives SIGBUS.
type BusError struct {
	// Addr is the address at which the SIGBUS occurred.
	Addr uintptr
}

// Error implements error.Error.
func (e BusError) Error() string {
	return fmt.Sprintf("SIGBUS at %#x", e.Addr)
}

// AlignmentError is returned when a safecopy function is passed an address
// that does not meet alignment requirements.
type AlignmentError struct {
	// Addr is the invalid address.
	Addr uintptr

	// Alignment is the required alignment.
	Alignment uintptr
}

// Error implements error.Error.
func (e AlignmentError) Error() string {
	return fmt.Sprintf("address %#x is not aligned to a %d-byte boundary", e.Addr, e.Alignment)
}

var (
	// The begin and end addresses below are for the functions that are
	// checked by the signal handler.
	memcpyBegin               uintptr
	memcpyEnd                 uintptr
	memclrBegin               uintptr
	memclrEnd                 uintptr
	swapUint32Begin           uintptr
	swapUint32End             uintptr
	swapUint64Begin           uintptr
	swapUint64End             uintptr
	compareAndSwapUint32Begin uintptr
	compareAndSwapUint32End   uintptr
	loadUint32Begin           uintptr
	loadUint32End             uintptr

	// savedSigSegVHandler is a pointer to the SIGSEGV handler that was
	// configured before we replaced it with our own. We still call into it
	// when we get a SIGSEGV that is not interesting to us.
	savedSigSegVHandler uintptr

	// same a above, but for SIGBUS signals.
	savedSigBusHandler uintptr
)

// signalHandler is our replacement signal handler for SIGSEGV and SIGBUS
// signals.
func signalHandler()

// addrOfSignalHandler returns the start address of signalHandler.
//
// See comment on addrOfMemcpy for more details.
func addrOfSignalHandler() uintptr

// FindEndAddress returns the end address (one byte beyond the last) of the
// function that contains the specified address (begin).
func FindEndAddress(begin uintptr) uintptr {
	f := runtime.FuncForPC(begin)
	if f != nil {
		for p := begin; ; p++ {
			g := runtime.FuncForPC(p)
			if f != g {
				return p
			}
		}
	}
	return begin
}

// initializeAddresses initializes the addresses used by the signal handler.
func initializeAddresses() {
	// The following functions are written in assembly language, so they won't
	// be inlined by the existing compiler/linker. Tests will fail if this
	// assumption is violated.
	memcpyBegin = addrOfMemcpy()
	memcpyEnd = FindEndAddress(memcpyBegin)
	memclrBegin = addrOfMemclr()
	memclrEnd = FindEndAddress(memclrBegin)
	swapUint32Begin = addrOfSwapUint32()
	swapUint32End = FindEndAddress(swapUint32Begin)
	swapUint64Begin = addrOfSwapUint64()
	swapUint64End = FindEndAddress(swapUint64Begin)
	compareAndSwapUint32Begin = addrOfCompareAndSwapUint32()
	compareAndSwapUint32End = FindEndAddress(compareAndSwapUint32Begin)
	loadUint32Begin = addrOfLoadUint32()
	loadUint32End = FindEndAddress(loadUint32Begin)
}

func init() {
	initializeAddresses()
	if err := ReplaceSignalHandler(unix.SIGSEGV, addrOfSignalHandler(), &savedSigSegVHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for SIGSEGV: %v", err))
	}
	if err := ReplaceSignalHandler(unix.SIGBUS, addrOfSignalHandler(), &savedSigBusHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for SIGBUS: %v", err))
	}
	syserror.AddErrorUnwrapper(func(e error) (unix.Errno, bool) {
		switch e.(type) {
		case SegvError, BusError, AlignmentError:
			return unix.EFAULT, true
		default:
			return 0, false
		}
	})
}
