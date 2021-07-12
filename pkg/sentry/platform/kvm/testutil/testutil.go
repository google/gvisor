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

// Package testutil provides common assembly stubs for testing.
package testutil

import (
	"fmt"
	"strings"
)

// Getpid executes a trivial system call.
func Getpid()

// AddrOfGetpid returns the address of Getpid.
//
// In Go 1.17+, Go references to assembly functions resolve to an ABIInternal
// wrapper function rather than the function itself. We must reference from
// assembly to get the ABI0 (i.e., primary) address.
func AddrOfGetpid() uintptr

// AddrOfTouch returns the address of a function that touches the value in the
// first register.
func AddrOfTouch() uintptr
func touch()

// AddrOfSyscallLoop returns the address of a function that executes a syscall
// and loops.
func AddrOfSyscallLoop() uintptr
func syscallLoop()

// AddrOfSpinLoop returns the address of a function that spins on the CPU.
func AddrOfSpinLoop() uintptr
func spinLoop()

// AddrOfHaltLoop returns the address of a function that immediately halts and
// loops.
func AddrOfHaltLoop() uintptr
func haltLoop()

// AddrOfTwiddleRegsFault returns the address of a function that twiddles
// registers then faults.
func AddrOfTwiddleRegsFault() uintptr
func twiddleRegsFault()

// AddrOfTwiddleRegsSyscall returns the address of a function that twiddles
// registers then executes a syscall.
func AddrOfTwiddleRegsSyscall() uintptr
func twiddleRegsSyscall()

// FloatingPointWorks is a floating point test.
//
// It returns true or false.
func FloatingPointWorks() bool

// RegisterMismatchError is used for checking registers.
type RegisterMismatchError []string

// Error returns a human-readable error.
func (r RegisterMismatchError) Error() string {
	return strings.Join([]string(r), ";")
}

// addRegisterMisatch allows simple chaining of register mismatches.
func addRegisterMismatch(err error, reg string, got, expected interface{}) error {
	errStr := fmt.Sprintf("%s got %08x, expected %08x", reg, got, expected)
	switch r := err.(type) {
	case nil:
		// Return a new register mismatch.
		return RegisterMismatchError{errStr}
	case RegisterMismatchError:
		// Append the error.
		r = append(r, errStr)
		return r
	default:
		// Leave as is.
		return err
	}
}
