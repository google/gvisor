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

// Package testutil provides common assembly stubs for testing.
package testutil

import (
	"fmt"
	"strings"
)

// Getpid executes a trivial system call.
func Getpid()

// Touch touches the value in the first register.
func Touch()

// SyscallLoop executes a syscall and loops.
func SyscallLoop()

// SpinLoop spins on the CPU.
func SpinLoop()

// HaltLoop immediately halts and loops.
func HaltLoop()

// TwiddleRegsFault twiddles registers then faults.
func TwiddleRegsFault()

// TwiddleRegsSyscall twiddles registers then executes a syscall.
func TwiddleRegsSyscall()

// TwiddleSegments reads segments into known registers.
func TwiddleSegments()

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
