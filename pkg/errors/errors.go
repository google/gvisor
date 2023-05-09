// Copyright 2021 The gVisor Authors.
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

// Package errors holds the standardized error definition for gVisor.
package errors

import (
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
)

// Error represents a syscall errno with a descriptive message.
type Error struct {
	errno   errno.Errno
	message string
}

// New creates a new *Error.
func New(err errno.Errno, message string) *Error {
	return &Error{
		errno:   err,
		message: message,
	}
}

// Error implements error.Error.
func (e *Error) Error() string { return e.message }

// Errno returns the underlying errno.Errno value.
func (e *Error) Errno() errno.Errno { return e.errno }
