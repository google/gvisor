// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"),;
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

package linuxerr

import (
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/errors"
)

var (
	// ErrWouldBlock is an internal error used to indicate that an operation
	// cannot be satisfied immediately, and should be retried at a later
	// time, possibly when the caller has received a notification that the
	// operation may be able to complete. It is used by implementations of
	// the kio.File interface.
	ErrWouldBlock = errors.New(errno.EWOULDBLOCK, "request would block")

	// ErrInterrupted is returned if a request is interrupted before it can
	// complete.
	ErrInterrupted = errors.New(errno.EINTR, "request was interrupted")

	// ErrExceedsFileSizeLimit is returned if a request would exceed the
	// file's size limit.
	ErrExceedsFileSizeLimit = errors.New(errno.E2BIG, "exceeds file size limit")
)

var errorMap = map[error]*errors.Error{
	ErrWouldBlock:           EWOULDBLOCK,
	ErrInterrupted:          EINTR,
	ErrExceedsFileSizeLimit: EFBIG,
}

// errorUnwrappers is an array of unwrap functions to extract typed errors.
var errorUnwrappers = []func(error) (*errors.Error, bool){}

// AddErrorUnwrapper registers an unwrap method that can extract a concrete error
// from a typed, but not initialized, error.
func AddErrorUnwrapper(unwrap func(e error) (*errors.Error, bool)) {
	errorUnwrappers = append(errorUnwrappers, unwrap)
}

// TranslateError translates errors to errnos, it will return false if
// the error was not registered.
func TranslateError(from error) (*errors.Error, bool) {
	if err, ok := errorMap[from]; ok {
		return err, true
	}
	// Try to unwrap the error if we couldn't match an error
	// exactly.  This might mean that a package has its own
	// error type.
	for _, unwrap := range errorUnwrappers {
		if err, ok := unwrap(from); ok {
			return err, true
		}
	}
	return nil, false
}

// These errors are significant because ptrace syscall exit tracing can
// observe them.
//
// For all of the following errors, if the syscall is not interrupted by a
// signal delivered to a user handler, the syscall is restarted.
var (
	// ERESTARTSYS is returned by an interrupted syscall to indicate that it
	// should be converted to EINTR if interrupted by a signal delivered to a
	// user handler without SA_RESTART set, and restarted otherwise.
	ERESTARTSYS = errors.New(errno.ERESTARTSYS, "to be restarted if SA_RESTART is set")

	// ERESTARTNOINTR is returned by an interrupted syscall to indicate that it
	// should always be restarted.
	ERESTARTNOINTR = errors.New(errno.ERESTARTNOINTR, "to be restarted")

	// ERESTARTNOHAND is returned by an interrupted syscall to indicate that it
	// should be converted to EINTR if interrupted by a signal delivered to a
	// user handler, and restarted otherwise.
	ERESTARTNOHAND = errors.New(errno.ERESTARTNOHAND, "to be restarted if no handler")

	// ERESTART_RESTARTBLOCK is returned by an interrupted syscall to indicate
	// that it should be restarted using a custom function. The interrupted
	// syscall must register a custom restart function by calling
	// Task.SetRestartSyscallFn.
	ERESTART_RESTARTBLOCK = errors.New(errno.ERESTART_RESTARTBLOCK, "interrupted by signal")
)

var restartMap = map[int]*errors.Error{
	-int(errno.ERESTARTSYS):           ERESTARTSYS,
	-int(errno.ERESTARTNOINTR):        ERESTARTNOINTR,
	-int(errno.ERESTARTNOHAND):        ERESTARTNOHAND,
	-int(errno.ERESTART_RESTARTBLOCK): ERESTART_RESTARTBLOCK,
}

// IsRestartError checks if a given error is a restart error.
func IsRestartError(err error) bool {
	switch err {
	case ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK:
		return true
	default:
		return false
	}
}

// SyscallRestartErrorFromReturn returns the SyscallRestartErrno represented by
// rv, the value in a syscall return register.
func SyscallRestartErrorFromReturn(rv uintptr) (*errors.Error, bool) {
	err, ok := restartMap[int(rv)]
	return err, ok
}
