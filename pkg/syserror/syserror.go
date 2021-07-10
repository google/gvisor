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

// Package syserror contains syscall error codes exported as error interface
// instead of Errno. This allows for fast comparison and returns when the
// comparand or return value is of type error because there is no need to
// convert from Errno to an interface, i.e., runtime.convT2I isn't called.
package syserror

import (
	"errors"

	"golang.org/x/sys/unix"
)

var (
	// ErrWouldBlock is an internal error used to indicate that an operation
	// cannot be satisfied immediately, and should be retried at a later
	// time, possibly when the caller has received a notification that the
	// operation may be able to complete. It is used by implementations of
	// the kio.File interface.
	ErrWouldBlock = errors.New("request would block")

	// ErrInterrupted is returned if a request is interrupted before it can
	// complete.
	ErrInterrupted = errors.New("request was interrupted")

	// ErrExceedsFileSizeLimit is returned if a request would exceed the
	// file's size limit.
	ErrExceedsFileSizeLimit = errors.New("exceeds file size limit")
)

// errorMap is the map used to convert generic errors into errnos.
var errorMap = map[error]unix.Errno{}

// errorUnwrappers is an array of unwrap functions to extract typed errors.
var errorUnwrappers = []func(error) (unix.Errno, bool){}

// AddErrorTranslation allows modules to populate the error map by adding their
// own translations during initialization. Returns if the error translation is
// accepted or not. A pre-existing translation will not be overwritten by the
// new translation.
func AddErrorTranslation(from error, to unix.Errno) bool {
	if _, ok := errorMap[from]; ok {
		return false
	}

	errorMap[from] = to
	return true
}

// AddErrorUnwrapper registers an unwrap method that can extract a concrete error
// from a typed, but not initialized, error.
func AddErrorUnwrapper(unwrap func(e error) (unix.Errno, bool)) {
	errorUnwrappers = append(errorUnwrappers, unwrap)
}

// TranslateError translates errors to errnos, it will return false if
// the error was not registered.
func TranslateError(from error) (unix.Errno, bool) {
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
	return 0, false
}

// ConvertIntr converts the provided error code (err) to another one (intr) if
// the first error corresponds to an interrupted operation.
func ConvertIntr(err, intr error) error {
	if err == ErrInterrupted {
		return intr
	}
	return err
}

// SyscallRestartErrno represents a ERESTART* errno defined in the Linux's kernel
// include/linux/errno.h. These errnos are never returned to userspace
// directly, but are used to communicate the expected behavior of an
// interrupted syscall from the syscall to signal handling.
type SyscallRestartErrno int

// These numeric values are significant because ptrace syscall exit tracing can
// observe them.
//
// For all of the following errnos, if the syscall is not interrupted by a
// signal delivered to a user handler, the syscall is restarted.
const (
	// ERESTARTSYS is returned by an interrupted syscall to indicate that it
	// should be converted to EINTR if interrupted by a signal delivered to a
	// user handler without SA_RESTART set, and restarted otherwise.
	ERESTARTSYS = SyscallRestartErrno(512)

	// ERESTARTNOINTR is returned by an interrupted syscall to indicate that it
	// should always be restarted.
	ERESTARTNOINTR = SyscallRestartErrno(513)

	// ERESTARTNOHAND is returned by an interrupted syscall to indicate that it
	// should be converted to EINTR if interrupted by a signal delivered to a
	// user handler, and restarted otherwise.
	ERESTARTNOHAND = SyscallRestartErrno(514)

	// ERESTART_RESTARTBLOCK is returned by an interrupted syscall to indicate
	// that it should be restarted using a custom function. The interrupted
	// syscall must register a custom restart function by calling
	// Task.SetRestartSyscallFn.
	ERESTART_RESTARTBLOCK = SyscallRestartErrno(516)
)

// Error implements error.Error.
func (e SyscallRestartErrno) Error() string {
	// Descriptions are borrowed from strace.
	switch e {
	case ERESTARTSYS:
		return "to be restarted if SA_RESTART is set"
	case ERESTARTNOINTR:
		return "to be restarted"
	case ERESTARTNOHAND:
		return "to be restarted if no handler"
	case ERESTART_RESTARTBLOCK:
		return "interrupted by signal"
	default:
		return "(unknown interrupt error)"
	}
}

// SyscallRestartErrnoFromReturn returns the SyscallRestartErrno represented by
// rv, the value in a syscall return register.
func SyscallRestartErrnoFromReturn(rv uintptr) (SyscallRestartErrno, bool) {
	switch int(rv) {
	case -int(ERESTARTSYS):
		return ERESTARTSYS, true
	case -int(ERESTARTNOINTR):
		return ERESTARTNOINTR, true
	case -int(ERESTARTNOHAND):
		return ERESTARTNOHAND, true
	case -int(ERESTART_RESTARTBLOCK):
		return ERESTART_RESTARTBLOCK, true
	default:
		return 0, false
	}
}

func init() {
	AddErrorTranslation(ErrWouldBlock, unix.EWOULDBLOCK)
	AddErrorTranslation(ErrInterrupted, unix.EINTR)
	AddErrorTranslation(ErrExceedsFileSizeLimit, unix.EFBIG)
}
