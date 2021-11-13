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

//go:build !windows
// +build !windows

// Package syserr contains sandbox-internal errors. These errors are distinct
// from both the errors returned by host system calls and the errors returned
// to sandboxed applications.
package syserr

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/safecopy"
)

// Error represents an internal error.
type Error struct {
	// message is the human readable form of this Error.
	message string

	// noTranslation indicates that this Error cannot be translated to a
	// errno.Errno.
	noTranslation bool

	// errno is the errno.Errno this Error should be translated to.
	errno errno.Errno
}

// New creates a new Error and adds a translation for it.
//
// New must only be called at init.
func New(message string, linuxTranslation errno.Errno) *Error {
	err := &Error{message: message, errno: linuxTranslation}

	// TODO(b/34162363): Remove this.
	if int(err.errno) >= len(linuxBackwardsTranslations) {
		panic(fmt.Sprint("invalid errno: ", err.errno))
	}

	e := error(unix.Errno(err.errno))
	// linuxerr.ErrWouldBlock gets translated to linuxerr.EWOULDBLOCK and
	// enables proper blocking semantics. This should temporary address the
	// class of blocking bugs that keep popping up with the current state of
	// the error space.
	if err.errno == linuxerr.EWOULDBLOCK.Errno() {
		e = linuxerr.ErrWouldBlock
	}
	linuxBackwardsTranslations[err.errno] = linuxBackwardsTranslation{err: e, ok: true}

	return err
}

// NewDynamic creates a new error with a dynamic error message and an errno
// translation.
//
// NewDynamic should only be used sparingly and not be used for static error
// messages. Errors with static error messages should be declared with New as
// global variables.
func NewDynamic(message string, linuxTranslation errno.Errno) *Error {
	return &Error{message: message, errno: linuxTranslation}
}

func newWithHost(message string, linuxTranslation errno.Errno, hostErrno unix.Errno) *Error {
	e := New(message, linuxTranslation)
	addHostTranslation(hostErrno, e)
	return e
}

// String implements fmt.Stringer.String.
func (e *Error) String() string {
	if e == nil {
		return "<nil>"
	}
	return e.message
}

type linuxBackwardsTranslation struct {
	err error
	ok  bool
}

// TODO(b/34162363): Remove this.
var linuxBackwardsTranslations [maxErrno]linuxBackwardsTranslation

// ToError translates an Error to a corresponding error value.
//
// TODO(b/34162363): Remove this.
func (e *Error) ToError() error {
	if e == nil {
		return nil
	}
	if e.noTranslation {
		panic(fmt.Sprintf("error %q does not support translation", e.message))
	}
	err := int(e.errno)
	if err == errno.NOERRNO {
		return nil
	}
	if err >= len(linuxBackwardsTranslations) || !linuxBackwardsTranslations[err].ok {
		panic(fmt.Sprintf("unknown error %q (%d)", e.message, err))
	}
	return linuxBackwardsTranslations[err].err
}

// ToLinux converts the Error to a Linux ABI error that can be returned to the
// application.
func (e *Error) ToLinux() errno.Errno {
	if e.noTranslation {
		panic(fmt.Sprintf("No Linux ABI translation available for %q", e.message))
	}
	return e.errno
}

// FromError converts a generic error to an *Error.
//
// TODO(b/34162363): Remove this function.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}

	switch e := err.(type) {
	case unix.Errno:
		return FromHost(e)
	case *errors.Error:
		return FromHost(unix.Errno(e.Errno()))
	case safecopy.SegvError, safecopy.BusError, safecopy.AlignmentError:
		return FromHost(unix.EFAULT)
	}

	msg := fmt.Sprintf("err: %s type: %T", err.Error(), err)
	panic(msg)
}
