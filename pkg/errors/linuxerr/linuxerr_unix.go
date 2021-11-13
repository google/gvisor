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

//go:build !windows
// +build !windows

package linuxerr

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/errors"
)

// ErrorFromUnix returns a linuxerr from a unix.Errno.
func ErrorFromUnix(err unix.Errno) error {
	if err == unix.Errno(0) {
		return nil
	}
	e := errorSlice[errno.Errno(err)]
	// Done this way because a single comparison in benchmarks is 2-3 faster
	// than something like ( if err == nil && err > 0 ).
	if e == errNotValidError {
		panic(fmt.Sprintf("invalid error requested with errno: %v", e))
	}
	return e
}

// ToUnix converts a linuxerr to a unix.Errno.
func ToUnix(e *errors.Error) unix.Errno {
	var unixErr unix.Errno
	if e != noError {
		unixErr = unix.Errno(e.Errno())
	}
	return unixErr
}

// Equals compars a linuxerr to a given error.
func Equals(e *errors.Error, err error) bool {
	var unixErr unix.Errno
	if e != noError {
		unixErr = unix.Errno(e.Errno())
	}
	if err == nil {
		err = noError
	}
	return e == err || unixErr == err
}
