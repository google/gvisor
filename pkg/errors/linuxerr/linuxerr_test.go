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

package syserror_test

import (
	"errors"
	"io"
	"io/fs"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	gErrors "gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/syserror"
)

var globalError error

func BenchmarkAssignUnix(b *testing.B) {
	for i := b.N; i > 0; i-- {
		globalError = unix.EINVAL
	}
}

func BenchmarkAssignLinuxerr(b *testing.B) {
	for i := b.N; i > 0; i-- {
		globalError = linuxerr.EINVAL
	}
}

func BenchmarkAssignSyserror(b *testing.B) {
	for i := b.N; i > 0; i-- {
		globalError = linuxerr.ENOMSG
	}
}

func BenchmarkCompareUnix(b *testing.B) {
	globalError = unix.EAGAIN
	j := 0
	for i := b.N; i > 0; i-- {
		if globalError == unix.EINVAL {
			j++
		}
	}
}

func BenchmarkCompareLinuxerr(b *testing.B) {
	globalError = linuxerr.E2BIG
	j := 0
	for i := b.N; i > 0; i-- {
		if globalError == linuxerr.EINVAL {
			j++
		}
	}
}

func BenchmarkCompareSyserror(b *testing.B) {
	globalError = linuxerr.EAGAIN
	j := 0
	for i := b.N; i > 0; i-- {
		if globalError == linuxerr.EACCES {
			j++
		}
	}
}

func BenchmarkSwitchUnix(b *testing.B) {
	globalError = unix.EPERM
	j := 0
	for i := b.N; i > 0; i-- {
		switch globalError {
		case unix.EINVAL:
			j++
		case unix.EINTR:
			j += 2
		case unix.EAGAIN:
			j += 3
		}
	}
}

func BenchmarkSwitchLinuxerr(b *testing.B) {
	globalError = linuxerr.EPERM
	j := 0
	for i := b.N; i > 0; i-- {
		switch globalError {
		case linuxerr.EINVAL:
			j++
		case linuxerr.EINTR:
			j += 2
		case linuxerr.EAGAIN:
			j += 3
		}
	}
}

func BenchmarkSwitchSyserror(b *testing.B) {
	globalError = linuxerr.EPERM
	j := 0
	for i := b.N; i > 0; i-- {
		switch globalError {
		case linuxerr.EACCES:
			j++
		case syserror.EINTR:
			j += 2
		case linuxerr.EAGAIN:
			j += 3
		}
	}
}

func BenchmarkReturnUnix(b *testing.B) {
	var localError error
	f := func() error {
		return unix.EINVAL
	}
	for i := b.N; i > 0; i-- {
		localError = f()
	}
	if localError != nil {
		return
	}
}

func BenchmarkReturnLinuxerr(b *testing.B) {
	var localError error
	f := func() error {
		return linuxerr.EINVAL
	}
	for i := b.N; i > 0; i-- {
		localError = f()
	}
	if localError != nil {
		return
	}
}

func BenchmarkConvertUnixLinuxerr(b *testing.B) {
	var localError error
	for i := b.N; i > 0; i-- {
		localError = linuxerr.ErrorFromErrno(errno.Errno(unix.EINVAL))
	}
	if localError != nil {
		return
	}
}

func BenchmarkConvertUnixLinuxerrZero(b *testing.B) {
	var localError error
	for i := b.N; i > 0; i-- {
		localError = linuxerr.ErrorFromErrno(errno.Errno(0))
	}
	if localError != nil {
		return
	}
}

type translationTestTable struct {
	fn                  string
	errIn               error
	syscallErrorIn      unix.Errno
	expectedBool        bool
	expectedTranslation unix.Errno
}

func TestErrorTranslation(t *testing.T) {
	myError := errors.New("My test error")
	myError2 := errors.New("Another test error")
	testTable := []translationTestTable{
		{"TranslateError", myError, 0, false, 0},
		{"TranslateError", myError2, 0, false, 0},
		{"AddErrorTranslation", myError, unix.EAGAIN, true, 0},
		{"AddErrorTranslation", myError, unix.EAGAIN, false, 0},
		{"AddErrorTranslation", myError, unix.EPERM, false, 0},
		{"TranslateError", myError, 0, true, unix.EAGAIN},
		{"TranslateError", myError2, 0, false, 0},
		{"AddErrorTranslation", myError2, unix.EPERM, true, 0},
		{"AddErrorTranslation", myError2, unix.EPERM, false, 0},
		{"AddErrorTranslation", myError2, unix.EAGAIN, false, 0},
		{"TranslateError", myError, 0, true, unix.EAGAIN},
		{"TranslateError", myError2, 0, true, unix.EPERM},
	}
	for _, tt := range testTable {
		switch tt.fn {
		case "TranslateError":
			err, ok := syserror.TranslateError(tt.errIn)
			if ok != tt.expectedBool {
				t.Fatalf("%v(%v) => %v expected %v", tt.fn, tt.errIn, ok, tt.expectedBool)
			} else if err != tt.expectedTranslation {
				t.Fatalf("%v(%v) (error) => %v expected %v", tt.fn, tt.errIn, err, tt.expectedTranslation)
			}
		case "AddErrorTranslation":
			ok := syserror.AddErrorTranslation(tt.errIn, tt.syscallErrorIn)
			if ok != tt.expectedBool {
				t.Fatalf("%v(%v) => %v expected %v", tt.fn, tt.errIn, ok, tt.expectedBool)
			}
		default:
			t.Fatalf("Unknown function %v", tt.fn)
		}
	}
}

func TestSyscallErrnoToErrors(t *testing.T) {
	for _, tc := range []struct {
		errno syscall.Errno
		err   *gErrors.Error
	}{
		{errno: syscall.EACCES, err: linuxerr.EACCES},
		{errno: syscall.EAGAIN, err: linuxerr.EAGAIN},
		{errno: syscall.EBADF, err: linuxerr.EBADF},
		{errno: syscall.EBUSY, err: linuxerr.EBUSY},
		{errno: syscall.EDOM, err: linuxerr.EDOM},
		{errno: syscall.EEXIST, err: linuxerr.EEXIST},
		{errno: syscall.EFAULT, err: linuxerr.EFAULT},
		{errno: syscall.EFBIG, err: linuxerr.EFBIG},
		{errno: syscall.EINTR, err: linuxerr.EINTR},
		{errno: syscall.EINVAL, err: linuxerr.EINVAL},
		{errno: syscall.EIO, err: linuxerr.EIO},
		{errno: syscall.ENOTDIR, err: linuxerr.ENOTDIR},
		{errno: syscall.ENOTTY, err: linuxerr.ENOTTY},
		{errno: syscall.EPERM, err: linuxerr.EPERM},
		{errno: syscall.EPIPE, err: linuxerr.EPIPE},
		{errno: syscall.ESPIPE, err: linuxerr.ESPIPE},
		{errno: syscall.EWOULDBLOCK, err: linuxerr.EAGAIN},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			e := linuxerr.ErrorFromErrno(errno.Errno(tc.errno))
			if e != tc.err {
				t.Fatalf("Mismatch errors: want: %+v (%d) got: %+v %d", tc.err, tc.err.Errno(), e, e.Errno())
			}
		})
	}
}

// TestEqualsMethod tests that the Equals method correctly compares syerror,
// unix.Errno and linuxerr.
// TODO (b/34162363): Remove this.
func TestEqualsMethod(t *testing.T) {
	for _, tc := range []struct {
		name     string
		linuxErr []*gErrors.Error
		err      []error
		equal    bool
	}{
		{
			name:     "compare nil",
			linuxErr: []*gErrors.Error{nil, linuxerr.NOERROR},
			err:      []error{nil, linuxerr.NOERROR, unix.Errno(0)},
			equal:    true,
		},
		{
			name:     "linuxerr nil error not",
			linuxErr: []*gErrors.Error{nil, linuxerr.NOERROR},
			err:      []error{unix.Errno(1), linuxerr.EPERM, linuxerr.EACCES},
			equal:    false,
		},
		{
			name:     "linuxerr not nil error nil",
			linuxErr: []*gErrors.Error{linuxerr.ENOENT},
			err:      []error{nil, unix.Errno(0), linuxerr.NOERROR},
			equal:    false,
		},
		{
			name:     "equal errors",
			linuxErr: []*gErrors.Error{linuxerr.ESRCH},
			err:      []error{linuxerr.ESRCH, syserror.ESRCH, unix.Errno(linuxerr.ESRCH.Errno())},
			equal:    true,
		},
		{
			name:     "unequal errors",
			linuxErr: []*gErrors.Error{linuxerr.ENOENT},
			err:      []error{linuxerr.ESRCH, syserror.ESRCH, unix.Errno(linuxerr.ESRCH.Errno())},
			equal:    false,
		},
		{
			name:     "other error",
			linuxErr: []*gErrors.Error{nil, linuxerr.NOERROR, linuxerr.E2BIG, linuxerr.EINVAL},
			err:      []error{fs.ErrInvalid, io.EOF},
			equal:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, le := range tc.linuxErr {
				for _, e := range tc.err {
					if linuxerr.Equals(le, e) != tc.equal {
						t.Fatalf("Expected %t from Equals method for linuxerr: %s %T and error: %s %T", tc.equal, le, le, e, e)
					}
				}
			}
		})
	}
}
