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
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/syserror"
)

var globalError error

func BenchmarkAssignErrno(b *testing.B) {
	for i := b.N; i > 0; i-- {
		globalError = unix.EINVAL
	}
}

func BenchmarkAssignError(b *testing.B) {
	for i := b.N; i > 0; i-- {
		globalError = syserror.EINVAL
	}
}

func BenchmarkCompareErrno(b *testing.B) {
	globalError = unix.EAGAIN
	j := 0
	for i := b.N; i > 0; i-- {
		if globalError == unix.EINVAL {
			j++
		}
	}
}

func BenchmarkCompareError(b *testing.B) {
	globalError = syserror.EAGAIN
	j := 0
	for i := b.N; i > 0; i-- {
		if globalError == syserror.EINVAL {
			j++
		}
	}
}

func BenchmarkSwitchErrno(b *testing.B) {
	globalError = unix.EPERM
	j := 0
	for i := b.N; i > 0; i-- {
		switch globalError {
		case unix.EINVAL:
			j += 1
		case unix.EINTR:
			j += 2
		case unix.EAGAIN:
			j += 3
		}
	}
}

func BenchmarkSwitchError(b *testing.B) {
	globalError = syserror.EPERM
	j := 0
	for i := b.N; i > 0; i-- {
		switch globalError {
		case syserror.EINVAL:
			j += 1
		case syserror.EINTR:
			j += 2
		case syserror.EAGAIN:
			j += 3
		}
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
