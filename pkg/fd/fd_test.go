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

package fd

import (
	"math"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetNegOne(t *testing.T) {
	type entry struct {
		name string
		file *FD
		fn   func() error
	}
	var tests []entry

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("unix.Socket:", err)
	}
	f1 := New(fd)
	tests = append(tests, entry{
		"Release",
		f1,
		func() error {
			return unix.Close(f1.Release())
		},
	})

	fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("unix.Socket:", err)
	}
	f2 := New(fd)
	tests = append(tests, entry{
		"Close",
		f2,
		f2.Close,
	})

	for _, test := range tests {
		if err := test.fn(); err != nil {
			t.Errorf("%s: %v", test.name, err)
			continue
		}
		if fd := test.file.FD(); fd != -1 {
			t.Errorf("%s: got FD() = %d, want = -1", test.name, fd)
		}
	}
}

func TestStartsNegOne(t *testing.T) {
	type entry struct {
		name string
		file *FD
	}

	tests := []entry{
		{"-1", New(-1)},
		{"-2", New(-2)},
		{"MinInt32", New(math.MinInt32)},
		{"MinInt64", New(math.MinInt64)},
	}

	for _, test := range tests {
		if fd := test.file.FD(); fd != -1 {
			t.Errorf("%s: got FD() = %d, want = -1", test.name, fd)
		}
	}
}

func TestFileDotFile(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("unix.Socket:", err)
	}

	f := New(fd)
	of, err := f.File()
	if err != nil {
		t.Fatalf("File got err %v want nil", err)
	}

	if ofd, nfd := int(of.Fd()), f.FD(); ofd == nfd || ofd == -1 {
		// Try not to double close the FD.
		f.Release()

		t.Fatalf("got %#v.File().Fd() = %d, want new FD", f, ofd)
	}

	f.Close()
	of.Close()
}

func TestFileDotFileError(t *testing.T) {
	f := &FD{ReadWriter{-2}}

	if of, err := f.File(); err == nil {
		t.Errorf("File %v got nil err want non-nil", of)
		of.Close()
	}
}

func TestNewFromFile(t *testing.T) {
	f, err := NewFromFile(os.Stdin)
	if err != nil {
		t.Fatalf("NewFromFile got err %v want nil", err)
	}
	if nfd, ofd := f.FD(), int(os.Stdin.Fd()); nfd == -1 || nfd == ofd {
		t.Errorf("got FD() = %d, want = new FD (old FD was %d)", nfd, ofd)
	}
	f.Close()
}

func TestNewFromFileError(t *testing.T) {
	f, err := NewFromFile(nil)
	if err == nil {
		t.Errorf("NewFromFile got %v with nil err want non-nil", f)
		f.Close()
	}
}
