// Copyright 2020 The gVisor Authors.
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

// +build linux

package iovec

import (
	"bytes"
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestBuilderEmpty(t *testing.T) {
	var builder Builder
	iovecs := builder.Build()
	if got, want := len(iovecs), 0; got != want {
		t.Errorf("len(iovecs) = %d, want %d", got, want)
	}
}

func TestBuilderBuild(t *testing.T) {
	a := []byte{1, 2}
	b := []byte{3, 4, 5}

	var builder Builder
	builder.Add(a)
	builder.Add(b)
	builder.Add(nil)      // Nil slice won't be added.
	builder.Add([]byte{}) // Empty slice won't be added.
	iovecs := builder.Build()

	if got, want := len(iovecs), 2; got != want {
		t.Fatalf("len(iovecs) = %d, want %d", got, want)
	}
	for i, data := range [][]byte{a, b} {
		if got, want := *iovecs[i].Base, data[0]; got != want {
			t.Fatalf("*iovecs[%d].Base = %d, want %d", i, got, want)
		}
		if got, want := iovecs[i].Len, uint64(len(data)); got != want {
			t.Fatalf("iovecs[%d].Len = %d, want %d", i, got, want)
		}
	}
}

func TestBuilderBuildMaxIov(t *testing.T) {
	for _, test := range []struct {
		numIov int
	}{
		{
			numIov: MaxIovs - 1,
		},
		{
			numIov: MaxIovs,
		},
		{
			numIov: MaxIovs + 1,
		},
		{
			numIov: MaxIovs + 10,
		},
	} {
		name := fmt.Sprintf("numIov=%v", test.numIov)
		t.Run(name, func(t *testing.T) {
			var data []byte
			var builder Builder
			for i := 0; i < test.numIov; i++ {
				buf := []byte{byte(i)}
				builder.Add(buf)
				data = append(data, buf...)
			}
			iovec := builder.Build()

			// Check the expected length of iovec.
			wantNum := test.numIov
			if wantNum > MaxIovs {
				wantNum = MaxIovs
			}
			if got, want := len(iovec), wantNum; got != want {
				t.Errorf("len(iovec) = %d, want %d", got, want)
			}

			// Test a real read-write.
			var fds [2]int
			if err := unix.Pipe(fds[:]); err != nil {
				t.Fatalf("Pipe: %v", err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			wrote, _, e := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fds[1]), uintptr(unsafe.Pointer(&iovec[0])), uintptr(len(iovec)))
			if int(wrote) != len(data) || e != 0 {
				t.Fatalf("writev: %v, %v; want %v, 0", wrote, e, len(data))
			}

			got := make([]byte, len(data))
			if n, err := unix.Read(fds[0], got); n != len(got) || err != nil {
				t.Fatalf("read: %v, %v; want %v, nil", n, err, len(got))
			}

			if !bytes.Equal(got, data) {
				t.Errorf("read: got data %v, want %v", got, data)
			}
		})
	}
}
