// Copyright 2024 The gVisor Authors.
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

//go:build linux
// +build linux

package aio

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxQueue(t *testing.T) {
	testQueue(t, func(cap int) (Queue, error) {
		q, err := NewLinuxQueue(cap)
		return q, err
	})
}

func TestLinuxQueueShortSubmit(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	q, err := NewLinuxQueue(2)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Destroy()

	// Linux accepts the read, then rejects the write to the same read-only
	// descriptor. Waiting for one completion lets a lost write fail the test
	// without blocking on a completion the kernel will never produce.
	fd := int32(f.Fd())
	Read(q, 0, fd, 0, nil)
	Write(q, 1, fd, 0, nil)
	if _, err := q.Wait(nil, 1); !errors.Is(err, unix.EBADF) {
		t.Errorf("submitting a write to a read-only descriptor: got %v, want %v", err, unix.EBADF)
	}
}
