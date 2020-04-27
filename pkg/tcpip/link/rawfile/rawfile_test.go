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

package rawfile

import (
	"syscall"
	"testing"
)

func TestNonBlockingWrite3ZeroLength(t *testing.T) {
	fd, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("failed to open /dev/null: %v", err)
	}
	defer syscall.Close(fd)

	if err := NonBlockingWrite3(fd, []byte{}, []byte{0}, nil); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
}

func TestNonBlockingWrite3Nil(t *testing.T) {
	fd, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("failed to open /dev/null: %v", err)
	}
	defer syscall.Close(fd)

	if err := NonBlockingWrite3(fd, nil, []byte{0}, nil); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
}
