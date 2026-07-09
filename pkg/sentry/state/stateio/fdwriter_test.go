// Copyright 2026 The gVisor Authors.
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

package stateio

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestFDWriterDoubleClose(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	readFD := fds[0]
	writeFD := fds[1]

	defer unix.Close(readFD)

	// NewFDWriter takes ownership of writeFD.
	w := NewFDWriter(int32(writeFD), 4096, 1, 1)

	// First close should succeed.
	if err := w.Close(); err != nil {
		t.Fatalf("First Close() failed: %v", err)
	}

	// Second close should also succeed (idempotent) and not return EBADF.
	if err := w.Close(); err != nil {
		t.Fatalf("Second Close() failed: %v", err)
	}
}
