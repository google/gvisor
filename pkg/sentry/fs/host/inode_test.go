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

package host

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
)

// TestCloseFD verifies fds will be closed.
func TestCloseFD(t *testing.T) {
	var p [2]int
	if err := unix.Pipe(p[0:]); err != nil {
		t.Fatalf("Failed to create pipe %v", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])

	// Use the write-end because we will detect if it's closed on the read end.
	ctx := contexttest.Context(t)
	file, err := NewFile(ctx, p[1])
	if err != nil {
		t.Fatalf("Failed to create File: %v", err)
	}
	file.DecRef(ctx)

	s := make([]byte, 10)
	if c, err := unix.Read(p[0], s); c != 0 || err != nil {
		t.Errorf("want 0, nil (EOF) from read end, got %v, %v", c, err)
	}
}
