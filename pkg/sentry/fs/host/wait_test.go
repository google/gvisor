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
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestWait(t *testing.T) {
	var fds [2]int
	err := unix.Pipe(fds[:])
	if err != nil {
		t.Fatalf("Unable to create pipe: %v", err)
	}

	defer unix.Close(fds[1])

	ctx := contexttest.Context(t)
	file, err := NewFile(ctx, fds[0])
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("NewFile failed: %v", err)
	}

	defer file.DecRef(ctx)

	r := file.Readiness(waiter.EventIn)
	if r != 0 {
		t.Fatalf("File is ready for read when it shouldn't be.")
	}

	e, ch := waiter.NewChannelEntry(nil)
	file.EventRegister(&e, waiter.EventIn)
	defer file.EventUnregister(&e)

	// Check that there are no notifications yet.
	if len(ch) != 0 {
		t.Fatalf("Channel is non-empty")
	}

	// Write to the pipe, so it should be writable now.
	unix.Write(fds[1], []byte{1})

	// Check that we get a notification. We need to yield the current thread
	// so that the fdnotifier can deliver notifications, so we use a
	// 1-second timeout instead of just checking the length of the channel.
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Channel not notified")
	}
}
