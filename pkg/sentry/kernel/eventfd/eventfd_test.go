// Copyright 2018 Google LLC
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

package eventfd

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

func TestEventfd(t *testing.T) {
	initVals := []uint64{
		0,
		// Using a non-zero initial value verifies that writing to an
		// eventfd signals when the eventfd's counter was already
		// non-zero.
		343,
	}

	for _, initVal := range initVals {
		ctx := contexttest.Context(t)

		// Make a new event that is writable.
		event := New(ctx, initVal, false)

		// Register a callback for a write event.
		w, ch := waiter.NewChannelEntry(nil)
		event.EventRegister(&w, waiter.EventIn)
		defer event.EventUnregister(&w)

		data := []byte("00000124")
		// Create and submit a write request.
		n, err := event.Writev(ctx, usermem.BytesIOSequence(data))
		if err != nil {
			t.Fatal(err)
		}
		if n != 8 {
			t.Errorf("eventfd.write wrote %d bytes, not full int64", n)
		}

		// Check if the callback fired due to the write event.
		select {
		case <-ch:
		default:
			t.Errorf("Didn't get notified of EventIn after write")
		}
	}
}

func TestEventfdStat(t *testing.T) {
	ctx := contexttest.Context(t)

	// Make a new event that is writable.
	event := New(ctx, 0, false)

	// Create and submit an stat request.
	uattr, err := event.Dirent.Inode.UnstableAttr(ctx)
	if err != nil {
		t.Fatalf("eventfd stat request failed: %v", err)
	}
	if uattr.Size != 0 {
		t.Fatal("EventFD size should be 0")
	}
}
