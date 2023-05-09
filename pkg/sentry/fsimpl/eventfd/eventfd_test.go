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

package eventfd

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestEventFD(t *testing.T) {
	initVals := []uint64{
		0,
		// Using a non-zero initial value verifies that writing to an
		// eventfd signals when the eventfd's counter was already
		// non-zero.
		343,
	}

	for _, initVal := range initVals {
		ctx := contexttest.Context(t)
		vfsObj := &vfs.VirtualFilesystem{}
		if err := vfsObj.Init(ctx); err != nil {
			t.Fatalf("VFS init: %v", err)
		}

		// Make a new eventfd that is writable.
		eventfd, err := New(ctx, vfsObj, initVal, false, linux.O_RDWR)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		defer eventfd.DecRef(ctx)

		// Register a callback for a write event.
		w, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
		if err := eventfd.EventRegister(&w); err != nil {
			t.Fatalf("EventRegister(): %v", err)
		}
		defer eventfd.EventUnregister(&w)

		data := []byte("00000124")
		// Create and submit a write request.
		n, err := eventfd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
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

func TestEventFDStat(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	// Make a new eventfd that is writable.
	eventfd, err := New(ctx, vfsObj, 0, false, linux.O_RDWR)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer eventfd.DecRef(ctx)

	statx, err := eventfd.Stat(ctx, vfs.StatOptions{
		Mask: linux.STATX_BASIC_STATS,
	})
	if err != nil {
		t.Fatalf("eventfd.Stat failed: %v", err)
	}
	if statx.Size != 0 {
		t.Errorf("eventfd size should be 0")
	}
}
