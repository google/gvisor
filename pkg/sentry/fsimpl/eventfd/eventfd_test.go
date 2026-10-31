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
	"math"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
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

func TestHostFDPreservesCounter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count uint64
	}{
		{"max_uint32", math.MaxUint32},
		{"above_uint32", 1<<32 + 1},
		{"max_eventfd", math.MaxUint64 - 1},
	} {
		t.Run(tc.name+"/counter", func(t *testing.T) { testHostFDCounter(t, tc.count, false) })
		t.Run(tc.name+"/semaphore", func(t *testing.T) { testHostFDCounter(t, tc.count, true) })
	}
}

func testHostFDCounter(t *testing.T, count uint64, semaphore bool) {
	ctx := contexttest.Context(t)
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer vfsObj.Release(ctx)
	file, err := New(ctx, &vfsObj, 1, semaphore, linux.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer file.DecRef(ctx)
	var buf [8]byte
	hostarch.ByteOrder.PutUint64(buf[:], count-1)
	if _, err := file.Write(ctx, usermem.BytesIOSequence(buf[:]), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	fd, err := file.Impl().(*EventFileDescription).HostFD()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Read(fd, buf[:]); err != nil {
		t.Fatalf("read host eventfd: %v", err)
	}
	want := count
	if semaphore {
		want = 1
	}
	if got := hostarch.ByteOrder.Uint64(buf[:]); got != want {
		t.Fatalf("read host eventfd: got %d, want %d", got, want)
	}
	if semaphore {
		// A single read consumes one. Fill the remaining space
		// to verify the exact count without draining it.
		hostarch.ByteOrder.PutUint64(buf[:], math.MaxUint64-count)
		if _, err := unix.Write(fd, buf[:]); err != nil {
			t.Fatalf("fill host semaphore: %v", err)
		}
		hostarch.ByteOrder.PutUint64(buf[:], 1)
		if _, err := unix.Write(fd, buf[:]); err != unix.EAGAIN {
			t.Fatalf("write to full host semaphore: got %v, want EAGAIN", err)
		}
	}
}
