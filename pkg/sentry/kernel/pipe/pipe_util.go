// Copyright 2019 The gVisor Authors.
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

package pipe

import (
	"io"
	"math"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/amutex"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This file contains Pipe file functionality that is tied to neither VFS nor
// the old fs architecture.

// Release cleans up the pipe's state.
func (p *Pipe) Release() {
	p.rClose()
	p.wClose()

	// Wake up readers and writers.
	p.Notify(waiter.EventIn | waiter.EventOut)
}

// Read reads from the Pipe into dst.
func (p *Pipe) Read(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	n, err := p.read(ctx, readOps{
		left: func() int64 {
			return dst.NumBytes()
		},
		limit: func(l int64) {
			dst = dst.TakeFirst64(l)
		},
		read: func(view *buffer.View) (int64, error) {
			n, err := dst.CopyOutFrom(ctx, view)
			dst = dst.DropFirst64(n)
			view.TrimFront(n)
			return n, err
		},
	})
	if n > 0 {
		p.Notify(waiter.EventOut)
	}
	return n, err
}

// WriteTo writes to w from the Pipe.
func (p *Pipe) WriteTo(ctx context.Context, w io.Writer, count int64, dup bool) (int64, error) {
	ops := readOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		read: func(view *buffer.View) (int64, error) {
			n, err := view.ReadToWriter(w, count)
			if !dup {
				view.TrimFront(n)
			}
			count -= n
			return n, err
		},
	}
	n, err := p.read(ctx, ops)
	if n > 0 {
		p.Notify(waiter.EventOut)
	}
	return n, err
}

// Write writes to the Pipe from src.
func (p *Pipe) Write(ctx context.Context, src usermem.IOSequence) (int64, error) {
	n, err := p.write(ctx, writeOps{
		left: func() int64 {
			return src.NumBytes()
		},
		limit: func(l int64) {
			src = src.TakeFirst64(l)
		},
		write: func(view *buffer.View) (int64, error) {
			n, err := src.CopyInTo(ctx, view)
			src = src.DropFirst64(n)
			return n, err
		},
	})
	if n > 0 {
		p.Notify(waiter.EventIn)
	}
	return n, err
}

// ReadFrom reads from r to the Pipe.
func (p *Pipe) ReadFrom(ctx context.Context, r io.Reader, count int64) (int64, error) {
	n, err := p.write(ctx, writeOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		write: func(view *buffer.View) (int64, error) {
			n, err := view.WriteFromReader(r, count)
			count -= n
			return n, err
		},
	})
	if n > 0 {
		p.Notify(waiter.EventIn)
	}
	return n, err
}

// Readiness returns the ready events in the underlying pipe.
func (p *Pipe) Readiness(mask waiter.EventMask) waiter.EventMask {
	return p.rwReadiness() & mask
}

// Ioctl implements ioctls on the Pipe.
func (p *Pipe) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	// Switch on ioctl request.
	switch int(args[1].Int()) {
	case linux.FIONREAD:
		v := p.queued()
		if v > math.MaxInt32 {
			v = math.MaxInt32 // Silently truncate.
		}
		// Copy result to user-space.
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), int32(v), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	default:
		return 0, syscall.ENOTTY
	}
}

// waitFor blocks until the underlying pipe has at least one reader/writer is
// announced via 'wakeupChan', or until 'sleeper' is cancelled. Any call to this
// function will block for either readers or writers, depending on where
// 'wakeupChan' points.
//
// mu must be held by the caller. waitFor returns with mu held, but it will
// drop mu before blocking for any reader/writers.
func waitFor(mu *sync.Mutex, wakeupChan *chan struct{}, sleeper amutex.Sleeper) bool {
	// Ideally this function would simply use a condition variable. However, the
	// wait needs to be interruptible via 'sleeper', so we must sychronize via a
	// channel. The synchronization below relies on the fact that closing a
	// channel unblocks all receives on the channel.

	// Does an appropriate wakeup channel already exist? If not, create a new
	// one. This is all done under f.mu to avoid races.
	if *wakeupChan == nil {
		*wakeupChan = make(chan struct{})
	}

	// Grab a local reference to the wakeup channel since it may disappear as
	// soon as we drop f.mu.
	wakeup := *wakeupChan

	// Drop the lock and prepare to sleep.
	mu.Unlock()
	cancel := sleeper.SleepStart()

	// Wait for either a new reader/write to be signalled via 'wakeup', or
	// for the sleep to be cancelled.
	select {
	case <-wakeup:
		sleeper.SleepFinish(true)
	case <-cancel:
		sleeper.SleepFinish(false)
	}

	// Take the lock and check if we were woken. If we were woken and
	// interrupted, the former takes priority.
	mu.Lock()
	select {
	case <-wakeup:
		return true
	default:
		return false
	}
}

// newHandleLocked signals a new pipe reader or writer depending on where
// 'wakeupChan' points. This unblocks any corresponding reader or writer
// waiting for the other end of the channel to be opened, see Fifo.waitFor.
//
// Precondition: the mutex protecting wakeupChan must be held.
func newHandleLocked(wakeupChan *chan struct{}) {
	if *wakeupChan != nil {
		close(*wakeupChan)
		*wakeupChan = nil
	}
}
