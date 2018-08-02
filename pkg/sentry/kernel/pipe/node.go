// Copyright 2018 Google Inc.
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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/amutex"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// inodeOperations wraps fs.InodeOperations operations with common pipe opening semantics.
//
// +stateify savable
type inodeOperations struct {
	fs.InodeOperations

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// p is the underlying Pipe object representing this fifo.
	p *Pipe

	// Channels for synchronizing the creation of new readers and writers of
	// this fifo. See waitFor and newHandleLocked.
	//
	// These are not saved/restored because all waiters are unblocked on save,
	// and either automatically restart (via ERESTARTSYS) or return EINTR on
	// resume. On restarts via ERESTARTSYS, the appropriate channel will be
	// recreated.
	rWakeup chan struct{} `state:"nosave"`
	wWakeup chan struct{} `state:"nosave"`
}

// NewInodeOperations creates a new pipe fs.InodeOperations.
func NewInodeOperations(base fs.InodeOperations, p *Pipe) fs.InodeOperations {
	return &inodeOperations{
		InodeOperations: base,
		p:               p,
	}
}

// GetFile implements fs.InodeOperations.GetFile. Named pipes have special blocking
// semantics during open:
//
// "Normally, opening the FIFO blocks until the other end is opened also. A
// process can open a FIFO in nonblocking mode. In this case, opening for
// read-only will succeed even if no-one has opened on the write side yet,
// opening for write-only will fail with ENXIO (no such device or address)
// unless the other end has already been opened. Under Linux, opening a FIFO
// for read and write will succeed both in blocking and nonblocking mode. POSIX
// leaves this behavior undefined. This can be used to open a FIFO for writing
// while there are no readers available." - fifo(7)
func (i *inodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	switch {
	case flags.Read && !flags.Write: // O_RDONLY.
		r := i.p.ROpen(ctx)
		i.newHandleLocked(&i.rWakeup)

		if i.p.isNamed && !flags.NonBlocking && !i.p.HasWriters() {
			if !i.waitFor(&i.wWakeup, ctx) {
				r.DecRef()
				return nil, syserror.ErrInterrupted
			}
		}

		// By now, either we're doing a nonblocking open or we have a writer. On
		// a nonblocking read-only open, the open succeeds even if no-one has
		// opened the write side yet.
		return r, nil

	case flags.Write && !flags.Read: // O_WRONLY.
		w := i.p.WOpen(ctx)
		i.newHandleLocked(&i.wWakeup)

		if i.p.isNamed && !i.p.HasReaders() {
			// On a nonblocking, write-only open, the open fails with ENXIO if the
			// read side isn't open yet.
			if flags.NonBlocking {
				w.DecRef()
				return nil, syserror.ENXIO
			}

			if !i.waitFor(&i.rWakeup, ctx) {
				w.DecRef()
				return nil, syserror.ErrInterrupted
			}
		}
		return w, nil

	case flags.Read && flags.Write: // O_RDWR.
		// Pipes opened for read-write always succeeds without blocking.
		rw := i.p.RWOpen(ctx)
		i.newHandleLocked(&i.rWakeup)
		i.newHandleLocked(&i.wWakeup)
		return rw, nil

	default:
		return nil, syserror.EINVAL
	}
}

// waitFor blocks until the underlying pipe has at least one reader/writer is
// announced via 'wakeupChan', or until 'sleeper' is cancelled. Any call to this
// function will block for either readers or writers, depending on where
// 'wakeupChan' points.
//
// f.mu must be held by the caller. waitFor returns with f.mu held, but it will
// drop f.mu before blocking for any reader/writers.
func (i *inodeOperations) waitFor(wakeupChan *chan struct{}, sleeper amutex.Sleeper) bool {
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
	i.mu.Unlock()
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
	i.mu.Lock()
	select {
	case <-wakeup:
		return true
	default:
		return false
	}
}

// Truncate implements fs.InodeOperations.Truncate
//
// This method is required to override the default i.InodeOperations.Truncate
// which may return ErrInvalidOperation, this allows open related
// syscalls to set the O_TRUNC flag without returning an error by
// calling Truncate directly during openat. The ftruncate and truncate
// system calls will check that the file is an actual file and return
// EINVAL because it's a PIPE, making this behavior consistent with linux.
func (i *inodeOperations) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// newHandleLocked signals a new pipe reader or writer depending on where
// 'wakeupChan' points. This unblocks any corresponding reader or writer
// waiting for the other end of the channel to be opened, see Fifo.waitFor.
//
// i.mu must be held.
func (*inodeOperations) newHandleLocked(wakeupChan *chan struct{}) {
	if *wakeupChan != nil {
		close(*wakeupChan)
		*wakeupChan = nil
	}
}
