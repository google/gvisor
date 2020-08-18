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

package pipe

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// inodeOperations implements fs.InodeOperations for pipes.
//
// +stateify savable
type inodeOperations struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`

	// Marking pipe inodes as virtual allows them to be saved and restored
	// even if they have been unlinked. We can get away with this because
	// their state exists entirely within the sentry.
	fsutil.InodeVirtual `state:"nosave"`

	fsutil.InodeSimpleAttributes

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

var _ fs.InodeOperations = (*inodeOperations)(nil)

// NewInodeOperations returns a new fs.InodeOperations for a given pipe.
func NewInodeOperations(ctx context.Context, perms fs.FilePermissions, p *Pipe) *inodeOperations {
	return &inodeOperations{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.FileOwnerFromContext(ctx), perms, linux.PIPEFS_MAGIC),
		p:                     p,
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
		r := i.p.Open(ctx, d, flags)
		newHandleLocked(&i.rWakeup)

		if i.p.isNamed && !flags.NonBlocking && !i.p.HasWriters() {
			if !waitFor(&i.mu, &i.wWakeup, ctx) {
				r.DecRef(ctx)
				return nil, syserror.ErrInterrupted
			}
		}

		// By now, either we're doing a nonblocking open or we have a writer. On
		// a nonblocking read-only open, the open succeeds even if no-one has
		// opened the write side yet.
		return r, nil

	case flags.Write && !flags.Read: // O_WRONLY.
		w := i.p.Open(ctx, d, flags)
		newHandleLocked(&i.wWakeup)

		if i.p.isNamed && !i.p.HasReaders() {
			// On a nonblocking, write-only open, the open fails with ENXIO if the
			// read side isn't open yet.
			if flags.NonBlocking {
				w.DecRef(ctx)
				return nil, syserror.ENXIO
			}

			if !waitFor(&i.mu, &i.rWakeup, ctx) {
				w.DecRef(ctx)
				return nil, syserror.ErrInterrupted
			}
		}
		return w, nil

	case flags.Read && flags.Write: // O_RDWR.
		// Pipes opened for read-write always succeeds without blocking.
		rw := i.p.Open(ctx, d, flags)
		newHandleLocked(&i.rWakeup)
		newHandleLocked(&i.wWakeup)
		return rw, nil

	default:
		return nil, syserror.EINVAL
	}
}

func (*inodeOperations) Allocate(_ context.Context, _ *fs.Inode, _, _ int64) error {
	return syserror.EPIPE
}
