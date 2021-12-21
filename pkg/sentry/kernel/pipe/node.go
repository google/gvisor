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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/waiter"
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

	// p is the underlying Pipe object representing this fifo. This field
	// may have methods called on it, but the pointer is immutable.
	p *Pipe
}

var _ fs.InodeOperations = (*inodeOperations)(nil)

// NewInodeOperations returns a new fs.InodeOperations for a given pipe.
func NewInodeOperations(ctx context.Context, perms fs.FilePermissions, p *Pipe) *inodeOperations {
	i := &inodeOperations{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.FileOwnerFromContext(ctx), perms, linux.PIPEFS_MAGIC),
		p:                     p,
	}
	return i
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
	switch {
	case flags.Read && !flags.Write: // O_RDONLY.
		tWriters := atomic.LoadInt32(&i.p.totalWriters)
		r := i.p.Open(ctx, d, flags)
		for i.p.isNamed && !flags.NonBlocking && !i.p.HasWriters() &&
			tWriters == atomic.LoadInt32(&i.p.totalWriters) {
			if !ctx.BlockOn((*waitWriters)(i.p), waiter.EventInternal) {
				r.DecRef(ctx)
				return nil, linuxerr.ErrInterrupted
			}
		}

		// By now, either we're doing a nonblocking open or we have a writer. On
		// a nonblocking read-only open, the open succeeds even if no-one has
		// opened the write side yet.
		return r, nil

	case flags.Write && !flags.Read: // O_WRONLY.
		tReaders := atomic.LoadInt32(&i.p.totalReaders)
		w := i.p.Open(ctx, d, flags)
		for i.p.isNamed && !i.p.HasReaders() &&
			tReaders == atomic.LoadInt32(&i.p.totalReaders) {
			// On a nonblocking, write-only open, the open fails with ENXIO if the
			// read side isn't open yet.
			if flags.NonBlocking {
				w.DecRef(ctx)
				return nil, linuxerr.ENXIO
			}
			if !ctx.BlockOn((*waitReaders)(i.p), waiter.EventInternal) {
				w.DecRef(ctx)
				return nil, linuxerr.ErrInterrupted
			}
		}
		return w, nil

	case flags.Read && flags.Write: // O_RDWR.
		// Pipes opened for read-write always succeeds without blocking.
		rw := i.p.Open(ctx, d, flags)
		return rw, nil

	default:
		return nil, linuxerr.EINVAL
	}
}

func (*inodeOperations) Allocate(_ context.Context, _ *fs.Inode, _, _ int64) error {
	return linuxerr.EPIPE
}
