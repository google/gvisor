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

// Package pipe provides an in-memory implementation of a unidirectional
// pipe.
//
// The goal of this pipe is to emulate the pipe syscall in all of its
// edge cases and guarantees of atomic IO.
package pipe

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/ilist"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// DefaultPipeSize is the system-wide default size of a pipe in bytes.
const DefaultPipeSize = 65536

// Pipe is an encapsulation of a platform-independent pipe.
// It manages a buffered byte queue shared between a reader/writer
// pair.
type Pipe struct {
	waiter.Queue `state:"nosave"`

	// Whether this is a named or anonymous pipe.
	isNamed bool

	// The dirent backing this pipe. Shared by all readers and writers.
	dirent *fs.Dirent

	// The buffered byte queue.
	data ilist.List

	// Max size of the pipe in bytes.  When this max has been reached,
	// writers will get EWOULDBLOCK.
	max int

	// Current size of the pipe in bytes.
	size int

	// Max number of bytes the pipe can guarantee to read or write
	// atomically.
	atomicIOBytes int

	// The number of active readers for this pipe. Load/store atomically.
	readers int32

	// The number of active writes for this pipe. Load/store atomically.
	writers int32

	// This flag indicates if this pipe ever had a writer. Note that this does
	// not necessarily indicate there is *currently* a writer, just that there
	// has been a writer at some point since the pipe was created.
	//
	// Protected by mu.
	hadWriter bool

	// Lock protecting all pipe internal state.
	mu sync.Mutex `state:"nosave"`
}

// NewPipe initializes and returns a pipe. A pipe created by this function is
// persistent, and will remain valid even without any open fds to it. Named
// pipes for mknod(2) are created via this function. Note that the
// implementation of blocking semantics for opening the read and write ends of a
// named pipe are left to filesystems.
func NewPipe(ctx context.Context, isNamed bool, sizeBytes, atomicIOBytes int) *Pipe {
	p := &Pipe{
		isNamed:       isNamed,
		max:           sizeBytes,
		atomicIOBytes: atomicIOBytes,
	}

	// Build the fs.Dirent of this pipe, shared by all fs.Files associated
	// with this pipe.
	ino := pipeDevice.NextIno()
	base := fsutil.NewSimpleInodeOperations(fsutil.InodeSimpleAttributes{
		FSType: linux.PIPEFS_MAGIC,
		UAttr: fs.WithCurrentTime(ctx, fs.UnstableAttr{
			Owner: fs.FileOwnerFromContext(ctx),
			Perms: fs.FilePermissions{
				User: fs.PermMask{Read: true, Write: true},
			},
			Links: 1,
		}),
	})
	sattr := fs.StableAttr{
		Type:      fs.Pipe,
		DeviceID:  pipeDevice.DeviceID(),
		InodeID:   ino,
		BlockSize: int64(atomicIOBytes),
	}
	// There is no real filesystem backing this pipe, so we pass in a nil
	// Filesystem.
	sb := fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{})
	p.dirent = fs.NewDirent(fs.NewInode(NewInodeOperations(base, p), sb, sattr), fmt.Sprintf("pipe:[%d]", ino))

	return p
}

// NewConnectedPipe initializes a pipe and returns a pair of objects (which
// implement kio.File) representing the read and write ends of the pipe. A pipe
// created by this function becomes invalid as soon as either the read or write
// end is closed, and errors on subsequent operations on either end. Pipes
// for pipe(2) and pipe2(2) are generally created this way.
func NewConnectedPipe(ctx context.Context, sizeBytes int, atomicIOBytes int) (*fs.File, *fs.File) {
	p := NewPipe(ctx, false /* isNamed */, sizeBytes, atomicIOBytes)
	return p.ROpen(ctx), p.WOpen(ctx)
}

// ROpen opens the pipe for reading.
func (p *Pipe) ROpen(ctx context.Context) *fs.File {
	p.rOpen()
	return fs.NewFile(ctx, p.dirent, fs.FileFlags{Read: true}, &Reader{
		ReaderWriter: ReaderWriter{Pipe: p},
	})
}

// WOpen opens the pipe for writing.
func (p *Pipe) WOpen(ctx context.Context) *fs.File {
	p.wOpen()
	return fs.NewFile(ctx, p.dirent, fs.FileFlags{Write: true}, &Writer{
		ReaderWriter: ReaderWriter{Pipe: p},
	})
}

// RWOpen opens the pipe for both reading and writing.
func (p *Pipe) RWOpen(ctx context.Context) *fs.File {
	p.rOpen()
	p.wOpen()
	return fs.NewFile(ctx, p.dirent, fs.FileFlags{Read: true, Write: true}, &ReaderWriter{
		Pipe: p,
	})
}

// read reads data from the pipe into dst and returns the number of bytes
// read, or returns ErrWouldBlock if the pipe is empty.
func (p *Pipe) read(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	if !p.HasReaders() {
		return 0, syscall.EBADF
	}

	// Don't block for a zero-length read even if the pipe is empty.
	if dst.NumBytes() == 0 {
		return 0, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// If there is nothing to read at the moment but there is a writer, tell the
	// caller to block.
	if p.size == 0 {
		if !p.HasWriters() {
			// There are no writers, return EOF.
			return 0, nil
		}
		return 0, syserror.ErrWouldBlock
	}
	var n int64
	for b := p.data.Front(); b != nil; b = p.data.Front() {
		buffer := b.(*Buffer)
		n0, err := dst.CopyOut(ctx, buffer.bytes())
		n += int64(n0)
		p.size -= n0
		if buffer.truncate(n0) == 0 {
			p.data.Remove(b)
		}
		dst = dst.DropFirst(n0)
		if dst.NumBytes() == 0 || err != nil {
			return n, err
		}
	}
	return n, nil
}

// write writes data from sv into the pipe and returns the number of bytes
// written. If no bytes are written because the pipe is full (or has less than
// atomicIOBytes free capacity), write returns ErrWouldBlock.
func (p *Pipe) write(ctx context.Context, src usermem.IOSequence) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.HasWriters() {
		return 0, syscall.EBADF
	}
	if !p.HasReaders() {
		return 0, syscall.EPIPE
	}

	// POSIX requires that a write smaller than atomicIOBytes (PIPE_BUF) be
	// atomic, but requires no atomicity for writes larger than this. However,
	// Linux appears to provide stronger semantics than this in practice:
	// unmerged writes are done one PAGE_SIZE buffer at a time, so for larger
	// writes, the writing of each PIPE_BUF-sized chunk is atomic. We implement
	// this by writing at most atomicIOBytes at a time if we can't service the
	// write in its entirety.
	canWrite := src.NumBytes()
	if canWrite > int64(p.max-p.size) {
		if p.max-p.size >= p.atomicIOBytes {
			canWrite = int64(p.atomicIOBytes)
		} else {
			return 0, syserror.ErrWouldBlock
		}
	}

	// Copy data from user memory into a pipe-owned buffer.
	buf := make([]byte, canWrite)
	n, err := src.CopyIn(ctx, buf)
	if n > 0 {
		p.data.PushBack(newBuffer(buf[:n]))
		p.size += n
	}
	if int64(n) < src.NumBytes() && err == nil {
		// Partial write due to full pipe.
		err = syserror.ErrWouldBlock
	}
	return int64(n), err
}

// rOpen signals a new reader of the pipe.
func (p *Pipe) rOpen() {
	atomic.AddInt32(&p.readers, 1)
}

// wOpen signals a new writer of the pipe.
func (p *Pipe) wOpen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hadWriter = true
	atomic.AddInt32(&p.writers, 1)
}

// rClose signals that a reader has closed their end of the pipe.
func (p *Pipe) rClose() {
	newReaders := atomic.AddInt32(&p.readers, -1)
	if newReaders < 0 {
		panic(fmt.Sprintf("Refcounting bug, pipe has negative readers: %v", newReaders))
	}
}

// wClose signals that a writer has closed their end of the pipe.
func (p *Pipe) wClose() {
	newWriters := atomic.AddInt32(&p.writers, -1)
	if newWriters < 0 {
		panic(fmt.Sprintf("Refcounting bug, pipe has negative writers: %v.", newWriters))
	}
}

// HasReaders returns whether the pipe has any active readers.
func (p *Pipe) HasReaders() bool {
	return atomic.LoadInt32(&p.readers) > 0
}

// HasWriters returns whether the pipe has any active writers.
func (p *Pipe) HasWriters() bool {
	return atomic.LoadInt32(&p.writers) > 0
}

func (p *Pipe) rReadinessLocked() waiter.EventMask {
	ready := waiter.EventMask(0)
	if p.HasReaders() && p.data.Front() != nil {
		ready |= waiter.EventIn
	}
	if !p.HasWriters() && p.hadWriter {
		// POLLHUP must be supressed until the pipe has had at least one writer
		// at some point. Otherwise a reader thread may poll and immediately get
		// a POLLHUP before the writer ever opens the pipe, which the reader may
		// interpret as the writer opening then closing the pipe.
		ready |= waiter.EventHUp
	}
	return ready
}

// rReadiness returns a mask that states whether the read end of the pipe is
// ready for reading.
func (p *Pipe) rReadiness() waiter.EventMask {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rReadinessLocked()
}

func (p *Pipe) wReadinessLocked() waiter.EventMask {
	ready := waiter.EventMask(0)
	if p.HasWriters() && p.size < p.max {
		ready |= waiter.EventOut
	}
	if !p.HasReaders() {
		ready |= waiter.EventErr
	}
	return ready
}

// wReadiness returns a mask that states whether the write end of the pipe
// is ready for writing.
func (p *Pipe) wReadiness() waiter.EventMask {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wReadinessLocked()
}

// rwReadiness returns a mask that states whether a read-write handle to the
// pipe is ready for IO.
func (p *Pipe) rwReadiness() waiter.EventMask {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rReadinessLocked() | p.wReadinessLocked()
}

func (p *Pipe) queuedSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.size
}
