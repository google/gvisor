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

// Package pipe provides a pipe implementation.
package pipe

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// MinimumPipeSize is a hard limit of the minimum size of a pipe.
	MinimumPipeSize = 64 << 10

	// DefaultPipeSize is the system-wide default size of a pipe in bytes.
	DefaultPipeSize = MinimumPipeSize

	// MaximumPipeSize is a hard limit on the maximum size of a pipe.
	MaximumPipeSize = 8 << 20
)

// Sizer is an interface for setting and getting the size of a pipe.
//
// It is implemented by Pipe and, through embedding, all other types.
type Sizer interface {
	// PipeSize returns the pipe capacity in bytes.
	PipeSize() int64

	// SetPipeSize sets the new pipe capacity in bytes.
	//
	// The new size is returned (which may be capped).
	SetPipeSize(int64) (int64, error)
}

// Pipe is an encapsulation of a platform-independent pipe.
// It manages a buffered byte queue shared between a reader/writer
// pair.
//
// +stateify savable
type Pipe struct {
	waiter.Queue `state:"nosave"`

	// isNamed indicates whether this is a named pipe.
	//
	// This value is immutable.
	isNamed bool

	// atomicIOBytes is the maximum number of bytes that the pipe will
	// guarantee atomic reads or writes atomically.
	//
	// This value is immutable.
	atomicIOBytes int64

	// The number of active readers for this pipe.
	//
	// Access atomically.
	readers int32

	// The number of active writes for this pipe.
	//
	// Access atomically.
	writers int32

	// mu protects all pipe internal state below.
	mu sync.Mutex `state:"nosave"`

	// data is the buffer queue of pipe contents.
	//
	// This is protected by mu.
	data bufferList

	// max is the maximum size of the pipe in bytes. When this max has been
	// reached, writers will get EWOULDBLOCK.
	//
	// This is protected by mu.
	max int64

	// size is the current size of the pipe in bytes.
	//
	// This is protected by mu.
	size int64

	// hadWriter indicates if this pipe ever had a writer. Note that this
	// does not necessarily indicate there is *currently* a writer, just
	// that there has been a writer at some point since the pipe was
	// created.
	//
	// This is protected by mu.
	hadWriter bool
}

// NewPipe initializes and returns a pipe.
//
// N.B. The size and atomicIOBytes will be bounded.
func NewPipe(ctx context.Context, isNamed bool, sizeBytes, atomicIOBytes int64) *Pipe {
	if sizeBytes < MinimumPipeSize {
		sizeBytes = MinimumPipeSize
	}
	if sizeBytes > MaximumPipeSize {
		sizeBytes = MaximumPipeSize
	}
	if atomicIOBytes <= 0 {
		atomicIOBytes = 1
	}
	if atomicIOBytes > sizeBytes {
		atomicIOBytes = sizeBytes
	}
	return &Pipe{
		isNamed:       isNamed,
		max:           sizeBytes,
		atomicIOBytes: atomicIOBytes,
	}
}

// NewConnectedPipe initializes a pipe and returns a pair of objects
// representing the read and write ends of the pipe.
func NewConnectedPipe(ctx context.Context, sizeBytes, atomicIOBytes int64) (*fs.File, *fs.File) {
	p := NewPipe(ctx, false /* isNamed */, sizeBytes, atomicIOBytes)

	// Build an fs.Dirent for the pipe which will be shared by both
	// returned files.
	perms := fs.FilePermissions{
		User: fs.PermMask{Read: true, Write: true},
	}
	iops := NewInodeOperations(ctx, perms, p)
	ino := pipeDevice.NextIno()
	sattr := fs.StableAttr{
		Type:      fs.Pipe,
		DeviceID:  pipeDevice.DeviceID(),
		InodeID:   ino,
		BlockSize: int64(atomicIOBytes),
	}
	ms := fs.NewPseudoMountSource(ctx)
	d := fs.NewDirent(ctx, fs.NewInode(ctx, iops, ms, sattr), fmt.Sprintf("pipe:[%d]", ino))
	// The p.Open calls below will each take a reference on the Dirent. We
	// must drop the one we already have.
	defer d.DecRef()
	return p.Open(ctx, d, fs.FileFlags{Read: true}), p.Open(ctx, d, fs.FileFlags{Write: true})
}

// Open opens the pipe and returns a new file.
//
// Precondition: at least one of flags.Read or flags.Write must be set.
func (p *Pipe) Open(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) *fs.File {
	switch {
	case flags.Read && flags.Write:
		p.rOpen()
		p.wOpen()
		return fs.NewFile(ctx, d, flags, &ReaderWriter{
			Pipe: p,
		})
	case flags.Read:
		p.rOpen()
		return fs.NewFile(ctx, d, flags, &Reader{
			ReaderWriter: ReaderWriter{Pipe: p},
		})
	case flags.Write:
		p.wOpen()
		return fs.NewFile(ctx, d, flags, &Writer{
			ReaderWriter: ReaderWriter{Pipe: p},
		})
	default:
		// Precondition violated.
		panic("invalid pipe flags")
	}
}

// read reads data from the pipe into dst and returns the number of bytes
// read, or returns ErrWouldBlock if the pipe is empty.
//
// Precondition: this pipe must have readers.
func (p *Pipe) read(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	// Don't block for a zero-length read even if the pipe is empty.
	if dst.NumBytes() == 0 {
		return 0, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Is the pipe empty?
	if p.size == 0 {
		if !p.HasWriters() {
			// There are no writers, return EOF.
			return 0, nil
		}
		return 0, syserror.ErrWouldBlock
	}

	// Limit how much we consume.
	if dst.NumBytes() > p.size {
		dst = dst.TakeFirst64(p.size)
	}

	done := int64(0)
	for dst.NumBytes() > 0 {
		// Pop the first buffer.
		first := p.data.Front()
		if first == nil {
			break
		}

		// Copy user data.
		n, err := dst.CopyOutFrom(ctx, first)
		done += int64(n)
		p.size -= n
		dst = dst.DropFirst64(n)

		// Empty buffer?
		if first.Empty() {
			// Push to the free list.
			p.data.Remove(first)
			bufferPool.Put(first)
		}

		// Handle errors.
		if err != nil {
			return done, err
		}
	}

	return done, nil
}

// write writes data from sv into the pipe and returns the number of bytes
// written. If no bytes are written because the pipe is full (or has less than
// atomicIOBytes free capacity), write returns ErrWouldBlock.
//
// Precondition: this pipe must have writers.
func (p *Pipe) write(ctx context.Context, src usermem.IOSequence) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Can't write to a pipe with no readers.
	if !p.HasReaders() {
		return 0, syscall.EPIPE
	}

	// POSIX requires that a write smaller than atomicIOBytes (PIPE_BUF) be
	// atomic, but requires no atomicity for writes larger than this.
	wanted := src.NumBytes()
	if avail := p.max - p.size; wanted > avail {
		if wanted <= p.atomicIOBytes {
			return 0, syserror.ErrWouldBlock
		}
		// Limit to the available capacity.
		src = src.TakeFirst64(avail)
	}

	done := int64(0)
	for src.NumBytes() > 0 {
		// Need a new buffer?
		last := p.data.Back()
		if last == nil || last.Full() {
			// Add a new buffer to the data list.
			last = newBuffer()
			p.data.PushBack(last)
		}

		// Copy user data.
		n, err := src.CopyInTo(ctx, last)
		done += int64(n)
		p.size += n
		src = src.DropFirst64(n)

		// Handle errors.
		if err != nil {
			return done, err
		}
	}
	if wanted > done {
		// Partial write due to full pipe.
		return done, syserror.ErrWouldBlock
	}

	return done, nil
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

// rReadinessLocked calculates the read readiness.
//
// Precondition: mu must be held.
func (p *Pipe) rReadinessLocked() waiter.EventMask {
	ready := waiter.EventMask(0)
	if p.HasReaders() && p.data.Front() != nil {
		ready |= waiter.EventIn
	}
	if !p.HasWriters() && p.hadWriter {
		// POLLHUP must be suppressed until the pipe has had at least one writer
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

// wReadinessLocked calculates the write readiness.
//
// Precondition: mu must be held.
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

// queued returns the amount of queued data.
func (p *Pipe) queued() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.size
}

// PipeSize implements PipeSizer.PipeSize.
func (p *Pipe) PipeSize() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.max
}

// SetPipeSize implements PipeSize.SetPipeSize.
func (p *Pipe) SetPipeSize(size int64) (int64, error) {
	if size < 0 {
		return 0, syserror.EINVAL
	}
	if size < MinimumPipeSize {
		size = MinimumPipeSize // Per spec.
	}
	if size > MaximumPipeSize {
		return 0, syserror.EPERM
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if size < p.size {
		return 0, syserror.EBUSY
	}
	p.max = size
	return size, nil
}
