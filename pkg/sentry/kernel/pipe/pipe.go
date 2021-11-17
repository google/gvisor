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
	"io"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// MinimumPipeSize is a hard limit of the minimum size of a pipe.
	// It corresponds to fs/pipe.c:pipe_min_size.
	MinimumPipeSize = hostarch.PageSize

	// MaximumPipeSize is a hard limit on the maximum size of a pipe.
	// It corresponds to fs/pipe.c:pipe_max_size.
	MaximumPipeSize = 1048576

	// DefaultPipeSize is the system-wide default size of a pipe in bytes.
	// It corresponds to pipe_fs_i.h:PIPE_DEF_BUFFERS.
	DefaultPipeSize = 16 * hostarch.PageSize

	// atomicIOBytes is the maximum number of bytes that the pipe will
	// guarantee atomic reads or writes atomically.
	// It corresponds to limits.h:PIPE_BUF.
	atomicIOBytes = 4096
)

// waitQueue is a wrapper around Pipe.
//
// This is used for ctx.Block operations that require the synchronization of
// readers and writers, along with the careful grabbing and releasing of locks.
type waitQueue Pipe

// Readiness implements waiter.Waitable.Readiness.
func (wq *waitQueue) Readiness(mask waiter.EventMask) waiter.EventMask {
	return ((*Pipe)(wq)).rwReadiness() & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (wq *waitQueue) EventRegister(e *waiter.Entry) {
	((*Pipe)(wq)).queue.EventRegister(e)

	// Notify synchronously.
	if ((*Pipe)(wq)).HasWriters() {
		e.NotifyEvent(waiter.ReadableEvents)
	} else if ((*Pipe)(wq)).HasReaders() {
		e.NotifyEvent(waiter.WritableEvents)
	}
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (wq *waitQueue) EventUnregister(e *waiter.Entry) {
	((*Pipe)(wq)).queue.EventUnregister(e)
}

// Pipe is an encapsulation of a platform-independent pipe.
// It manages a buffered byte queue shared between a reader/writer
// pair.
//
// +stateify savable
type Pipe struct {
	// queue is the waiter queue.
	queue waiter.Queue

	// isNamed indicates whether this is a named pipe.
	//
	// This value is immutable.
	isNamed bool

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

	// buf holds the pipe's data. buf is a circular buffer; the first valid
	// byte in buf is at offset off, and the pipe contains size valid bytes.
	// bufBlocks contains two identical safemem.Blocks representing buf; this
	// avoids needing to heap-allocate a new safemem.Block slice when buf is
	// resized. bufBlockSeq is a safemem.BlockSeq representing bufBlocks.
	//
	// These fields are protected by mu.
	buf         []byte
	bufBlocks   [2]safemem.Block `state:"nosave"`
	bufBlockSeq safemem.BlockSeq `state:"nosave"`
	off         int64
	size        int64

	// max is the maximum size of the pipe in bytes. When this max has been
	// reached, writers will get EWOULDBLOCK.
	//
	// This is protected by mu.
	max int64

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
// N.B. The size will be bounded.
func NewPipe(isNamed bool, sizeBytes int64) *Pipe {
	var p Pipe
	initPipe(&p, isNamed, sizeBytes)
	return &p
}

func initPipe(pipe *Pipe, isNamed bool, sizeBytes int64) {
	if sizeBytes < MinimumPipeSize {
		sizeBytes = MinimumPipeSize
	}
	if sizeBytes > MaximumPipeSize {
		sizeBytes = MaximumPipeSize
	}
	pipe.isNamed = isNamed
	pipe.max = sizeBytes
}

// NewConnectedPipe initializes a pipe and returns a pair of objects
// representing the read and write ends of the pipe.
func NewConnectedPipe(ctx context.Context, sizeBytes int64) (*fs.File, *fs.File) {
	p := NewPipe(false /* isNamed */, sizeBytes)

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
	defer d.DecRef(ctx)
	return p.Open(ctx, d, fs.FileFlags{Read: true}), p.Open(ctx, d, fs.FileFlags{Write: true})
}

// Open opens the pipe and returns a new file.
//
// Precondition: at least one of flags.Read or flags.Write must be set.
func (p *Pipe) Open(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) *fs.File {
	flags.NonSeekable = true
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

// peekLocked passes the first count bytes in the pipe to f and returns its
// result. If fewer than count bytes are available, the safemem.BlockSeq passed
// to f will be less than count bytes in length.
//
// peekLocked does not mutate the pipe; if the read consumes bytes from the
// pipe, then the caller is responsible for calling p.consumeLocked() and
// p.queue.Notify(waiter.WritableEvents). (The latter must be called with p.mu
// unlocked.)
//
// Preconditions:
// * p.mu must be locked.
// * This pipe must have readers.
func (p *Pipe) peekLocked(count int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	// Don't block for a zero-length read even if the pipe is empty.
	if count == 0 {
		return 0, nil
	}

	// Limit the amount of data read to the amount of data in the pipe.
	if count > p.size {
		if p.size == 0 {
			if !p.HasWriters() {
				return 0, io.EOF
			}
			return 0, linuxerr.ErrWouldBlock
		}
		count = p.size
	}

	// Prepare the view of the data to be read.
	bs := p.bufBlockSeq.DropFirst64(uint64(p.off)).TakeFirst64(uint64(count))

	// Perform the read.
	done, err := f(bs)
	return int64(done), err
}

// consumeLocked consumes the first n bytes in the pipe, such that they will no
// longer be visible to future reads.
//
// Preconditions:
// * p.mu must be locked.
// * The pipe must contain at least n bytes.
func (p *Pipe) consumeLocked(n int64) {
	p.off += n
	if max := int64(len(p.buf)); p.off >= max {
		p.off -= max
	}
	p.size -= n
}

// writeLocked passes a safemem.BlockSeq representing the first count bytes of
// unused space in the pipe to f and returns the result. If fewer than count
// bytes are free, the safemem.BlockSeq passed to f will be less than count
// bytes in length. If the pipe is full or otherwise cannot accomodate a write
// of any number of bytes up to count, writeLocked returns ErrWouldBlock
// without calling f.
//
// Unlike peekLocked, writeLocked assumes that f returns the number of bytes
// written to the pipe, and increases the number of bytes stored in the pipe
// accordingly. Callers are still responsible for calling
// p.queue.Notify(waiter.ReadableEvents) with p.mu unlocked.
//
// Preconditions:
// * p.mu must be locked.
func (p *Pipe) writeLocked(count int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	// Can't write to a pipe with no readers.
	if !p.HasReaders() {
		return 0, unix.EPIPE
	}

	avail := p.max - p.size
	if avail == 0 {
		return 0, linuxerr.ErrWouldBlock
	}
	short := false
	if count > avail {
		// POSIX requires that a write smaller than atomicIOBytes
		// (PIPE_BUF) be atomic, but requires no atomicity for writes
		// larger than this.
		if count <= atomicIOBytes {
			return 0, linuxerr.ErrWouldBlock
		}
		count = avail
		short = true
	}

	// Ensure that the buffer is big enough.
	if newLen, oldCap := p.size+count, int64(len(p.buf)); newLen > oldCap {
		// Allocate a new buffer.
		newCap := oldCap * 2
		if oldCap == 0 {
			newCap = 8 // arbitrary; sending individual integers across pipes is relatively common
		}
		for newLen > newCap {
			newCap *= 2
		}
		if newCap > p.max {
			newCap = p.max
		}
		newBuf := make([]byte, newCap)
		// Copy the old buffer's contents to the beginning of the new one.
		safemem.CopySeq(
			safemem.BlockSeqOf(safemem.BlockFromSafeSlice(newBuf)),
			p.bufBlockSeq.DropFirst64(uint64(p.off)).TakeFirst64(uint64(p.size)))
		// Switch to the new buffer.
		p.buf = newBuf
		p.bufBlocks[0] = safemem.BlockFromSafeSlice(newBuf)
		p.bufBlocks[1] = p.bufBlocks[0]
		p.bufBlockSeq = safemem.BlockSeqFromSlice(p.bufBlocks[:])
		p.off = 0
	}

	// Prepare the view of the space to be written.
	woff := p.off + p.size
	if woff >= int64(len(p.buf)) {
		woff -= int64(len(p.buf))
	}
	bs := p.bufBlockSeq.DropFirst64(uint64(woff)).TakeFirst64(uint64(count))

	// Perform the write.
	doneU64, err := f(bs)
	done := int64(doneU64)
	p.size += done
	if done < count || err != nil {
		return done, err
	}

	// If we shortened the write, adjust the returned error appropriately.
	if short {
		return done, linuxerr.ErrWouldBlock
	}

	return done, nil
}

// rOpen signals a new reader of the pipe.
func (p *Pipe) rOpen() {
	atomic.AddInt32(&p.readers, 1)

	// Notify for blocking openers.
	p.queue.Notify(waiter.WritableEvents)
}

// wOpen signals a new writer of the pipe.
func (p *Pipe) wOpen() {
	p.mu.Lock()
	p.hadWriter = true
	atomic.AddInt32(&p.writers, 1)
	p.mu.Unlock()

	// Notify for blocking openers.
	p.queue.Notify(waiter.ReadableEvents)
}

// rClose signals that a reader has closed their end of the pipe.
func (p *Pipe) rClose() {
	if newReaders := atomic.AddInt32(&p.readers, -1); newReaders < 0 {
		panic(fmt.Sprintf("Refcounting bug, pipe has negative readers: %v", newReaders))
	}
}

// wClose signals that a writer has closed their end of the pipe.
func (p *Pipe) wClose() {
	if newWriters := atomic.AddInt32(&p.writers, -1); newWriters < 0 {
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
	if p.HasReaders() && p.size != 0 {
		ready |= waiter.ReadableEvents
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
		ready |= waiter.WritableEvents
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

// EventRegister implements waiter.Waitable.EventRegister.
func (p *Pipe) EventRegister(e *waiter.Entry) {
	p.queue.EventRegister(e)

	// Notify synchronously.
	e.NotifyEvent(p.Readiness(^waiter.EventMask(0)))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (p *Pipe) EventUnregister(e *waiter.Entry) {
	p.queue.EventUnregister(e)
}

// queued returns the amount of queued data.
func (p *Pipe) queued() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.queuedLocked()
}

func (p *Pipe) queuedLocked() int64 {
	return p.size
}

// FifoSize implements fs.FifoSizer.FifoSize.
func (p *Pipe) FifoSize(context.Context, *fs.File) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.max, nil
}

// SetFifoSize implements fs.FifoSizer.SetFifoSize.
func (p *Pipe) SetFifoSize(size int64) (int64, error) {
	if size < 0 {
		return 0, linuxerr.EINVAL
	}
	if size < MinimumPipeSize {
		size = MinimumPipeSize // Per spec.
	}
	if size > MaximumPipeSize {
		return 0, linuxerr.EPERM
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if size < p.size {
		return 0, linuxerr.EBUSY
	}
	p.max = size
	return size, nil
}
