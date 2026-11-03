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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Pipe sizes that depend on the page size, which is only known at runtime on
// some architectures.
var (
	// MinimumPipeSize is a hard limit of the minimum size of a pipe.
	// It corresponds to fs/pipe.c:pipe_min_size.
	MinimumPipeSize = int64(hostarch.PageSize)

	// DefaultPipeSize is the system-wide default size of a pipe in bytes.
	// It corresponds to pipe_fs_i.h:PIPE_DEF_BUFFERS.
	DefaultPipeSize = 16 * int64(hostarch.PageSize)
)

const (
	// MaximumPipeSize is a hard limit on the maximum size of a pipe.
	// It corresponds to fs/pipe.c:pipe_max_size.
	MaximumPipeSize = 1048576

	// atomicIOBytes is the maximum number of bytes that the pipe will
	// guarantee atomic reads or writes atomically.
	// It corresponds to limits.h:PIPE_BUF.
	atomicIOBytes = 4096
)

// waitReaders is a wrapper around Pipe.
//
// This is used for ctx.Block operations that require the synchronization of
// readers and writers, along with the careful grabbing and releasing of locks.
type waitReaders Pipe

// Readiness implements waiter.Waitable.Readiness.
func (wq *waitReaders) Readiness(mask waiter.EventMask) waiter.EventMask {
	return ((*Pipe)(wq)).rwReadiness() & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (wq *waitReaders) EventRegister(e *waiter.Entry) error {
	((*Pipe)(wq)).queue.EventRegister(e)

	// Notify synchronously.
	if ((*Pipe)(wq)).HasReaders() {
		e.NotifyEvent(waiter.EventInternal)
	}

	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (wq *waitReaders) EventUnregister(e *waiter.Entry) {
	((*Pipe)(wq)).queue.EventUnregister(e)
}

// waitWriters is a wrapper around Pipe.
//
// This is used for ctx.Block operations that require the synchronization of
// readers and writers, along with the careful grabbing and releasing of locks.
type waitWriters Pipe

// Readiness implements waiter.Waitable.Readiness.
func (wq *waitWriters) Readiness(mask waiter.EventMask) waiter.EventMask {
	return ((*Pipe)(wq)).rwReadiness() & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (wq *waitWriters) EventRegister(e *waiter.Entry) error {
	((*Pipe)(wq)).queue.EventRegister(e)

	// Notify synchronously.
	if ((*Pipe)(wq)).HasWriters() {
		e.NotifyEvent(waiter.EventInternal)
	}

	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (wq *waitWriters) EventUnregister(e *waiter.Entry) {
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
	readers atomicbitops.Int32

	// The total number of readers for this pipe.
	totalReaders atomicbitops.Int32

	// The number of active writers for this pipe.
	writers atomicbitops.Int32

	// The total number of writers for this pipe.
	totalWriters atomicbitops.Int32

	// mu protects all pipe internal state below.
	mu pipeMutex `state:"nosave"`

	// buf holds the pipe's data. buf is a circular buffer; the first valid
	// byte in buf is at offset off, and the pipe contains size valid bytes.
	// bufBlocks contains two identical safemem.Blocks representing buf; this
	// avoids needing to heap-allocate a new safemem.Block slice when buf is
	// resized. bufBlockSeq is a safemem.BlockSeq representing bufBlocks.
	//
	// +checklocks:mu
	buf []byte
	// +checklocks:mu
	bufBlocks [2]safemem.Block `state:"nosave"`
	// +checklocks:mu
	bufBlockSeq safemem.BlockSeq `state:"nosave"`
	// +checklocks:mu
	off int64
	// +checklocks:mu
	size int64

	// max is the maximum size of the pipe in bytes. When this max has been
	// reached, writers will get EWOULDBLOCK.
	//
	// +checklocks:mu
	max int64

	// hadWriter indicates if this pipe ever had a writer. Note that this
	// does not necessarily indicate there is *currently* a writer, just
	// that there has been a writer at some point since the pipe was
	// created.
	//
	// +checklocks:mu
	hadWriter bool

	// segs describes the pipe's contents as consecutive runs of bytes, oldest
	// first, once a packet mode (O_DIRECT) write has happened. segs is empty
	// while the pipe holds only stream data. Otherwise, the sizes of segs sum
	// to size.
	//
	// +checklocks:mu
	segs []pipeSegment

	// packets is the number of packets in segs. Each packet takes one of the
	// page-sized buffers that Linux would use for the pipe's contents, so a
	// pipe holds at most max / PAGE_SIZE packets.
	//
	// +checklocks:mu
	packets int64

	// tailMergeable and tailEnd describe the last of the page-sized buffers
	// that Linux would use for the pipe's contents. tailMergeable is true if
	// the last buffer holds stream data that a later write may append to,
	// and tailEnd is where the data in the last buffer ends within its page.
	// Linux appends the first len % PAGE_SIZE bytes of a write, in packet
	// mode or not, to the last buffer as stream data if it is mergeable and
	// has room for them. See fs/pipe.c:anon_pipe_write().
	//
	// +checklocks:mu
	tailMergeable bool
	// +checklocks:mu
	tailEnd int64

	// boundaries records, oldest first, where each of the page-sized buffers
	// that Linux would use for the pipe's contents ends if it is not the last
	// buffer, holds stream data that a write may append to and ends partway
	// through its page. A splice that moves such a buffer whole makes it the
	// destination's last buffer, which later writes append to. See
	// fs/splice.c:splice_pipe_to_pipe(). boundaries holds at most
	// maxPackets(max) entries, as many as Linux has buffers.
	//
	// +checklocks:mu
	boundaries []pipeBoundary
}

// pipeBoundary is the end of a buffer in a Pipe.
//
// +stateify savable
type pipeBoundary struct {
	// pos is the number of bytes in the pipe before the end of the buffer.
	pos int64

	// end is where the buffer's data ends within its page.
	end int64
}

// pipeSegment is a run of bytes in a Pipe.
//
// +stateify savable
type pipeSegment struct {
	// size is the number of bytes in the run.
	size int64

	// packet is true if the run is one packet. A read returns at most one
	// packet, and discards the part of the packet that it does not return.
	// See pipe(7).
	packet bool
}

// NewPipe initializes and returns a pipe.
//
// N.B. The size will be bounded.
func NewPipe(isNamed bool, sizeBytes int64) *Pipe {
	p := newPipe(isNamed, sizeBytes)
	return &p
}

func newPipe(isNamed bool, sizeBytes int64) Pipe {
	return Pipe{
		isNamed: isNamed,
		max:     min(max(sizeBytes, MinimumPipeSize), MaximumPipeSize),
	}
}

// peekLocked passes the first count bytes in the pipe, starting at offset off,
// to f and returns its result. If fewer than count bytes are available, the
// safemem.BlockSeq passed to f will be less than count bytes in length.
//
// peekLocked does not mutate the pipe; if the read consumes bytes from the
// pipe, then the caller is responsible for calling p.consumeLocked() and
// p.queue.Notify(waiter.WritableEvents). (The latter must be called with p.mu
// unlocked.)
//
// Preconditions:
//   - This pipe must have readers.
//   - off <= p.size.
//
// +checklocks:p.mu
func (p *Pipe) peekLocked(off, count int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	srcs, err := p.readableBlocksLocked(off, count)
	if srcs.IsEmpty() {
		return 0, err
	}
	n, err := f(srcs)
	return int64(n), err
}

// readableBlocksLocked returns a view of up to count bytes starting at off.
// The view is valid only while p.mu is held.
//
// Preconditions: as for peekLocked.
//
// +checklocks:p.mu
func (p *Pipe) readableBlocksLocked(off, count int64) (safemem.BlockSeq, error) {
	// Don't block for a zero-length read even if the pipe is empty.
	if count == 0 {
		return safemem.BlockSeq{}, nil
	}

	// Limit the amount of data read to the amount of data in the pipe.
	if rem := p.size - off; count > rem {
		if rem == 0 {
			if !p.HasWriters() {
				return safemem.BlockSeq{}, io.EOF
			}
			return safemem.BlockSeq{}, linuxerr.ErrWouldBlock
		}
		count = rem
	}

	// Prepare the view of the data to be read.
	pipeOff := p.off + off
	if max := int64(len(p.buf)); pipeOff >= max {
		pipeOff -= max
	}
	return p.bufBlockSeq.DropFirst64(uint64(pipeOff)).TakeFirst64(uint64(count)), nil
}

// consumeLocked consumes the first n bytes in the pipe, such that they will no
// longer be visible to future reads.
//
// Preconditions:
//   - The pipe must contain at least n bytes.
//
// +checklocks:p.mu
func (p *Pipe) consumeLocked(n int64) {
	p.consumeSegsLocked(n)
	p.consumeBoundariesLocked(n)
	p.off += n
	if max := int64(len(p.buf)); p.off >= max {
		p.off -= max
	}
	p.size -= n
	if p.size == 0 {
		p.tailMergeable = false
		p.tailEnd = 0
	}
}

// writeLocked passes a safemem.BlockSeq representing the first count bytes of
// unused space in the pipe to f and returns the result. If fewer than count
// bytes are free, the safemem.BlockSeq passed to f will be less than count
// bytes in length. If the pipe is full or otherwise cannot accommodate a write
// of any number of bytes up to count, writeLocked returns ErrWouldBlock
// without calling f.
//
// Unlike peekLocked, writeLocked assumes that f returns the number of bytes
// written to the pipe, and increases the number of bytes stored in the pipe
// accordingly. Callers are still responsible for calling
// p.queue.Notify(waiter.ReadableEvents) with p.mu unlocked.
//
// +checklocks:p.mu
func (p *Pipe) writeLocked(count int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	return p.writeSegLocked(count, false /* packet */, f)
}

// writeSegLocked writes like writeLocked, as stream data if packet is false.
// If packet is true, the bytes written are one packet, which writeSegLocked
// writes whole or not at all.
//
// Preconditions: If packet is true, count <= p.max.
//
// +checklocks:p.mu
func (p *Pipe) writeSegLocked(count int64, packet bool, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	done, err := p.copyInLocked(count, packet, f)
	p.addSegLocked(done, packet)
	p.addTailLocked(done, packet)
	return done, err
}

// writeSplicedLocked writes like writeLocked the bytes that a splice or tee
// moves from another pipe, whose runs at the start of that pipe are layout,
// or nil if that pipe holds no packet. The bytes keep the runs' packet
// boundaries, and a packet cut short by count or by the space in the pipe
// stays a packet, as in Linux's splice_pipe_to_pipe() and link_pipe(). It
// writes no more packets than the pipe has free buffers for. The caller
// records the state of the buffers it added with finishSpliceLocked or
// addUnmergeableLocked.
//
// +checklocks:p.mu
func (p *Pipe) writeSplicedLocked(count int64, layout []pipeSegment, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	if len(layout) == 0 {
		done, err := p.copyInLocked(count, false /* whole */, f)
		p.addSegLocked(done, false /* packet */)
		return done, err
	}
	// A count of 0 here means the pipe holds as many packets as it has
	// buffers, so copyInLocked fails with EPIPE or ErrWouldBlock.
	count = layoutLimit(count, layout, maxPackets(p.max)-p.packets)
	done, err := p.copyInLocked(count, false /* whole */, f)
	start := p.size - done
	left := done
	for _, seg := range layout {
		if left == 0 {
			break
		}
		n := min(seg.size, left)
		p.addSegAtLocked(start, n, seg.packet)
		start += n
		left -= n
	}
	return done, err
}

// writeUnmergeableLocked writes like writeLocked, as stream data in new
// buffers that later writes don't append to.
//
// +checklocks:p.mu
func (p *Pipe) writeUnmergeableLocked(count int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	done, err := p.copyInLocked(count, false /* whole */, f)
	p.addSegLocked(done, false /* packet */)
	if done > 0 {
		p.addUnmergeableLocked(done)
	}
	return done, err
}

// setTailLocked sets the state of the last of the page-sized buffers that
// Linux would use for the pipe's contents, which tailMergeable and tailEnd
// describe.
//
// +checklocks:p.mu
func (p *Pipe) setTailLocked(mergeable bool, end int64) {
	p.tailMergeable = mergeable
	p.tailEnd = end
}

// tailLocked returns the state of the pipe's last buffer, which
// tailMergeable and tailEnd describe.
//
// +checklocks:p.mu
func (p *Pipe) tailLocked() (mergeable bool, end int64) {
	return p.tailMergeable, p.tailEnd
}

// copyInLocked passes a safemem.BlockSeq representing the first count bytes
// of unused space in the pipe to f, increases the pipe's size by the number
// of bytes f returns and returns that number. If whole is true, or count is
// at most PIPE_BUF, it writes all count bytes or none. It returns
// ErrWouldBlock without calling f if the pipe is full, and EPIPE if the pipe
// has no readers.
//
// +checklocks:p.mu
func (p *Pipe) copyInLocked(count int64, whole bool, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	// Can't write to a pipe with no readers.
	if !p.HasReaders() {
		return 0, unix.EPIPE
	}

	avail := p.max - p.size
	if avail == 0 || p.packetsFullLocked() {
		return 0, linuxerr.ErrWouldBlock
	}
	short := false
	if count > avail {
		// POSIX requires that a write smaller than atomicIOBytes
		// (PIPE_BUF) be atomic, but requires no atomicity for writes
		// larger than this. A packet is always written whole.
		if count <= atomicIOBytes || whole {
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
		p.rebuildBufferViews()
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

// rebuildBufferViews reconnects the safemem views to the current buffer
// after growth or checkpoint restore.
//
// +checklocks:p.mu
func (p *Pipe) rebuildBufferViews() {
	p.bufBlocks[0] = safemem.BlockFromSafeSlice(p.buf)
	p.bufBlocks[1] = p.bufBlocks[0]
	p.bufBlockSeq = safemem.BlockSeqFromSlice(p.bufBlocks[:])
}

// rOpen signals a new reader of the pipe.
func (p *Pipe) rOpen() {
	p.readers.Add(1)
	p.totalReaders.Add(1)

	// Notify for blocking openers.
	p.queue.Notify(waiter.EventInternal)
}

// wOpen signals a new writer of the pipe.
func (p *Pipe) wOpen() {
	p.mu.Lock()
	p.hadWriter = true
	p.writers.Add(1)
	p.totalWriters.Add(1)
	p.mu.Unlock()

	// Notify for blocking openers.
	p.queue.Notify(waiter.EventInternal)
}

// rClose signals that a reader has closed their end of the pipe.
func (p *Pipe) rClose() {
	if newReaders := p.readers.Add(-1); newReaders < 0 {
		panic(fmt.Sprintf("Refcounting bug, pipe has negative readers: %v", newReaders))
	}
}

// wClose signals that a writer has closed their end of the pipe.
func (p *Pipe) wClose() {
	if newWriters := p.writers.Add(-1); newWriters < 0 {
		panic(fmt.Sprintf("Refcounting bug, pipe has negative writers: %v.", newWriters))
	}
}

// HasReaders returns whether the pipe has any active readers.
func (p *Pipe) HasReaders() bool {
	return p.readers.Load() > 0
}

// HasWriters returns whether the pipe has any active writers.
func (p *Pipe) HasWriters() bool {
	return p.writers.Load() > 0
}

// rReadinessLocked calculates the read readiness.
//
// +checklocks:p.mu
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
// +checklocks:p.mu
func (p *Pipe) wReadinessLocked() waiter.EventMask {
	ready := waiter.EventMask(0)
	if p.HasWriters() && p.size < p.max && !p.packetsFullLocked() {
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
func (p *Pipe) EventRegister(e *waiter.Entry) error {
	p.queue.EventRegister(e)
	return nil
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

// +checklocks:p.mu
func (p *Pipe) queuedLocked() int64 {
	return p.size
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
	if size < p.size || p.packets > maxPackets(size) {
		return 0, linuxerr.EBUSY
	}
	p.max = size
	if extra := len(p.boundaries) - int(maxPackets(size)); extra > 0 {
		p.boundaries = append(p.boundaries[:0], p.boundaries[extra:]...)
	}
	return size, nil
}

// maxPackets returns the number of packets that a pipe of size bytes holds.
func maxPackets(size int64) int64 {
	return max(size/int64(hostarch.PageSize), 1)
}

// packetsFullLocked returns true if the pipe holds as many packets as it has
// page-sized buffers, which fills a pipe in Linux.
//
// +checklocks:p.mu
func (p *Pipe) packetsFullLocked() bool {
	return p.packets >= maxPackets(p.max)
}

// addSegLocked records that the last n bytes in the pipe were just written,
// as one packet if packet is true.
//
// +checklocks:p.mu
func (p *Pipe) addSegLocked(n int64, packet bool) {
	p.addSegAtLocked(p.size-n, n, packet)
}

// addSegAtLocked records that the n bytes after the first prior bytes in the
// pipe were just written, as one packet if packet is true. The bytes before
// them must already be recorded.
//
// +checklocks:p.mu
func (p *Pipe) addSegAtLocked(prior, n int64, packet bool) {
	if n == 0 {
		return
	}
	if len(p.segs) == 0 {
		if !packet {
			return
		}
		if prior > 0 {
			p.segs = append(p.segs, pipeSegment{size: prior})
		}
	} else if last := &p.segs[len(p.segs)-1]; !packet && !last.packet {
		last.size += n
		return
	}
	p.segs = append(p.segs, pipeSegment{size: n, packet: packet})
	if packet {
		p.packets++
	}
}

// canMergeLocked returns true if Linux would append n bytes of a write to the
// last buffer of the pipe.
//
// +checklocks:p.mu
func (p *Pipe) canMergeLocked(n int64) bool {
	return p.tailMergeable && p.tailEnd+n <= int64(hostarch.PageSize)
}

// addTailLocked updates p.tailMergeable and p.tailEnd for a write of n bytes
// to the pipe, as one packet if packet is true.
//
// +checklocks:p.mu
func (p *Pipe) addTailLocked(n int64, packet bool) {
	if n == 0 {
		return
	}
	pageSize := int64(hostarch.PageSize)
	if !packet {
		if chars := n % pageSize; chars != 0 && p.canMergeLocked(chars) {
			p.tailEnd += chars
			n -= chars
			if n == 0 {
				return
			}
		}
	}
	p.endTailLocked(n)
	p.tailMergeable = !packet
	p.tailEnd = n % pageSize
	if p.tailEnd == 0 {
		p.tailEnd = pageSize
	}
}

// endTailLocked records in p.boundaries where the pipe's last buffer ends,
// when the last n bytes in the pipe start new buffers after it. It records
// nothing if the last buffer can't be appended to, fills its page or is
// empty.
//
// +checklocks:p.mu
func (p *Pipe) endTailLocked(n int64) {
	if !p.tailMergeable || p.tailEnd >= int64(hostarch.PageSize) || p.size == n {
		return
	}
	p.addBoundaryLocked(pipeBoundary{pos: p.size - n, end: p.tailEnd})
}

// addBoundaryLocked appends b to p.boundaries, and drops the oldest entry if
// p.boundaries already holds as many as Linux has buffers.
//
// +checklocks:p.mu
func (p *Pipe) addBoundaryLocked(b pipeBoundary) {
	if len(p.boundaries) >= int(maxPackets(p.max)) {
		p.boundaries = append(p.boundaries[:0], p.boundaries[1:]...)
	}
	p.boundaries = append(p.boundaries, b)
}

// boundariesLocked returns p.boundaries. The slice is valid only while p.mu is
// held.
//
// +checklocks:p.mu
func (p *Pipe) boundariesLocked() []pipeBoundary {
	return p.boundaries
}

// consumeBoundariesLocked drops the first n bytes from p.boundaries.
//
// +checklocks:p.mu
func (p *Pipe) consumeBoundariesLocked(n int64) {
	if len(p.boundaries) == 0 {
		return
	}
	kept := p.boundaries[:0]
	for _, b := range p.boundaries {
		if b.pos > n {
			kept = append(kept, pipeBoundary{pos: b.pos - n, end: b.end})
		}
	}
	p.boundaries = kept
	if len(p.boundaries) == 0 {
		p.boundaries = nil
	}
}

// finishSpliceLocked records the state of the buffers that a splice of the
// last n bytes in the pipe added, as splice_pipe_to_pipe() moves them. The
// source held srcSize bytes, its buffers ended where srcBoundaries records
// and its last buffer had the state srcMergeable and srcEnd. A source buffer
// that the splice moves whole keeps its state, and one it moves only part of
// can't be appended to.
//
// +checklocks:p.mu
func (p *Pipe) finishSpliceLocked(n, srcSize int64, srcBoundaries []pipeBoundary, srcMergeable bool, srcEnd int64) {
	start := p.size - n
	p.endTailLocked(n)
	mergeable, end := false, int64(0)
	if n == srcSize {
		mergeable, end = srcMergeable, srcEnd
	}
	for _, b := range srcBoundaries {
		if b.pos == n {
			mergeable, end = true, b.end
		}
		if b.pos >= n {
			break
		}
		p.addBoundaryLocked(pipeBoundary{pos: start + b.pos, end: b.end})
	}
	p.setTailLocked(mergeable, end)
}

// addUnmergeableLocked records that the last n bytes in the pipe are in new
// buffers that later writes don't append to, as link_pipe() copies them for a
// tee and Linux's splice_read implementations add them for a splice from a
// file that is not a pipe.
//
// +checklocks:p.mu
func (p *Pipe) addUnmergeableLocked(n int64) {
	p.endTailLocked(n)
	p.setTailLocked(false, 0)
}

// consumeSegsLocked drops the first n bytes from p.segs.
//
// +checklocks:p.mu
func (p *Pipe) consumeSegsLocked(n int64) {
	for n > 0 && len(p.segs) > 0 {
		if p.segs[0].size > n {
			p.segs[0].size -= n
			return
		}
		n -= p.segs[0].size
		if p.segs[0].packet {
			p.packets--
		}
		p.segs = p.segs[1:]
	}
	if len(p.segs) == 0 {
		p.segs = nil
	}
}

// layoutLocked returns the runs of the pipe's contents, or nil if the pipe
// holds no packet. The slice is valid only while p.mu is held.
//
// +checklocks:p.mu
func (p *Pipe) layoutLocked() []pipeSegment {
	return p.segs
}

// layoutLimit returns how many of the first count bytes of layout can be
// written to a pipe with free buffers for freePackets more packets. It stops
// before the first packet that does not fit.
func layoutLimit(count int64, layout []pipeSegment, freePackets int64) int64 {
	var limit int64
	for _, seg := range layout {
		if limit >= count {
			break
		}
		if seg.packet {
			if freePackets <= 0 {
				break
			}
			freePackets--
		}
		limit += seg.size
	}
	return min(limit, count)
}

// readLimitLocked returns how many of the first count bytes in the pipe one
// read may return, and how many bytes after them belong to the same packet.
// A read returns the stream bytes before the first packet, and then at most
// that one packet.
//
// +checklocks:p.mu
func (p *Pipe) readLimitLocked(count int64) (limit, discard int64) {
	var total int64
	for _, seg := range p.segs {
		if !seg.packet {
			if total+seg.size >= count {
				return count, 0
			}
			total += seg.size
			continue
		}
		take := min(seg.size, count-total)
		return total + take, seg.size - take
	}
	return count, 0
}
