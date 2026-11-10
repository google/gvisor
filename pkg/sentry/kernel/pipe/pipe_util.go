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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This file contains Pipe file functionality that is tied to neither VFS nor
// the old fs architecture.

// Release cleans up the pipe's state.
func (p *Pipe) Release(context.Context) {
	p.rClose()
	p.wClose()

	// Wake up readers and writers.
	p.queue.Notify(waiter.ReadableEvents | waiter.WritableEvents)
}

// Read reads from the Pipe into dst.
func (p *Pipe) Read(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	n, err := p.read(dst.NumBytes(), func(srcs safemem.BlockSeq) (uint64, error) {
		var done uint64
		for !srcs.IsEmpty() {
			src := srcs.Head()
			n, err := dst.CopyOut(ctx, src.ToSlice())
			done += uint64(n)
			if err != nil {
				return done, err
			}
			dst = dst.DropFirst(n)
			srcs = srcs.Tail()
		}
		return done, nil
	}, true /* removeFromSrc */)
	if n > 0 {
		p.queue.Notify(waiter.WritableEvents)
	}
	return n, err
}

func (p *Pipe) read(count int64, f func(srcs safemem.BlockSeq) (uint64, error), removeFromSrc bool) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	limit, discard := p.readLimitLocked(count)
	n, err := p.peekLocked(0, limit, f)
	if n > 0 && removeFromSrc {
		consumed := n
		if n == limit {
			// A read that ends inside a packet discards the rest of the
			// packet.
			consumed += discard
		}
		p.consumeLocked(consumed)
	}
	return n, err
}

// WriteTo writes to w from the Pipe.
func (p *Pipe) WriteTo(ctx context.Context, w io.Writer, count int64, dup bool) (int64, error) {
	n, err := p.read(count, func(srcs safemem.BlockSeq) (uint64, error) {
		return safemem.FromIOWriter{w}.WriteFromBlocks(srcs)
	}, !dup /* removeFromSrc */)
	if n > 0 && !dup {
		p.queue.Notify(waiter.WritableEvents)
	}
	return n, err
}

// Write writes to the Pipe from src.
func (p *Pipe) Write(ctx context.Context, src usermem.IOSequence) (int64, error) {
	n, err := p.write(src.NumBytes(), func(dsts safemem.BlockSeq) (uint64, error) {
		var done uint64
		for !dsts.IsEmpty() {
			dst := dsts.Head()
			n, err := src.CopyIn(ctx, dst.ToSlice())
			done += uint64(n)
			if err != nil {
				return done, err
			}
			src = src.DropFirst(n)
			dsts = dsts.Tail()
		}
		return done, nil
	})
	if n > 0 {
		p.queue.Notify(waiter.ReadableEvents)
	}
	if linuxerr.Equals(linuxerr.EPIPE, err) {
		// If we are returning EPIPE send SIGPIPE to the task.
		if sendSig := linux.SignalNoInfoFuncFromContext(ctx); sendSig != nil {
			sendSig(linux.SIGPIPE)
		}
	}
	return n, err
}

func (p *Pipe) write(count int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeLocked(count, f)
}

// WritePackets writes src to the Pipe in packet mode (O_DIRECT). See pipe(7).
// It splits the write into pages as fs/pipe.c:anon_pipe_write() does, and
// each page is one packet, which is written whole or not at all. Like Linux,
// it first appends len % PAGE_SIZE bytes to the last buffer of the pipe as
// stream data if that buffer holds stream data and has room for them. The
// pipe stays locked until the write ends or must wait, so the packets of one
// write are not interleaved with those of another.
func (p *Pipe) WritePackets(ctx context.Context, src usermem.IOSequence) (int64, error) {
	copyIn := func(dsts safemem.BlockSeq) (uint64, error) {
		var done uint64
		for !dsts.IsEmpty() {
			dst := dsts.Head()
			n, err := src.CopyIn(ctx, dst.ToSlice())
			done += uint64(n)
			if err != nil {
				return done, err
			}
			src = src.DropFirst(n)
			dsts = dsts.Tail()
		}
		return done, nil
	}
	var total int64
	var err error
	p.mu.Lock()
	for src.NumBytes() > 0 {
		var n int64
		n, err = p.writePacketLocked(src.NumBytes(), copyIn)
		total += n
		if err != nil {
			break
		}
	}
	p.mu.Unlock()
	if total > 0 {
		p.queue.Notify(waiter.ReadableEvents)
	}
	if linuxerr.Equals(linuxerr.EPIPE, err) {
		// If we are returning EPIPE send SIGPIPE to the task.
		if sendSig := linux.SignalNoInfoFuncFromContext(ctx); sendSig != nil {
			sendSig(linux.SIGPIPE)
		}
	}
	return total, err
}

// writePacketLocked writes the next part of a packet mode write with
// remaining bytes left to the Pipe. That is at most a page as one packet, or
// the bytes that Linux would append to the last buffer of the pipe.
//
// +checklocks:p.mu
func (p *Pipe) writePacketLocked(remaining int64, f func(safemem.BlockSeq) (uint64, error)) (int64, error) {
	pageSize := int64(hostarch.PageSize)
	if chars := remaining % pageSize; chars != 0 && p.canMergeLocked(chars) {
		return p.writeSegLocked(chars, false /* packet */, f)
	}
	return p.writeSegLocked(min(remaining, pageSize), true /* packet */, f)
}

// ReadFrom reads from r to the Pipe.
func (p *Pipe) ReadFrom(ctx context.Context, r io.Reader, count int64) (int64, error) {
	n, err := p.write(count, func(dsts safemem.BlockSeq) (uint64, error) {
		return safemem.FromIOReader{r}.ReadToBlocks(dsts)
	})
	if n > 0 {
		p.queue.Notify(waiter.ReadableEvents)
	}
	return n, err
}

// Readiness returns the ready events in the underlying pipe.
func (p *Pipe) Readiness(mask waiter.EventMask) waiter.EventMask {
	return p.rwReadiness() & mask
}

// Ioctl implements ioctls on the Pipe.
func (p *Pipe) Ioctl(ctx context.Context, io usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	// Switch on ioctl request.
	switch int(args[1].Int()) {
	case linux.FIONREAD:
		v := p.queued()
		if v > math.MaxInt32 {
			v = math.MaxInt32 // Silently truncate.
		}
		// Copy result to userspace.
		iocc := usermem.IOCopyContext{
			IO:  io,
			Ctx: ctx,
		}
		_, err := primitive.CopyInt32Out(&iocc, args[2].Pointer(), int32(v))
		return 0, err
	default:
		return 0, unix.ENOTTY
	}
}
