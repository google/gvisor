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

// Package usermem governs access to user memory.
package usermem

import (
	"errors"
	"io"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// IO provides access to the contents of a virtual memory space.
//
// FIXME: Implementations of IO cannot expect ctx to contain any
// meaningful data.
type IO interface {
	// CopyOut copies len(src) bytes from src to the memory mapped at addr. It
	// returns the number of bytes copied. If the number of bytes copied is <
	// len(src), it returns a non-nil error explaining why.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order.
	CopyOut(ctx context.Context, addr Addr, src []byte, opts IOOpts) (int, error)

	// CopyIn copies len(dst) bytes from the memory mapped at addr to dst.
	// It returns the number of bytes copied. If the number of bytes copied is
	// < len(dst), it returns a non-nil error explaining why.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order.
	CopyIn(ctx context.Context, addr Addr, dst []byte, opts IOOpts) (int, error)

	// ZeroOut sets toZero bytes to 0, starting at addr. It returns the number
	// of bytes zeroed. If the number of bytes zeroed is < toZero, it returns a
	// non-nil error explaining why.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order. toZero >= 0.
	ZeroOut(ctx context.Context, addr Addr, toZero int64, opts IOOpts) (int64, error)

	// CopyOutFrom copies ars.NumBytes() bytes from src to the memory mapped at
	// ars. It returns the number of bytes copied, which may be less than the
	// number of bytes read from src if copying fails. CopyOutFrom may return a
	// partial copy without an error iff src.ReadToBlocks returns a partial
	// read without an error.
	//
	// CopyOutFrom calls src.ReadToBlocks at most once.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order. src.ReadToBlocks must not block
	// on mm.MemoryManager.activeMu or any preceding locks in the lock order.
	CopyOutFrom(ctx context.Context, ars AddrRangeSeq, src safemem.Reader, opts IOOpts) (int64, error)

	// CopyInTo copies ars.NumBytes() bytes from the memory mapped at ars to
	// dst. It returns the number of bytes copied. CopyInTo may return a
	// partial copy without an error iff dst.WriteFromBlocks returns a partial
	// write without an error.
	//
	// CopyInTo calls dst.WriteFromBlocks at most once.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order. dst.WriteFromBlocks must not
	// block on mm.MemoryManager.activeMu or any preceding locks in the lock
	// order.
	CopyInTo(ctx context.Context, ars AddrRangeSeq, dst safemem.Writer, opts IOOpts) (int64, error)

	// TODO: The requirement that CopyOutFrom/CopyInTo call src/dst
	// at most once, which is unnecessary in most cases, forces implementations
	// to gather safemem.Blocks into a single slice to pass to src/dst. Add
	// CopyOutFromIter/CopyInToIter, which relaxes this restriction, to avoid
	// this allocation.

	// SwapUint32 atomically sets the uint32 value at addr to new and
	// returns the previous value.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order. addr must be aligned to a 4-byte
	// boundary.
	SwapUint32(ctx context.Context, addr Addr, new uint32, opts IOOpts) (uint32, error)

	// CompareAndSwapUint32 atomically compares the uint32 value at addr to
	// old; if they are equal, the value in memory is replaced by new. In
	// either case, the previous value stored in memory is returned.
	//
	// Preconditions: The caller must not hold mm.MemoryManager.mappingMu or
	// any following locks in the lock order. addr must be aligned to a 4-byte
	// boundary.
	CompareAndSwapUint32(ctx context.Context, addr Addr, old, new uint32, opts IOOpts) (uint32, error)
}

// IOOpts contains options applicable to all IO methods.
type IOOpts struct {
	// If IgnorePermissions is true, application-defined memory protections set
	// by mmap(2) or mprotect(2) will be ignored. (Memory protections required
	// by the target of the mapping are never ignored.)
	IgnorePermissions bool

	// If AddressSpaceActive is true, the IO implementation may assume that it
	// has an active AddressSpace and can therefore use AddressSpace copying
	// without performing activation. See mm/io.go for details.
	AddressSpaceActive bool
}

// IOReadWriter is an io.ReadWriter that reads from / writes to addresses
// starting at addr in IO. The preconditions that apply to IO.CopyIn and
// IO.CopyOut also apply to IOReadWriter.Read and IOReadWriter.Write
// respectively.
type IOReadWriter struct {
	Ctx  context.Context
	IO   IO
	Addr Addr
	Opts IOOpts
}

// Read implements io.Reader.Read.
//
// Note that an address space does not have an "end of file", so Read can only
// return io.EOF if IO.CopyIn returns io.EOF. Attempts to read unmapped or
// unreadable memory, or beyond the end of the address space, should return
// EFAULT.
func (rw *IOReadWriter) Read(dst []byte) (int, error) {
	n, err := rw.IO.CopyIn(rw.Ctx, rw.Addr, dst, rw.Opts)
	end, ok := rw.Addr.AddLength(uint64(n))
	if ok {
		rw.Addr = end
	} else {
		// Disallow wraparound.
		rw.Addr = ^Addr(0)
		if err != nil {
			err = syserror.EFAULT
		}
	}
	return n, err
}

// Writer implements io.Writer.Write.
func (rw *IOReadWriter) Write(src []byte) (int, error) {
	n, err := rw.IO.CopyOut(rw.Ctx, rw.Addr, src, rw.Opts)
	end, ok := rw.Addr.AddLength(uint64(n))
	if ok {
		rw.Addr = end
	} else {
		// Disallow wraparound.
		rw.Addr = ^Addr(0)
		if err != nil {
			err = syserror.EFAULT
		}
	}
	return n, err
}

// CopyObjectOut copies a fixed-size value or slice of fixed-size values from
// src to the memory mapped at addr in uio. It returns the number of bytes
// copied.
//
// CopyObjectOut must use reflection to encode src; performance-sensitive
// clients should do encoding manually and use uio.CopyOut directly.
//
// Preconditions: As for IO.CopyOut.
func CopyObjectOut(ctx context.Context, uio IO, addr Addr, src interface{}, opts IOOpts) (int, error) {
	w := &IOReadWriter{
		Ctx:  ctx,
		IO:   uio,
		Addr: addr,
		Opts: opts,
	}
	return w.Write(binary.Marshal(nil, ByteOrder, src))
}

// CopyObjectIn copies a fixed-size value or slice of fixed-size values from
// the memory mapped at addr in uio to dst. It returns the number of bytes
// copied.
//
// CopyObjectIn must use reflection to decode dst; performance-sensitive
// clients should use uio.CopyIn directly and do decoding manually.
//
// Preconditions: As for IO.CopyIn.
func CopyObjectIn(ctx context.Context, uio IO, addr Addr, dst interface{}, opts IOOpts) (int, error) {
	r := &IOReadWriter{
		Ctx:  ctx,
		IO:   uio,
		Addr: addr,
		Opts: opts,
	}
	buf := make([]byte, binary.Size(dst))
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	binary.Unmarshal(buf, ByteOrder, dst)
	return int(r.Addr - addr), nil
}

// copyStringIncrement is the maximum number of bytes that are copied from
// virtual memory at a time by CopyStringIn.
const copyStringIncrement = 64

// CopyStringIn copies a NUL-terminated string of unknown length from the
// memory mapped at addr in uio and returns it as a string (not including the
// trailing NUL). If the length of the string, including the terminating NUL,
// would exceed maxlen, CopyStringIn returns the string truncated to maxlen and
// ENAMETOOLONG.
//
// Preconditions: As for IO.CopyFromUser. maxlen >= 0.
func CopyStringIn(ctx context.Context, uio IO, addr Addr, maxlen int, opts IOOpts) (string, error) {
	buf := make([]byte, maxlen)
	var done int
	for done < maxlen {
		start, ok := addr.AddLength(uint64(done))
		if !ok {
			// Last page of kernel memory. The application can't use this
			// anyway.
			return string(buf[:done]), syserror.EFAULT
		}
		// Read up to copyStringIncrement bytes at a time.
		readlen := copyStringIncrement
		if readlen > maxlen-done {
			readlen = maxlen - done
		}
		end, ok := start.AddLength(uint64(readlen))
		if !ok {
			return string(buf[:done]), syserror.EFAULT
		}
		// Shorten the read to avoid crossing page boundaries, since faulting
		// in a page unnecessarily is expensive. This also ensures that partial
		// copies up to the end of application-mappable memory succeed.
		if start.RoundDown() != end.RoundDown() {
			end = end.RoundDown()
		}
		n, err := uio.CopyIn(ctx, start, buf[done:done+int(end-start)], opts)
		// Look for the terminating zero byte, which may have occurred before
		// hitting err.
		for i, c := range buf[done : done+n] {
			if c == 0 {
				return string(buf[:done+i]), nil
			}
		}
		done += n
		if err != nil {
			return string(buf[:done]), err
		}
	}
	return string(buf), syserror.ENAMETOOLONG
}

// CopyOutVec copies bytes from src to the memory mapped at ars in uio. The
// maximum number of bytes copied is ars.NumBytes() or len(src), whichever is
// less. CopyOutVec returns the number of bytes copied; if this is less than
// the maximum, it returns a non-nil error explaining why.
//
// Preconditions: As for IO.CopyOut.
func CopyOutVec(ctx context.Context, uio IO, ars AddrRangeSeq, src []byte, opts IOOpts) (int, error) {
	var done int
	for !ars.IsEmpty() && done < len(src) {
		ar := ars.Head()
		cplen := len(src) - done
		if Addr(cplen) >= ar.Length() {
			cplen = int(ar.Length())
		}
		n, err := uio.CopyOut(ctx, ar.Start, src[done:done+cplen], opts)
		done += n
		if err != nil {
			return done, err
		}
		ars = ars.DropFirst(n)
	}
	return done, nil
}

// CopyInVec copies bytes from the memory mapped at ars in uio to dst. The
// maximum number of bytes copied is ars.NumBytes() or len(dst), whichever is
// less. CopyInVec returns the number of bytes copied; if this is less than the
// maximum, it returns a non-nil error explaining why.
//
// Preconditions: As for IO.CopyIn.
func CopyInVec(ctx context.Context, uio IO, ars AddrRangeSeq, dst []byte, opts IOOpts) (int, error) {
	var done int
	for !ars.IsEmpty() && done < len(dst) {
		ar := ars.Head()
		cplen := len(dst) - done
		if Addr(cplen) >= ar.Length() {
			cplen = int(ar.Length())
		}
		n, err := uio.CopyIn(ctx, ar.Start, dst[done:done+cplen], opts)
		done += n
		if err != nil {
			return done, err
		}
		ars = ars.DropFirst(n)
	}
	return done, nil
}

// ZeroOutVec writes zeroes to the memory mapped at ars in uio. The maximum
// number of bytes written is ars.NumBytes() or toZero, whichever is less.
// ZeroOutVec returns the number of bytes written; if this is less than the
// maximum, it returns a non-nil error explaining why.
//
// Preconditions: As for IO.ZeroOut.
func ZeroOutVec(ctx context.Context, uio IO, ars AddrRangeSeq, toZero int64, opts IOOpts) (int64, error) {
	var done int64
	for !ars.IsEmpty() && done < toZero {
		ar := ars.Head()
		cplen := toZero - done
		if Addr(cplen) >= ar.Length() {
			cplen = int64(ar.Length())
		}
		n, err := uio.ZeroOut(ctx, ar.Start, cplen, opts)
		done += n
		if err != nil {
			return done, err
		}
		ars = ars.DropFirst64(n)
	}
	return done, nil
}

func isASCIIWhitespace(b byte) bool {
	// Compare Linux include/linux/ctype.h, lib/ctype.c.
	//  9 => horizontal tab '\t'
	// 10 => line feed '\n'
	// 11 => vertical tab '\v'
	// 12 => form feed '\c'
	// 13 => carriage return '\r'
	return b == ' ' || (b >= 9 && b <= 13)
}

// CopyInt32StringsInVec copies up to len(dsts) whitespace-separated decimal
// strings from the memory mapped at ars in uio and converts them to int32
// values in dsts. It returns the number of bytes read.
//
// CopyInt32StringsInVec shares the following properties with Linux's
// kernel/sysctl.c:proc_dointvec(write=1):
//
// - If any read value overflows the range of int32, or any invalid characters
// are encountered during the read, CopyInt32StringsInVec returns EINVAL.
//
// - If, upon reaching the end of ars, fewer than len(dsts) values have been
// read, CopyInt32StringsInVec returns no error if at least 1 value was read
// and EINVAL otherwise.
//
// - Trailing whitespace after the last successfully read value is counted in
// the number of bytes read.
//
// Unlike proc_dointvec():
//
// - CopyInt32StringsInVec does not implicitly limit ars.NumBytes() to
// PageSize-1; callers that require this must do so explicitly.
//
// - CopyInt32StringsInVec returns EINVAL if ars.NumBytes() == 0.
//
// Preconditions: As for CopyInVec.
func CopyInt32StringsInVec(ctx context.Context, uio IO, ars AddrRangeSeq, dsts []int32, opts IOOpts) (int64, error) {
	if len(dsts) == 0 {
		return 0, nil
	}

	buf := make([]byte, ars.NumBytes())
	n, cperr := CopyInVec(ctx, uio, ars, buf, opts)
	buf = buf[:n]

	var i, j int
	for ; j < len(dsts); j++ {
		// Skip leading whitespace.
		for i < len(buf) && isASCIIWhitespace(buf[i]) {
			i++
		}
		if i == len(buf) {
			break
		}

		// Find the end of the value to be parsed (next whitespace or end of string).
		nextI := i + 1
		for nextI < len(buf) && !isASCIIWhitespace(buf[nextI]) {
			nextI++
		}

		// Parse a single value.
		val, err := strconv.ParseInt(string(buf[i:nextI]), 10, 32)
		if err != nil {
			return int64(i), syserror.EINVAL
		}
		dsts[j] = int32(val)

		i = nextI
	}

	// Skip trailing whitespace.
	for i < len(buf) && isASCIIWhitespace(buf[i]) {
		i++
	}

	if cperr != nil {
		return int64(i), cperr
	}
	if j == 0 {
		return int64(i), syserror.EINVAL
	}
	return int64(i), nil
}

// CopyInt32StringInVec is equivalent to CopyInt32StringsInVec, but copies at
// most one int32.
func CopyInt32StringInVec(ctx context.Context, uio IO, ars AddrRangeSeq, dst *int32, opts IOOpts) (int64, error) {
	dsts := [1]int32{*dst}
	n, err := CopyInt32StringsInVec(ctx, uio, ars, dsts[:], opts)
	*dst = dsts[0]
	return n, err
}

// IOSequence holds arguments to IO methods.
type IOSequence struct {
	IO    IO
	Addrs AddrRangeSeq
	Opts  IOOpts
}

// NumBytes returns s.Addrs.NumBytes().
//
// Note that NumBytes() may return 0 even if !s.Addrs.IsEmpty(), since
// s.Addrs may contain a non-zero number of zero-length AddrRanges.
// Many clients of
// IOSequence currently do something like:
//
//     if ioseq.NumBytes() == 0 {
//       return 0, nil
//     }
//     if f.availableBytes == 0 {
//       return 0, syserror.ErrWouldBlock
//     }
//     return ioseq.CopyOutFrom(..., reader)
//
// In such cases, using s.Addrs.IsEmpty() will cause them to have the wrong
// behavior for zero-length I/O. However, using s.NumBytes() == 0 instead means
// that we will return success for zero-length I/O in cases where Linux would
// return EFAULT due to a failed access_ok() check, so in the long term we
// should move checks for ErrWouldBlock etc. into the body of
// reader.ReadToBlocks and use s.Addrs.IsEmpty() instead.
func (s IOSequence) NumBytes() int64 {
	return s.Addrs.NumBytes()
}

// DropFirst returns a copy of s with s.Addrs.DropFirst(n).
//
// Preconditions: As for AddrRangeSeq.DropFirst.
func (s IOSequence) DropFirst(n int) IOSequence {
	return IOSequence{s.IO, s.Addrs.DropFirst(n), s.Opts}
}

// DropFirst64 returns a copy of s with s.Addrs.DropFirst64(n).
//
// Preconditions: As for AddrRangeSeq.DropFirst64.
func (s IOSequence) DropFirst64(n int64) IOSequence {
	return IOSequence{s.IO, s.Addrs.DropFirst64(n), s.Opts}
}

// TakeFirst returns a copy of s with s.Addrs.TakeFirst(n).
//
// Preconditions: As for AddrRangeSeq.TakeFirst.
func (s IOSequence) TakeFirst(n int) IOSequence {
	return IOSequence{s.IO, s.Addrs.TakeFirst(n), s.Opts}
}

// TakeFirst64 returns a copy of s with s.Addrs.TakeFirst64(n).
//
// Preconditions: As for AddrRangeSeq.TakeFirst64.
func (s IOSequence) TakeFirst64(n int64) IOSequence {
	return IOSequence{s.IO, s.Addrs.TakeFirst64(n), s.Opts}
}

// CopyOut invokes CopyOutVec over s.Addrs.
//
// As with CopyOutVec, if s.NumBytes() < len(src), the copy will be truncated
// to s.NumBytes(), and a nil error will be returned.
//
// Preconditions: As for CopyOutVec.
func (s IOSequence) CopyOut(ctx context.Context, src []byte) (int, error) {
	return CopyOutVec(ctx, s.IO, s.Addrs, src, s.Opts)
}

// CopyIn invokes CopyInVec over s.Addrs.
//
// As with CopyInVec, if s.NumBytes() < len(dst), the copy will be truncated to
// s.NumBytes(), and a nil error will be returned.
//
// Preconditions: As for CopyInVec.
func (s IOSequence) CopyIn(ctx context.Context, dst []byte) (int, error) {
	return CopyInVec(ctx, s.IO, s.Addrs, dst, s.Opts)
}

// ZeroOut invokes ZeroOutVec over s.Addrs.
//
// As with ZeroOutVec, if s.NumBytes() < toZero, the write will be truncated
// to s.NumBytes(), and a nil error will be returned.
//
// Preconditions: As for ZeroOutVec.
func (s IOSequence) ZeroOut(ctx context.Context, toZero int64) (int64, error) {
	return ZeroOutVec(ctx, s.IO, s.Addrs, toZero, s.Opts)
}

// CopyOutFrom invokes s.CopyOutFrom over s.Addrs.
//
// Preconditions: As for IO.CopyOutFrom.
func (s IOSequence) CopyOutFrom(ctx context.Context, src safemem.Reader) (int64, error) {
	return s.IO.CopyOutFrom(ctx, s.Addrs, src, s.Opts)
}

// CopyInTo invokes s.CopyInTo over s.Addrs.
//
// Preconditions: As for IO.CopyInTo.
func (s IOSequence) CopyInTo(ctx context.Context, dst safemem.Writer) (int64, error) {
	return s.IO.CopyInTo(ctx, s.Addrs, dst, s.Opts)
}

// Reader returns an io.Reader that reads from s. Reads beyond the end of s
// return io.EOF. The preconditions that apply to s.CopyIn also apply to the
// returned io.Reader.Read.
func (s IOSequence) Reader(ctx context.Context) io.Reader {
	return &ioSequenceReadWriter{ctx, s}
}

// Writer returns an io.Writer that writes to s. Writes beyond the end of s
// return ErrEndOfIOSequence. The preconditions that apply to s.CopyOut also
// apply to the returned io.Writer.Write.
func (s IOSequence) Writer(ctx context.Context) io.Writer {
	return &ioSequenceReadWriter{ctx, s}
}

// ErrEndOfIOSequence is returned by IOSequence.Writer().Write() when
// attempting to write beyond the end of the IOSequence.
var ErrEndOfIOSequence = errors.New("write beyond end of IOSequence")

type ioSequenceReadWriter struct {
	ctx context.Context
	s   IOSequence
}

// Read implements io.Reader.Read.
func (rw *ioSequenceReadWriter) Read(dst []byte) (int, error) {
	n, err := rw.s.CopyIn(rw.ctx, dst)
	rw.s = rw.s.DropFirst(n)
	if err == nil && rw.s.NumBytes() == 0 {
		err = io.EOF
	}
	return n, err
}

// Write implements io.Writer.Write.
func (rw *ioSequenceReadWriter) Write(src []byte) (int, error) {
	n, err := rw.s.CopyOut(rw.ctx, src)
	rw.s = rw.s.DropFirst(n)
	if err == nil && n < len(src) {
		err = ErrEndOfIOSequence
	}
	return n, err
}
