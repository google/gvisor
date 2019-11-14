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

package usermem

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/syserror"
)

const maxInt = int(^uint(0) >> 1)

// BytesIO implements IO using a byte slice. Addresses are interpreted as
// offsets into the slice. Reads and writes beyond the end of the slice return
// EFAULT.
type BytesIO struct {
	Bytes []byte
}

// CopyOut implements IO.CopyOut.
func (b *BytesIO) CopyOut(ctx context.Context, addr Addr, src []byte, opts IOOpts) (int, error) {
	rngN, rngErr := b.rangeCheck(addr, len(src))
	if rngN == 0 {
		return 0, rngErr
	}
	return copy(b.Bytes[int(addr):], src[:rngN]), rngErr
}

// CopyIn implements IO.CopyIn.
func (b *BytesIO) CopyIn(ctx context.Context, addr Addr, dst []byte, opts IOOpts) (int, error) {
	rngN, rngErr := b.rangeCheck(addr, len(dst))
	if rngN == 0 {
		return 0, rngErr
	}
	return copy(dst[:rngN], b.Bytes[int(addr):]), rngErr
}

// ZeroOut implements IO.ZeroOut.
func (b *BytesIO) ZeroOut(ctx context.Context, addr Addr, toZero int64, opts IOOpts) (int64, error) {
	if toZero > int64(maxInt) {
		return 0, syserror.EINVAL
	}
	rngN, rngErr := b.rangeCheck(addr, int(toZero))
	if rngN == 0 {
		return 0, rngErr
	}
	zeroSlice := b.Bytes[int(addr) : int(addr)+rngN]
	for i := range zeroSlice {
		zeroSlice[i] = 0
	}
	return int64(rngN), rngErr
}

// CopyOutFrom implements IO.CopyOutFrom.
func (b *BytesIO) CopyOutFrom(ctx context.Context, ars AddrRangeSeq, src safemem.Reader, opts IOOpts) (int64, error) {
	dsts, rngErr := b.blocksFromAddrRanges(ars)
	n, err := src.ReadToBlocks(dsts)
	if err != nil {
		return int64(n), err
	}
	return int64(n), rngErr
}

// CopyInTo implements IO.CopyInTo.
func (b *BytesIO) CopyInTo(ctx context.Context, ars AddrRangeSeq, dst safemem.Writer, opts IOOpts) (int64, error) {
	srcs, rngErr := b.blocksFromAddrRanges(ars)
	n, err := dst.WriteFromBlocks(srcs)
	if err != nil {
		return int64(n), err
	}
	return int64(n), rngErr
}

func (b *BytesIO) rangeCheck(addr Addr, length int) (int, error) {
	if length == 0 {
		return 0, nil
	}
	if length < 0 {
		return 0, syserror.EINVAL
	}
	max := Addr(len(b.Bytes))
	if addr >= max {
		return 0, syserror.EFAULT
	}
	end, ok := addr.AddLength(uint64(length))
	if !ok || end > max {
		return int(max - addr), syserror.EFAULT
	}
	return length, nil
}

func (b *BytesIO) blocksFromAddrRanges(ars AddrRangeSeq) (safemem.BlockSeq, error) {
	switch ars.NumRanges() {
	case 0:
		return safemem.BlockSeq{}, nil
	case 1:
		block, err := b.blockFromAddrRange(ars.Head())
		return safemem.BlockSeqOf(block), err
	default:
		blocks := make([]safemem.Block, 0, ars.NumRanges())
		for !ars.IsEmpty() {
			block, err := b.blockFromAddrRange(ars.Head())
			if block.Len() != 0 {
				blocks = append(blocks, block)
			}
			if err != nil {
				return safemem.BlockSeqFromSlice(blocks), err
			}
			ars = ars.Tail()
		}
		return safemem.BlockSeqFromSlice(blocks), nil
	}
}

func (b *BytesIO) blockFromAddrRange(ar AddrRange) (safemem.Block, error) {
	n, err := b.rangeCheck(ar.Start, int(ar.Length()))
	if n == 0 {
		return safemem.Block{}, err
	}
	return safemem.BlockFromSafeSlice(b.Bytes[int(ar.Start) : int(ar.Start)+n]), err
}

// BytesIOSequence returns an IOSequence representing the given byte slice.
func BytesIOSequence(buf []byte) IOSequence {
	return IOSequence{
		IO:    &BytesIO{buf},
		Addrs: AddrRangeSeqOf(AddrRange{0, Addr(len(buf))}),
	}
}
