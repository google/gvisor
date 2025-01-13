// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package packet contains implementations specific to packet sockets.
package packet

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// RingBuffer holds the state of a packet ring buffer as described in
// https://docs.kernel.org/networking/packet_mmap.html. It is used to
// implement the PACKET_MMAP interface. It is always used with a packet
// endpoint, and certain methods must only be called with the endpoint's
// receive mutex held.
type RingBuffer struct {
	framesPerBlock uint32
	frameSize      uint32
	frameMax       uint32
	blockSize      uint32
	numBlocks      uint32
	mapped         bool

	// Any access to the following fields must be protected by the encapsulating
	// packet endpoint's receive mutex.
	head       uint32
	rxOwnerMap map[uint32]struct{}

	dataMu sync.RWMutex
	// +checklocks:dataMu
	size uint64
	// +checklocks:dataMu
	mappedData fsutil.FileRangeSet

	mf *pgalloc.MemoryFile
}

// Init initializes a PacketRingBuffer.
func (rb *RingBuffer) Init(req *tcpip.TpacketReq) tcpip.Error {
	if rb.mapped {
		return &tcpip.ErrEndpointBusy{}
	}
	if req.TpBlockNr != 0 {
		if req.TpBlockSize <= 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		if req.TpBlockSize%hostarch.PageSize != 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		if req.TpFrameSize < uint32(linux.TPACKET_HDRLEN) {
			return &tcpip.ErrInvalidOptionValue{}
		}
		if req.TpFrameSize&(linux.TPACKET_ALIGNMENT-1) != 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		rb.framesPerBlock = req.TpBlockSize / req.TpFrameSize
		if rb.framesPerBlock == 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		if rb.framesPerBlock > ^uint32(0)/req.TpFrameSize {
			return &tcpip.ErrInvalidOptionValue{}
		}
		if rb.framesPerBlock*req.TpFrameSize != req.TpBlockSize {
			return &tcpip.ErrInvalidOptionValue{}
		}
	} else {
		if req.TpFrameNr != 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}
	}

	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	rb.blockSize = req.TpBlockSize
	rb.frameMax = req.TpFrameNr - 1
	rb.size = uint64(req.TpBlockSize) * uint64(req.TpBlockNr)
	rb.rxOwnerMap = make(map[uint32]struct{}, req.TpFrameNr)
	rb.frameSize = req.TpFrameSize
	rb.numBlocks = req.TpBlockNr
	return nil
}

// Destroy destroys the packet ring buffer.
//
// Precondition: The encapsulating packet endpoint must hold rcvMu.
func (rb *RingBuffer) Destroy() {
	rb.dataMu.Lock()
	rb.mappedData.DropAll(rb.mf)
	rb.dataMu.Unlock()
	*rb = RingBuffer{}
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (rb *RingBuffer) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	if opts.Length != rb.size {
		return linuxerr.EINVAL
	}
	mf := pgalloc.MemoryFileFromContext(ctx)
	if mf == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFile))
	}
	rb.mf = mf
	// The mapped data is empty at this point, so we know any gap will be large
	// enough to hold the requested number of blocks.
	gap := rb.mappedData.FindGap(opts.Offset)
	if !gap.Ok() {
		return linuxerr.EINVAL
	}
	for i := uint32(opts.Offset); i < rb.numBlocks; i++ {
		start := uint64(i * rb.blockSize)
		end := start + uint64(rb.blockSize)
		fr, err := rb.mf.Allocate(uint64(rb.blockSize), pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: pgalloc.MemoryCgroupIDFromContext(ctx)})
		if err != nil {
			return err
		}
		gap = rb.mappedData.Insert(gap, memmap.MappableRange{Start: start, End: end}, fr.Start).NextGap()
	}
	rb.mapped = true
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (rb *RingBuffer) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	var beyondEOF bool
	if required.End > rb.size {
		if required.Start >= rb.size {
			return nil, &memmap.BusError{Err: io.EOF}
		}
		beyondEOF = true
		required.End = rb.size
	}
	if optional.End > rb.size {
		optional.End = rb.size
	}
	var ts []memmap.Translation
	for seg := rb.mappedData.FindSegment(required.Start); seg.Ok() && seg.Start() < required.End; seg, _ = seg.NextNonEmpty() {
		segMR := seg.Range().Intersect(optional)
		ts = append(ts, memmap.Translation{
			Source: segMR,
			File:   rb.mf,
			Offset: seg.FileRangeOf(segMR).Start,
			Perms:  hostarch.AnyAccess,
		})
	}
	if beyondEOF {
		return ts, &memmap.BusError{Err: io.EOF}
	}
	return ts, nil
}

// WriteFrameStatus writes the status of a frame to the ring buffer's internal
// mappings at the provided frame number. It also clears the owner map for the
// frame number if setting it to TP_STATUS_USER.
//
// Precondition: The encapsulating packet endpoint must hold rcvMu.
func (rb *RingBuffer) WriteFrameStatus(frameNum uint32, status uint64) error {
	if status&linux.TP_STATUS_USER != 0 {
		defer func() {
			delete(rb.rxOwnerMap, frameNum)
		}()
	}
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Write)
	if err != nil {
		return err
	}
	// Status is the first uint64 in the frame.
	hostarch.ByteOrder.PutUint64(ims.Head().ToSlice()[:8], status)
	return nil
}

// WriteFrame writes a frame to the ring buffer's internal mappings at the
// provided frame number.
func (rb *RingBuffer) WriteFrame(frameNum uint32, hdr linux.TpacketHdr, pktOffset uint32, pkt buffer.Buffer) error {
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Write)
	if err != nil {
		return err
	}
	// The status is set separately to ensure the frame is written before the
	// status is set.
	hdr.TpStatus = linux.TP_STATUS_KERNEL
	hdrBytes := marshal.Marshal(&hdr)
	frame := buffer.MakeWithData(hdrBytes)
	frame.GrowTo(int64(pktOffset), true)
	frame.Merge(&pkt)
	br := frame.AsBufferReader()
	defer br.Close()

	rdr := safemem.FromIOReader{Reader: &br}
	if _, err = rdr.ReadToBlocks(ims); err != nil {
		return err
	}
	return nil
}

// IncrementHead increments the head of the ring buffer.
//
// Precondition: The encapsulating packet endpoint must hold rcvMu.
func (rb *RingBuffer) IncrementHead() {
	if rb.head == rb.frameMax {
		rb.head = 0
	} else {
		rb.head++
	}
}

// CurrentFrameStatus returns the status of the current frame.
//
// Precondition: The encapsulating packet endpoint must hold rcvMu.
func (rb *RingBuffer) CurrentFrameStatus() (uint64, error) {
	return rb.frameStatus(rb.head)
}

// PreviousFrameStatus returns the status of the frame before the current
// frame.
//
// Precondition: The encapsulating packet endpoint must hold rcvMu.
func (rb *RingBuffer) PreviousFrameStatus() (uint64, error) {
	prev := rb.head - 1
	if rb.head == 0 {
		prev = rb.frameMax
	}
	return rb.frameStatus(prev)
}

// TestAndMarkHeadSlot tests whether the head slot is available and marks it
// as owned if it is.
//
// Precondition: The encapsulating packet endpoint must hold rcvMu.
func (rb *RingBuffer) TestAndMarkHeadSlot() (uint32, bool) {
	if _, ok := rb.rxOwnerMap[rb.head]; ok {
		return 0, false
	}
	rb.rxOwnerMap[rb.head] = struct{}{}
	return rb.head, true

}

// HasRoom returns true if the ring buffer has room for a new frame at head.
func (rb *RingBuffer) HasRoom() bool {
	status, err := rb.CurrentFrameStatus()
	if err != nil {
		return false
	}
	return status == linux.TP_STATUS_KERNEL
}

// FrameSize returns the size of a frame in the ring buffer.
func (rb *RingBuffer) FrameSize() uint32 {
	return rb.frameSize
}

// Size returns the size of the ring buffer in bytes.
func (rb *RingBuffer) Size() uint64 {
	rb.dataMu.RLock()
	defer rb.dataMu.RUnlock()
	return rb.size
}

func (rb *RingBuffer) internalMappingsForFrame(frameNum uint32, at hostarch.AccessType) (safemem.BlockSeq, error) {
	rb.dataMu.RLock()
	defer rb.dataMu.RUnlock()

	blockIdx := uint32(frameNum / rb.framesPerBlock)
	frameIdx := uint32(frameNum % rb.framesPerBlock)

	seg := rb.mappedData.LowerBoundSegment(uint64(blockIdx * rb.blockSize))
	if !seg.Ok() {
		return safemem.BlockSeq{}, linuxerr.EFAULT
	}
	frameStart := seg.FileRange().Start + (uint64(blockIdx) * uint64(rb.blockSize)) + (uint64(frameIdx) * uint64(rb.frameSize))
	frameEnd := frameStart + uint64(rb.frameSize)

	frameFR := memmap.FileRange{Start: frameStart, End: frameEnd}
	return rb.mf.MapInternal(frameFR, at)
}

func (rb *RingBuffer) frameStatus(frameNum uint32) (uint64, error) {
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Read)
	if err != nil {
		return 0, err
	}
	// Status is the first uint64 in the frame.
	return hostarch.ByteOrder.Uint64(ims.Head().ToSlice()[:8]), err
}
