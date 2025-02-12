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

package packetmmap

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// +stateify savable
type ringBuffer struct {
	framesPerBlock uint32
	frameSize      uint32
	frameMax       uint32
	blockSize      uint32
	numBlocks      uint32
	version        int

	// The following fields are protected by the owning endpoint's mutex.
	head       uint32
	rxOwnerMap bitmap.Bitmap

	dataMu sync.RWMutex `state:"nosave"`
	// +checklocks:dataMu
	size uint64
	// +checklocks:dataMu
	mapping memmap.MappableRange
	// +checklocks:dataMu
	data memmap.FileRange

	mf *pgalloc.MemoryFile `state:"nosave"`
}

// init initializes a PacketRingBuffer.
//
// The owning endpoint must be locked when calling this function.
func (rb *ringBuffer) init(ctx context.Context, req *tcpip.TpacketReq) error {
	rb.blockSize = req.TpBlockSize
	rb.framesPerBlock = req.TpBlockSize / req.TpFrameSize
	rb.frameMax = req.TpFrameNr - 1
	rb.frameSize = req.TpFrameSize
	rb.numBlocks = req.TpBlockNr

	rb.rxOwnerMap = bitmap.New(req.TpFrameNr)
	rb.head = 0

	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	rb.size = uint64(req.TpBlockSize) * uint64(req.TpBlockNr)
	mf := pgalloc.MemoryFileFromContext(ctx)
	if mf == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFile))
	}
	rb.mf = mf
	fr, err := rb.mf.Allocate(rb.size, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: pgalloc.MemoryCgroupIDFromContext(ctx)})
	if err != nil {
		return err
	}
	rb.mapping = memmap.MappableRange{Start: 0, End: rb.size}
	rb.data = fr
	return nil
}

// destroy destroys the packet ring buffer.
//
// The owning endpoint must be locked when calling this function.
func (rb *ringBuffer) destroy() {
	rb.dataMu.Lock()
	rb.mf.DecRef(rb.data)
	rb.dataMu.Unlock()
	*rb = ringBuffer{}
}

// AppendTranslation essentially implements memmap.Mappable.Translate, with the
// only difference being that it takes in a slice of translations and appends
// this ring buffer's translation.
func (rb *ringBuffer) AppendTranslation(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType, ts []memmap.Translation) ([]memmap.Translation, error) {
	rb.dataMu.Lock()
	defer rb.dataMu.Unlock()
	var beyondEOF bool
	if required.End > rb.size {
		if required.Start >= rb.size {
			return ts, &memmap.BusError{Err: io.EOF}
		}
		beyondEOF = true
		required.End = rb.size
	}
	if optional.End > rb.size {
		optional.End = rb.size
	}
	mappableRange := rb.mapping.Intersect(optional)
	ts = append(ts, memmap.Translation{
		Source: mappableRange,
		File:   rb.mf,
		Offset: rb.data.Start + (mappableRange.Start - rb.mapping.Start),
		Perms:  hostarch.AnyAccess,
	})
	if beyondEOF {
		return ts, &memmap.BusError{Err: io.EOF}
	}
	return ts, nil
}

// writeStatus writes the status of a frame to the ring buffer's internal
// mappings at the provided frame number. It also clears the owner map for the
// frame number if setting it to TP_STATUS_USER.
//
// The owning endpoint must be locked when calling this method.
func (rb *ringBuffer) writeStatus(frameNum uint32, status uint32) error {
	if status&linux.TP_STATUS_USER != 0 {
		rb.rxOwnerMap.Remove(frameNum)
	}
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Write)
	if err != nil {
		return err
	}
	// Status is the first uint32 in the frame. It is a uint64 in TPACKET_V1,
	// but is a uint32 in TPACKET_V2. In practice status is never larger than a
	// uint32 for either version.
	_, err = safemem.SwapUint32(ims.Head(), status)
	return err
}

// writeFrame writes a frame to the ring buffer's internal mappings at the
// provided frame number.
func (rb *ringBuffer) writeFrame(frameNum uint32, hdrView *buffer.View, pkt buffer.Buffer) error {
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Write)
	if err != nil {
		return err
	}
	frame := buffer.MakeWithView(hdrView)
	frame.Merge(&pkt)
	br := frame.AsBufferReader()
	defer br.Close()

	rdr := safemem.FromIOReader{Reader: &br}
	if _, err = rdr.ReadToBlocks(ims); err != nil {
		return err
	}
	return nil
}

// incHead increments the head of the ring buffer.
//
// The owning endpoint must be locked when calling this method.
func (rb *ringBuffer) incHead() {
	if rb.head == rb.frameMax {
		rb.head = 0
	} else {
		rb.head++
	}
}

// currFrameStatus returns the status of the current frame.
//
// The owning endpoint must be locked when calling this method.
func (rb *ringBuffer) currFrameStatus() (uint32, error) {
	return rb.frameStatus(rb.head)
}

// prevFrameStatus returns the status of the frame before the current
// frame.
//
// The owning endpoint must be locked when calling this method.
func (rb *ringBuffer) prevFrameStatus() (uint32, error) {
	prev := rb.head - 1
	if rb.head == 0 {
		prev = rb.frameMax
	}
	return rb.frameStatus(prev)
}

// testAndMarkHead tests whether the head slot is available and marks it
// as owned if it is.
//
// The owning endpoint must be locked when calling this method.
func (rb *ringBuffer) testAndMarkHead() (uint32, bool) {
	if firstZero, err := rb.rxOwnerMap.FirstZero(rb.head); err != nil || firstZero != rb.head {
		return 0, false
	}
	rb.rxOwnerMap.Add(rb.head)
	return rb.head, true

}

// hasRoom returns true if the ring buffer has room for a new frame at head.
//
// The owning endpoint must be locked when calling this method.
func (rb *ringBuffer) hasRoom() bool {
	status, err := rb.currFrameStatus()
	if err != nil {
		return false
	}
	return status == linux.TP_STATUS_KERNEL
}

// bufferSize returns the size of the ring buffer in bytes.
func (rb *ringBuffer) bufferSize() uint64 {
	rb.dataMu.RLock()
	defer rb.dataMu.RUnlock()
	return rb.size
}

func (rb *ringBuffer) internalMappingsForFrame(frameNum uint32, at hostarch.AccessType) (safemem.BlockSeq, error) {
	rb.dataMu.RLock()
	defer rb.dataMu.RUnlock()

	blockIdx := uint32(frameNum / rb.framesPerBlock)
	frameIdx := uint32(frameNum % rb.framesPerBlock)

	frameStart := rb.data.Start + (uint64(blockIdx) * uint64(rb.blockSize)) + (uint64(frameIdx) * uint64(rb.frameSize))
	frameEnd := frameStart + uint64(rb.frameSize)

	frameFR := memmap.FileRange{Start: frameStart, End: frameEnd}
	return rb.mf.MapInternal(frameFR, at)
}

func (rb *ringBuffer) frameStatus(frameNum uint32) (uint32, error) {
	ims, err := rb.internalMappingsForFrame(frameNum, hostarch.Read)
	if err != nil {
		return 0, err
	}
	// Status is the first uint32 in the frame.
	return safemem.LoadUint32(ims.Head())
}
