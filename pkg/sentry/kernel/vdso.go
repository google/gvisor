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

package kernel

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

// vdsoParams are the parameters exposed to the VDSO.
//
// They are exposed to the VDSO via a parameter page managed by VDSOParamPage,
// which also includes a sequence counter.
//
// +marshal
type vdsoParams struct {
	monotonicReady      uint64
	monotonicBaseCycles int64
	monotonicBaseRef    int64
	monotonicFrequency  uint64

	realtimeReady      uint64
	realtimeBaseCycles int64
	realtimeBaseRef    int64
	realtimeFrequency  uint64
}

// VDSOParamPage manages a VDSO parameter page.
//
// Its memory layout looks like:
//
//	type page struct {
//		// seq is a sequence counter that protects the fields below.
//		seq uint64
//		vdsoParams
//	}
//
// Everything in the struct is 8 bytes for easy alignment.
//
// It must be kept in sync with params in vdso/vdso_time.cc.
//
// +stateify savable
type VDSOParamPage struct {
	// The parameter page is fr, allocated from mfp.MemoryFile().
	mfp pgalloc.MemoryFileProvider
	fr  memmap.FileRange

	// seq is the current sequence count written to the page.
	//
	// A write is in progress if bit 1 of the counter is set.
	//
	// Timekeeper's updater goroutine may call Write before equality is
	// checked in state_test_util tests, causing this field to change across
	// save / restore.
	seq uint64

	// copyScratchBuffer is a temporary buffer used to marshal the params before
	// copying it to the real parameter page. The parameter page is typically
	// updated at a moderate frequency of ~O(seconds) throughout the lifetime of
	// the sentry, so reusing this buffer is a good tradeoff between memory
	// usage and the cost of allocation.
	copyScratchBuffer []byte
}

// NewVDSOParamPage returns a VDSOParamPage.
//
// Preconditions:
//   - fr is a single page allocated from mfp.MemoryFile(). VDSOParamPage does
//     not take ownership of fr; it must remain allocated for the lifetime of the
//     VDSOParamPage.
//   - VDSOParamPage must be the only writer to fr.
//   - mfp.MemoryFile().MapInternal(fr) must return a single safemem.Block.
func NewVDSOParamPage(mfp pgalloc.MemoryFileProvider, fr memmap.FileRange) *VDSOParamPage {
	return &VDSOParamPage{
		mfp:               mfp,
		fr:                fr,
		copyScratchBuffer: make([]byte, (*vdsoParams)(nil).SizeBytes()),
	}
}

// access returns a mapping of the param page.
func (v *VDSOParamPage) access() (safemem.Block, error) {
	bs, err := v.mfp.MemoryFile().MapInternal(v.fr, hostarch.ReadWrite)
	if err != nil {
		return safemem.Block{}, err
	}
	if bs.NumBlocks() != 1 {
		panic(fmt.Sprintf("Multiple blocks (%d) in VDSO param BlockSeq", bs.NumBlocks()))
	}
	return bs.Head(), nil
}

// incrementSeq increments the sequence counter in the param page.
func (v *VDSOParamPage) incrementSeq(paramPage safemem.Block) error {
	next := v.seq + 1
	old, err := safemem.SwapUint64(paramPage, next)
	if err != nil {
		return err
	}

	if old != v.seq {
		return fmt.Errorf("unexpected VDSOParamPage seq value: got %d expected %d; application may hang or get incorrect time from the VDSO", old, v.seq)
	}

	v.seq = next
	return nil
}

// Write updates the VDSO parameters.
//
// Write starts a write block, calls f to get the new parameters, writes
// out the new parameters, then ends the write block.
func (v *VDSOParamPage) Write(f func() vdsoParams) error {
	paramPage, err := v.access()
	if err != nil {
		return err
	}

	// Write begin.
	next := v.seq + 1
	if next%2 != 1 {
		panic("Out-of-order sequence count")
	}

	err = v.incrementSeq(paramPage)
	if err != nil {
		return err
	}

	// Get the new params.
	p := f()
	buf := v.copyScratchBuffer[:p.SizeBytes()]
	p.MarshalUnsafe(buf)

	// Skip the sequence counter.
	if _, err := safemem.Copy(paramPage.DropFirst(8), safemem.BlockFromSafeSlice(buf)); err != nil {
		panic(fmt.Sprintf("Unable to get set VDSO parameters: %v", err))
	}

	// Write end.
	return v.incrementSeq(paramPage)
}
