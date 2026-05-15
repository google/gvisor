// Copyright 2025 The gVisor Authors.
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

package stateipc

import (
	"fmt"
	"math"
	"unsafe"

	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// Arbitrary constraints on MaxRanges and MaxParallel to prevent overflow of
// uint32 sizes:
const (
	maxMaxRanges   = 32 << 10
	maxMaxParallel = 4 << 10
)

// getDataSize returns the datagram size required for a Flipcall connection
// with the given parameters.
//
// Preconditions:
// - maxRanges <= maxMaxRanges.
// - maxParallel <= maxMaxParallel.
func getDataSize(maxRanges, maxParallel uint32, mode int) uint32 {
	var maxReqSize uintptr
	switch mode {
	case OpenModeRead:
		maxReqSize = unsafe.Sizeof(readRequestHeader{}) + uintptr(maxParallel)*(unsafe.Sizeof(readSubmissionHeader{})+uintptr(maxRanges)*unsafe.Sizeof(memmap.FileRange{}))
	case OpenModeWrite:
		maxReqSize = unsafe.Sizeof(writeRequestHeader{}) + uintptr(maxParallel)*(unsafe.Sizeof(writeSubmissionHeader{})+uintptr(maxRanges)*unsafe.Sizeof(memmap.FileRange{}))
	default:
		panic(fmt.Sprintf("unknown open mode %v", mode))
	}
	maxRespSize := unsafe.Sizeof(ioResponseHeader{}) + uintptr(maxParallel)*unsafe.Sizeof(ioCompletion{})
	if maxReqSize > math.MaxUint32 || maxRespSize > math.MaxUint32 {
		panic(fmt.Sprintf("maxReqSize=%d or maxRespSize=%d overflows uint32 for maxRanges=%d, maxParallel=%d", maxReqSize, maxRespSize, maxRanges, maxParallel))
	}
	return uint32(max(maxReqSize, maxRespSize))
}

// ioEndpoint wraps a flipcall.Endpoint used for file I/O with the ability to
// read/write file I/O fields in the connection packet window.
type ioEndpoint struct {
	flipcall.Endpoint

	// ptr is the pointer into the datagram part of the Flipcall packet window
	// where the next field will be read or written.
	ptr unsafe.Pointer
}

func (ioep *ioEndpoint) Destroy() {
	ioep.ptr = nil
	ioep.Endpoint.Destroy()
}

func (ioep *ioEndpoint) readRequestHeader() *readRequestHeader {
	return (*readRequestHeader)(unsafe.Pointer(ioep.DataAddr()))
}

func (ioep *ioEndpoint) writeRequestHeader() *writeRequestHeader {
	return (*writeRequestHeader)(unsafe.Pointer(ioep.DataAddr()))
}

func (ioep *ioEndpoint) ioResponseHeader() *ioResponseHeader {
	return (*ioResponseHeader)(unsafe.Pointer(ioep.DataAddr()))
}

// resetForReadSubmissions prepares ioep to read or write read submissions using
// calls to ioep.scanReadSubmissionHeader() and ioep.scanFileRanges().
func (ioep *ioEndpoint) resetForReadSubmissions() {
	ioep.ptr = unsafe.Pointer(ioep.DataAddr() + unsafe.Sizeof(readRequestHeader{}))
}

// resetForWriteSubmissions prepares ioep to read or write write submissions using
// calls to ioep.scanWriteSubmissionHeader() and ioep.scanFileRanges().
func (ioep *ioEndpoint) resetForWriteSubmissions() {
	ioep.ptr = unsafe.Pointer(ioep.DataAddr() + unsafe.Sizeof(writeRequestHeader{}))
}

// resetForCompletions prepares ioep to read or write I/O completions using
// calls to ioep.scanCompletion().
func (ioep *ioEndpoint) resetForCompletions() {
	ioep.ptr = unsafe.Pointer(ioep.DataAddr() + unsafe.Sizeof(ioResponseHeader{}))
}

// scanReadSubmissionHeader returns a pointer to the readSubmissionHeader at the
// current datagram position, and advances the datagram position to past the
// ioSubmissionHeader.
func (ioep *ioEndpoint) scanReadSubmissionHeader() *readSubmissionHeader {
	return (*readSubmissionHeader)(ioep.ptrAdd(unsafe.Sizeof(readSubmissionHeader{})))
}

// scanWriteSubmissionHeader returns a pointer to the writeSubmissionHeader at
// the current datagram position, and advances the datagram position to past
// the ioSubmissionHeader.
func (ioep *ioEndpoint) scanWriteSubmissionHeader() *writeSubmissionHeader {
	return (*writeSubmissionHeader)(ioep.ptrAdd(unsafe.Sizeof(writeSubmissionHeader{})))
}

// scanFileRanges returns a slice representing the numRanges FileRanges at the
// current datagram position, and advances the datagram position to past the
// FileRanges.
func (ioep *ioEndpoint) scanFileRanges(numRanges uint32) []memmap.FileRange {
	ptr := ioep.ptrAdd(uintptr(numRanges) * unsafe.Sizeof(memmap.FileRange{}))
	return unsafe.Slice((*memmap.FileRange)(ptr), numRanges)
}

// scanCompletion returns a pointer to the ioCompletion at the current datagram
// position, and advances the datagram position to past the ioCompletion.
func (ioep *ioEndpoint) scanCompletion() *ioCompletion {
	return (*ioCompletion)(ioep.ptrAdd(unsafe.Sizeof(ioCompletion{})))
}

// ptrAdd increments ioep.ptr by the given number of bytes and returns the
// previous value.
func (ioep *ioEndpoint) ptrAdd(n uintptr) unsafe.Pointer {
	ptr := ioep.ptr
	if uintptr(ptr) == 0 {
		panic("stateipc.ioEndpoint.ptr advanced while 0 (missing reset or at end of packet window)")
	}
	end := uintptr(ptr) + n
	if dataEnd := ioep.DataEndAddr(); end == dataEnd {
		end = 0
	} else if dataStart := ioep.DataAddr(); end > dataEnd || end < dataStart {
		panic(fmt.Sprintf("stateipc.ioEndpoint.ptr advanced %d bytes to %#x, outside datagram [%#x, %#x)", n, end, dataStart, dataEnd))
	}
	ioep.ptr = unsafe.Pointer(end)
	return ptr
}
