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

// Package stateio defines I/O types used by sentry save/restore.
package stateio

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// AsyncReader represents a file supporting asynchronous random reads.
//
// MaxReadBytes, MaxRanges, MaxParallel, and NeedRegisterDestinationFD may be
// called concurrently. Only one goroutine may call RegisterDestinationFD at a
// time. Only one goroutine may call any of AddRead, AddReadv, or Wait at a
// time. However, RegisterDestinationFD and any one of AddRead, AddReadv, or
// Wait may be called concurrently. Close may not be called concurrently with
// any other methods, and no methods may be called after Close.
type AsyncReader interface {
	// Close cancels inflight reads if possible, waits for uncanceled inflight
	// reads to complete, and then releases resources owned by the AsyncReader.
	Close() error

	// MaxReadBytes returns the maximum length of each read in bytes, which
	// must be strictly positive. All calls to MaxReadBytes for a given
	// AsyncReader must return the same value.
	//
	// Implementations should return the largest read size that is efficient,
	// rather than the largest read size that is implementable, allowing
	// callers to treat MaxReadBytes() as a target.
	MaxReadBytes() uint64

	// MaxRanges returns the maximum number of FileRanges and Iovecs that may
	// passed in calls to AddReadv, which must be strictly positive. All calls
	// to MaxRanges for a given AsyncReader must return the same value.
	MaxRanges() int

	// MaxParallel returns the maximum number of parallel reads that may be
	// enqueued on this file, which must be strictly positive. All calls to
	// MaxParallel for a given AsyncReader must return the same value.
	MaxParallel() int

	// NeedRegisterDestinationFD returns true if RegisterDestinationFD must be
	// called to obtain DestinationFiles for read destinations. If
	// NeedRegisterDestinationFD returns false, callers may pass a nil
	// DestinationFile to AddRead and AddReadv, an empty FileRange to AddRead,
	// and a nil FileRange slice to AddReadv. All calls to
	// NeedRegisterDestinationFD for a given AsyncReader must return the same
	// value.
	//
	// This feature exists to support implementations of AsyncReader in which
	// reads take place in external processes. Implementations of AsyncReader
	// that don't require this can embed NoRegisterClientFD to obtain an
	// appropriate implementation of NeedRegisterDestinationFD and
	// RegisterDestinationFD.
	NeedRegisterDestinationFD() bool

	// RegisterDestinationFD makes the first size bytes of the given host file
	// descriptor a valid destination for reads from this file, and returns a
	// DestinationFile representing it. The returned DestinationFile can only
	// be used with the AsyncReader that returned it. fd does not need to
	// remain valid beyond the call to RegisterDestinationFD.
	//
	// There is no way to unregister individual DestinationFiles; all
	// DestinationFiles are invalidated by AsyncReader.Close.
	//
	// It is safe, though unnecessary, to call RegisterDestinationFD even if
	// NeedRegisterDestinationFD returns false.
	RegisterDestinationFD(fd int32, size uint64, settings []ClientFileRangeSetting) (DestinationFile, error)

	// AddRead enqueues a read of size dstFR.Length() bytes, from the file
	// starting at the given offset, to dstFile starting at dstFR.Start. dstMap
	// must be a mapping of dstFR.
	//
	// Note that some AsyncReader implementations may not begin execution of
	// enqueued reads until the following call to Wait.
	//
	// Preconditions:
	// - 0 <= id < MaxParallel().
	// - id must not be in use by any inflight read.
	// - 0 < dstFR.Length() <= MaxReadBytes().
	// - No call to Wait has returned a non-nil error.
	AddRead(id int, off int64, dstFile DestinationFile, dstFR memmap.FileRange, dstMap []byte)

	// AddReadv enqueues a read of size total, from the file starting at the
	// given offset, to the dstFile ranges in dstFRs. dstMaps must be a mapping
	// of dstFRs. The AsyncReader may retain dstFRs and dstMaps until the
	// corresponding completion is returned by Wait; neither the caller nor the
	// AsyncReader may mutate dstFRs or dstMaps during this time.
	//
	// Note that some AsyncReader implementations may not begin execution of
	// enqueued reads until the following call to Wait.
	//
	// Preconditions:
	// - 0 <= id < MaxParallel().
	// - id must not be in use by any inflight read.
	// - 0 < total <= MaxReadBytes().
	// - total == the sum of FileRange.Length() over dstFRs.
	// - No FileRange in dstFRs may have length 0.
	// - No call to Wait has returned a non-nil error.
	AddReadv(id int, off int64, total uint64, dstFile DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec)

	// Wait waits for at least minCompletions enqueued reads to complete,
	// appends information for completed reads to cs, and returns the updated
	// slice.
	//
	// Preconditions:
	// - minCompletions <= the number of inflight reads.
	// - No call to Wait has returned a non-nil error.
	Wait(cs []Completion, minCompletions int) ([]Completion, error)
}

// DestinationFile represents a file that has been registered for reads from an
// AsyncReader.
type DestinationFile any

// ClientFileRangeSetting specifies properties of a range in a DestinationFile.
type ClientFileRangeSetting struct {
	memmap.FileRange
	Property ClientFileRangeProperty
}

// ClientFileRangeProperty is the type of ClientFileRangeSetting.Property.
type ClientFileRangeProperty int

const (
	// PropertyInvalid ensures that the zero value of ClientFileRangeProperty
	// is invalid.
	PropertyInvalid ClientFileRangeProperty = iota

	// PropertyHugepage indicates that allocations in the given range should use
	// huge pages.
	PropertyHugepage

	// PropertyNoHugepage indicates that allocations in the given range should
	// not use huge pages.
	PropertyNoHugepage
)

// Completion indicates the result of a completed I/O operation.
type Completion struct {
	// ID is the ID passed to AsyncReader.AddRead or AsyncReader.AddReadv.
	ID int

	// N is the number of bytes for which I/O was successfully performed. Err
	// is the error that terminated I/O after N bytes.
	//
	// Invariant: If N is less than the number of bytes for which I/O was
	// submitted, Err is non-nil.
	N   uint64
	Err error
}
