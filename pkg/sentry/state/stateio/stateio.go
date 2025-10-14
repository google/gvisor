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
	// descriptor a valid destination for reads from the file represented by
	// the AsyncReader, and returns a DestinationFile representing the
	// registered host file. The returned DestinationFile can only be used with
	// the AsyncReader that returned it. fd does not need to remain valid
	// beyond the call to RegisterDestinationFD.
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

// AsyncWriter represents a file supporting asynchronous sequential writes.
//
// MaxWriteBytes, MaxRanges, MaxParallel, and NeedRegisterSourceFD may be
// called concurrently. Only one goroutine may call RegisterSourceFD at a time.
// Only one goroutine may call any of AddWrite, AddWritev, Wait, Reserve or
// Finalize at a time. However, RegisterSourceFD and any one of AddWrite,
// AddWritev, Wait, Reserve, or Finalize may be called concurrently. Close may
// not be called concurrently with any other methods, and no methods may be
// called after Close.
type AsyncWriter interface {
	// Close cancels inflight writes if possible, waits for uncanceled inflight
	// writes to complete, and then releases resources owned by the
	// AsyncWriter.
	//
	// Close may not flush buffered state to the file; callers must call
	// Finalize instead. This also means that if Finalize returns nil, but
	// Close returns a non-nil error, the file was still written successfully.
	Close() error

	// MaxWriteBytes returns the maximum length of each write in bytes, which
	// must be strictly positive. All calls to MaxWriteBytes for a given
	// AsyncWriter must return the same value.
	//
	// Implementations should return the largest write size that is efficient,
	// rather than the largest write size that is implementable, allowing
	// callers to treat MaxWriteBytes() as a target.
	MaxWriteBytes() uint64

	// MaxRanges returns the maximum number of FileRanges and Iovecs that may
	// be passed in calls to AddWritev, which must be strictly positive. All
	// calls to MaxRanges for a given AsyncWriter must return the same value.
	MaxRanges() int

	// MaxParallel returns the maximum number of parallel writes that may be
	// enqueued on this file, which must be strictly positive. All calls to
	// MaxParallel for a given AsyncWriter must return the same value.
	MaxParallel() int

	// NeedRegisterSourceFD returns true if RegisterSourceFD must be called to
	// obtain SourceFiles for write sources. If NeedRegisterSourceFD returns
	// false, callers may pass a nil SourceFile to AddWrite and AddWritev, an
	// empty FileRange to AddWrite, and a nil FileRange slice to AddWritev. All
	// calls to NeedRegisterSourceFD for a given AsyncWriter must return the
	// same value.
	//
	// This feature exists to support implementations of AsyncWriter in which
	// writes take place in external processes. Implementations of AsyncWriter
	// that don't require this can embed NoRegisterClientFD to obtain an
	// appropriate implementation of NeedRegisterSourceFD and RegisterSourceFD.
	NeedRegisterSourceFD() bool

	// RegisterSourceFD makes the first size bytes of the given host file
	// descriptor a valid source for writes to the file represented by the
	// AsyncWriter, and returns a SourceFile representing the registered host
	// file. The returned SourceFile can only be used with the AsyncWriter that
	// returned it. fd does not need to remain valid beyond the call to
	// RegisterSourceFD.
	//
	// There is no way to unregister individual SourceFiles; all SourceFiles
	// are invalidated by Close.
	//
	// It is safe, though unnecessary, to call RegisterSourceFD even if
	// NeedRegisterSourceFD returns false.
	RegisterSourceFD(fd int32, size uint64, settings []ClientFileRangeSetting) (SourceFile, error)

	// AddWrite enqueues an appending write of size srcFR.Length() bytes, from
	// srcFile starting at srcFR.Start, to the file represented by the
	// AsyncWriter. srcMap must be a mapping of srcFR.
	//
	// Note that some AsyncWriter implementations may not begin execution of
	// enqueued writes until the following call to Wait.
	//
	// Preconditions:
	// - 0 <= id < MaxParallel().
	// - id must not be in use by any inflight write.
	// - 0 < srcFR.Length() <= MaxWriteBytes().
	// - No previous call to Wait has returned a non-nil error.
	// - Finalize has never been called.
	AddWrite(id int, srcFile SourceFile, srcFR memmap.FileRange, srcMap []byte)

	// AddWritev enqueues an appending write of size total, from the srcFile
	// ranges in srcFRs, to the file represented by the AsyncWriter. srcMaps
	// must be a mapping of srcFRs. The AsyncWriter may retain srcFRs and
	// srcMaps until the corresponding completion is returned by Wait; neither
	// the caller nor the AsyncWriter may mutate srcFRs or srcMaps during this
	// time.
	//
	// Note that some AsyncWriter implementations may not begin execution of
	// enqueued writes until the following call to Wait.
	//
	// Preconditions:
	// - 0 <= id < MaxParallel().
	// - id must not be in use by any inflight write.
	// - 0 < total <= MaxWriteBytes().
	// - total == the sum of FileRange.Length() over srcFRs.
	// - No FileRange in srcFRs may have length 0.
	// - No call to Wait has returned a non-nil error.
	// - Finalize has never been called.
	AddWritev(id int, total uint64, srcFile SourceFile, srcFRs []memmap.FileRange, srcMaps []unix.Iovec)

	// Wait waits for at least minCompletions enqueued writes to complete,
	// appends information for completed writes to cs, and returns the updated
	// slice.
	//
	// Preconditions:
	// - minCompletions <= the number of inflight writes.
	// - No call to Wait has returned a non-nil error.
	// - Finalize has never been called.
	Wait(cs []Completion, minCompletions int) ([]Completion, error)

	// Reserve indicates that the caller intends to write at least n bytes in
	// total to the file. If n or more bytes have already been written to the
	// file, Reserve has no effect. Callers must not Reserve more bytes than
	// will actually be written to the file.
	//
	// Calling Reserve is optional, but may improve performance.
	//
	// Preconditions:
	// - Reserve has never been called with a smaller value of n.
	// - No call to Wait has returned a non-nil error.
	// - Finalize has never been called.
	Reserve(n uint64)

	// Finalize must be called after all writes to the file have completed
	// successfully. It may take actions such as flushing buffered state. If
	// Finalize returns a non-nil error, the written file may be corrupt
	// despite successful completion of previous writes.
	//
	// Preconditions:
	// - Wait has returned successful completions for all writes submitted by
	//   previous calls to AddWrite and AddWritev.
	// - No call to Wait has returned a non-nil error.
	// - Finalize has never been called.
	Finalize() error
}

// DestinationFile represents a file that has been registered for reads from an
// AsyncReader.
type DestinationFile any

// SourceFile represents a file that has been registered for writes to an
// AsyncWriter.
type SourceFile any

// ClientFileRangeSetting specifies properties of a range in a DestinationFile
// or SourceFile.
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
	// ID is the ID passed to AsyncReader.AddRead, AsyncReader.AddReadv,
	// AsyncWriter.AddWrite, or AsyncWriter.AddWritev.
	ID int

	// N is the number of bytes for which I/O was successfully performed. Err
	// is the error that terminated I/O after N bytes.
	//
	// Invariant: If N is less than the number of bytes for which I/O was
	// submitted, Err is non-nil.
	N   uint64
	Err error
}
