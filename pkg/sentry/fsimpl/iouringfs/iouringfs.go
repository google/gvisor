// Copyright 2022 The gVisor Authors.
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

// Package iouringfs provides a filesystem implementation for IO_URING basing
// it on anonfs. Currently, we don't support neither IOPOLL nor SQPOLL modes.
// Thus, user needs to set up IO_URING first with io_uring_setup(2) syscall and
// then issue submission request using io_uring_enter(2).
//
// Another important note, as of now, we don't support deferred CQE. In other
// words, the size of the backlogged set of CQE is zero. Whenever, completion
// queue ring buffer is full, we drop the subsequent completion queue entries.
package iouringfs

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// FileDescription implements vfs.FileDescriptionImpl for file-based IO_URING.
// It is based on io_rings struct. See io_uring/io_uring.c.
//
// +stateify savable
type FileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	rbmf  ringsBufferFile
	sqemf sqEntriesFile

	// running indicates whether the submission queue is currently being
	// processed. This is either 0 for not running, or 1 for running.
	running atomicbitops.Uint32
	// runC is used to wake up serialized task goroutines waiting for any
	// concurrent processors of the submisison queue.
	runC chan struct{} `state:"nosave"`

	ioRings linux.IORings

	ioRingsBuf sharedBuffer
	sqesBuf    sharedBuffer
	cqesBuf    sharedBuffer
}

var _ vfs.FileDescriptionImpl = (*FileDescription)(nil)

func roundUpPowerOfTwo(n uint32) (uint32, bool) {
	if n > (1 << 31) {
		return 0, false
	}
	result := uint32(1)
	for result < n {
		result = result << 1
	}
	return result, true
}

// New creates a new iouring fd.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, entries uint32, params *linux.IOUringParams) (*vfs.FileDescription, error) {
	if entries > linux.IORING_MAX_ENTRIES {
		return nil, linuxerr.EINVAL
	}

	vd := vfsObj.NewAnonVirtualDentry("[io_uring]")
	defer vd.DecRef(ctx)

	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFileProvider))
	}

	numSqEntries, ok := roundUpPowerOfTwo(entries)
	if !ok {
		return nil, linuxerr.EOVERFLOW
	}
	var numCqEntries uint32
	if params.Flags&linux.IORING_SETUP_CQSIZE != 0 {
		var ok bool
		numCqEntries, ok = roundUpPowerOfTwo(params.CqEntries)
		if !ok || numCqEntries < numSqEntries || numCqEntries > linux.IORING_MAX_CQ_ENTRIES {
			return nil, linuxerr.EINVAL
		}
	} else {
		numCqEntries = 2 * numSqEntries
	}

	// Allocate enough space to store the `struct io_rings` plus a given number of indexes
	// corresponding to the number of SQEs.
	ioRingsWithCqesSize := uint32((*linux.IORings)(nil).SizeBytes()) +
		numCqEntries*uint32((*linux.IOUringCqe)(nil).SizeBytes())
	ringsBufferSize := uint64(ioRingsWithCqesSize +
		numSqEntries*uint32((*linux.IORingIndex)(nil).SizeBytes()))
	ringsBufferSize = uint64(hostarch.Addr(ringsBufferSize).MustRoundUp())

	rbfr, err := mfp.MemoryFile().Allocate(ringsBufferSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, linuxerr.ENOMEM
	}

	// Allocate enough space to store the given number of submission queue entries.
	sqEntriesSize := uint64(numSqEntries * uint32((*linux.IOUringSqe)(nil).SizeBytes()))
	sqEntriesSize = uint64(hostarch.Addr(sqEntriesSize).MustRoundUp())
	sqefr, err := mfp.MemoryFile().Allocate(sqEntriesSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, linuxerr.ENOMEM
	}

	iouringfd := &FileDescription{
		rbmf: ringsBufferFile{
			mf: mfp.MemoryFile(),
			fr: rbfr,
		},
		sqemf: sqEntriesFile{
			mf: mfp.MemoryFile(),
			fr: sqefr,
		},
		// See ProcessSubmissions for why the capacity is 1.
		runC: make(chan struct{}, 1),
	}

	// iouringfd is always set up with read/write mode.
	// See io_uring/io_uring.c:io_uring_install_fd().
	if err := iouringfd.vfsfd.Init(iouringfd, uint32(linux.O_RDWR), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
		DenySpliceIn:      true,
	}); err != nil {
		return nil, err
	}

	params.SqEntries = numSqEntries
	params.CqEntries = numCqEntries

	arrayOffset := uint64(hostarch.Addr(ioRingsWithCqesSize))
	arrayOffset, ok = hostarch.CacheLineRoundUp(arrayOffset)
	if !ok {
		return nil, linuxerr.EOVERFLOW
	}

	params.SqOff = linux.PreComputedIOSqRingOffsets()
	params.SqOff.Array = uint32(arrayOffset)

	cqesOffset := uint64(hostarch.Addr((*linux.IORings)(nil).SizeBytes()))
	cqesOffset, ok = hostarch.CacheLineRoundUp(cqesOffset)
	if !ok {
		return nil, linuxerr.EOVERFLOW
	}

	params.CqOff = linux.PreComputedIOCqRingOffsets()
	params.CqOff.Cqes = uint32(cqesOffset)

	// Set features supported by the current IO_URING implementation.
	params.Features = linux.IORING_FEAT_SINGLE_MMAP

	// Map all shared buffers.
	if err := iouringfd.mapSharedBuffers(); err != nil {
		return nil, err
	}

	// Initialize IORings struct from params.
	iouringfd.ioRings.SqRingMask = params.SqEntries - 1
	iouringfd.ioRings.CqRingMask = params.CqEntries - 1
	iouringfd.ioRings.SqRingEntries = params.SqEntries
	iouringfd.ioRings.CqRingEntries = params.CqEntries

	// Write IORings out to shared buffer.
	view, err := iouringfd.ioRingsBuf.view(iouringfd.ioRings.SizeBytes())
	if err != nil {
		return nil, err
	}
	iouringfd.ioRings.MarshalUnsafe(view)
	if _, err := iouringfd.ioRingsBuf.writeback(iouringfd.ioRings.SizeBytes()); err != nil {
		return nil, err
	}

	return &iouringfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *FileDescription) Release(context.Context) {
	fd.rbmf.mf.DecRef(fd.rbmf.fr)
	fd.sqemf.mf.DecRef(fd.sqemf.fr)
}

// mapSharedBuffers caches internal mappings for the ring's shared memory
// regions.
func (fd *FileDescription) mapSharedBuffers() error {
	// Mapping for the IORings header struct.
	rb, err := fd.rbmf.mf.MapInternal(fd.rbmf.fr, hostarch.ReadWrite)
	if err != nil {
		return err
	}
	fd.ioRingsBuf.init(rb)

	// Mapping for the CQEs array. This is contiguous to the header struct.
	cqesOffset := uint64(fd.ioRings.SizeBytes())
	cqesOffset, ok := hostarch.CacheLineRoundUp(cqesOffset)
	if !ok {
		return linuxerr.EOVERFLOW
	}
	cqes := rb.DropFirst(int(cqesOffset))
	fd.cqesBuf.init(cqes)

	// Mapping for the SQEs array.
	sqes, err := fd.sqemf.mf.MapInternal(fd.sqemf.fr, hostarch.ReadWrite)
	if err != nil {
		return err
	}
	fd.sqesBuf.init(sqes)

	return nil

}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *FileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	var mf memmap.Mappable
	switch opts.Offset {
	case linux.IORING_OFF_SQ_RING, linux.IORING_OFF_CQ_RING:
		mf = &fd.rbmf
	case linux.IORING_OFF_SQES:
		mf = &fd.sqemf
	default:
		return linuxerr.EINVAL
	}

	opts.Offset = 0

	return vfs.GenericConfigureMMap(&fd.vfsfd, mf, opts)
}

// ProcessSubmissions processes the submission queue. Concurrent calls to
// ProcessSubmissions serialize, yielding task goroutines with Task.Block since
// processing can take a long time.
func (fd *FileDescription) ProcessSubmissions(t *kernel.Task, toSubmit uint32, minComplete uint32, flags uint32) (int, error) {
	// We use a combination of fd.running and fd.runC to serialize concurrent
	// callers to ProcessSubmissions. runC has a capacity of 1. The protocol
	// works as follows:
	//
	// * Becoming the active task
	//
	// On entry to ProcessSubmissions, we try to transition running from 0 to
	// 1. If there is already an active task, this will fail and we'll go to
	// sleep with Task.Block(). If we succeed, we're the active task.
	//
	// * Sleep, Wakeup
	//
	// If we had to sleep, on wakeup we try to transition running to 1 again as
	// we could still be racing with other tasks. Note that if multiple tasks
	// are sleeping, only one will wake up since only one will successfully
	// receive from runC. However we could still race with a new caller of
	// ProcessSubmissions that hasn't gone to sleep yet. Only one waiting task
	// will succeed and become the active task, the rest will go to sleep.
	//
	// runC needs to be buffered to avoid a race between checking running and
	// going back to sleep. With an unbuffered channel, we could miss a wakeup
	// like this:
	//
	// Task B (entering, sleeping)                        | Task A (active, releasing)
	// ---------------------------------------------------+-------------------------
	//                                                    | fd.running.Store(0)
	// for !fd.running.CompareAndSwap(0, 1) { // Succeess |
	//                                                    | nonblockingSend(runC) // Missed!
	//     t.Block(fd.runC) // Will block forever         |
	// }
	//
	// Task A's send would have to be non-blocking, as there may not be a
	// concurrent Task B.
	//
	// A side-effect of using a buffered channel is the first task that needs to
	// sleep may wake up once immediately due to a previously queued
	// wakeup. This isn't a problem, as it'll immediately try to transition
	// running to 1, likely fail again and go back to sleep. Task.Block has a
	// fast path if runC already has a queued message so this won't result in a
	// task state change.
	//
	// * Release
	//
	// When the active task is done, it releases the critical section by setting
	// running = 0, then doing a non-blocking send on runC. The send needs to be
	// non-blocking, as there may not be a concurrent sleeper.
	for !fd.running.CompareAndSwap(0, 1) {
		t.Block(fd.runC)
	}
	// We successfully set fd.running, so we're the active task now.
	defer func() {
		// Unblock any potentially waiting tasks.
		if !fd.running.CompareAndSwap(1, 0) {
			panic(fmt.Sprintf("iouringfs.FileDescription.ProcessSubmissions: active task encountered invalid fd.running state %v", fd.running.Load()))
		}
		select {
		case fd.runC <- struct{}{}:
		default:
		}
	}()

	var err error
	var sqe linux.IOUringSqe

	sqOff := linux.PreComputedIOSqRingOffsets()
	cqOff := linux.PreComputedIOCqRingOffsets()
	sqArraySize := sqe.SizeBytes() * int(fd.ioRings.SqRingEntries)
	cqArraySize := (*linux.IOUringCqe)(nil).SizeBytes() * int(fd.ioRings.CqRingEntries)

	// Fetch all buffers initially.
	fetchRB := true
	fetchSQA := true
	fetchCQA := true

	var view, sqaView, cqaView []byte
	submitted := uint32(0)

	for toSubmit > submitted {
		// This loop can take a long time to process, so periodically check for
		// interrupts. This also pets the watchdog.
		if t.Interrupted() {
			return -1, linuxerr.EINTR
		}

		if fetchRB {
			view, err = fd.ioRingsBuf.view(fd.ioRings.SizeBytes())
			if err != nil {
				return -1, err
			}
		}

		// Note: The kernel uses sqHead as a cursor and writes cqTail. Userspace
		// uses cqHead as a cursor and writes sqTail.

		sqHeadPtr := atomicUint32AtOffset(view, int(sqOff.Head))
		sqTailPtr := atomicUint32AtOffset(view, int(sqOff.Tail))
		cqHeadPtr := atomicUint32AtOffset(view, int(cqOff.Head))
		cqTailPtr := atomicUint32AtOffset(view, int(cqOff.Tail))
		overflowPtr := atomicUint32AtOffset(view, int(cqOff.Overflow))

		// Load the pointers once, so we work with a stable value. Particularly,
		// usersapce can update the SQ tail at any time.
		sqHead := sqHeadPtr.Load()
		sqTail := sqTailPtr.Load()

		// Is the submission queue is empty?
		if sqHead == sqTail {
			return int(submitted), nil
		}

		// We have at least one pending sqe, unmarshal the first from the
		// submission queue.
		if fetchSQA {
			sqaView, err = fd.sqesBuf.view(sqArraySize)
			if err != nil {
				return -1, err
			}
		}
		sqaOff := int(sqHead&fd.ioRings.SqRingMask) * sqe.SizeBytes()
		sqe.UnmarshalUnsafe(sqaView[sqaOff : sqaOff+sqe.SizeBytes()])
		fetchSQA = fd.sqesBuf.drop()

		// Dispatch request from unmarshalled entry.
		cqe := fd.ProcessSubmission(t, &sqe, flags)

		// Advance sq head.
		sqHeadPtr.Add(1)

		// Load once so we have stable values. Particularly, userspace can
		// update the CQ head at any time.
		cqHead := cqHeadPtr.Load()
		cqTail := cqTailPtr.Load()

		// Marshal response to completion queue.
		if (cqTail - cqHead) >= fd.ioRings.CqRingEntries {
			// CQ ring full.
			fd.ioRings.CqOverflow++
			overflowPtr.Store(fd.ioRings.CqOverflow)
		} else {
			// Have room in CQ, marshal CQE.
			if fetchCQA {
				cqaView, err = fd.cqesBuf.view(cqArraySize)
				if err != nil {
					return -1, err
				}
			}
			cqaOff := int(cqTail&fd.ioRings.CqRingMask) * cqe.SizeBytes()
			cqe.MarshalUnsafe(cqaView[cqaOff : cqaOff+cqe.SizeBytes()])
			fetchCQA, err = fd.cqesBuf.writebackWindow(cqaOff, cqe.SizeBytes())
			if err != nil {
				return -1, err
			}

			// Advance cq tail.
			cqTailPtr.Add(1)
		}

		fetchRB, err = fd.ioRingsBuf.writeback(fd.ioRings.SizeBytes())
		if err != nil {
			return -1, err
		}

		submitted++
	}

	return int(submitted), nil
}

// ProcessSubmission processes a single submission request.
func (fd *FileDescription) ProcessSubmission(t *kernel.Task, sqe *linux.IOUringSqe, flags uint32) *linux.IOUringCqe {
	var (
		cqeErr   error
		cqeFlags uint32
		retValue int32
	)

	switch op := sqe.Opcode; op {
	case linux.IORING_OP_NOP:
		// For the NOP operation, we don't do anything special.
	case linux.IORING_OP_READV:
		retValue, cqeErr = fd.handleReadv(t, sqe, flags)
		if cqeErr == io.EOF {
			// Don't raise EOF as errno, error translation will fail. Short
			// reads aren't failures.
			cqeErr = nil
		}
	default: // Unsupported operation
		retValue = -int32(linuxerr.EINVAL.Errno())
	}

	if cqeErr != nil {
		retValue = -int32(kernel.ExtractErrno(cqeErr, -1))
	}

	return &linux.IOUringCqe{
		UserData: sqe.UserData,
		Res:      retValue,
		Flags:    cqeFlags,
	}
}

// handleReadv handles IORING_OP_READV.
func (fd *FileDescription) handleReadv(t *kernel.Task, sqe *linux.IOUringSqe, flags uint32) (int32, error) {
	// Check that a file descriptor is valid.
	if sqe.Fd < 0 {
		return 0, linuxerr.EBADF
	}
	// Currently we don't support any flags for the SQEs.
	if sqe.Flags != 0 {
		return 0, linuxerr.EINVAL
	}
	// If the file is not seekable then offset must be zero. And currently, we don't support them.
	if sqe.OffOrAddrOrCmdOp != 0 {
		return 0, linuxerr.EINVAL
	}
	// ioprio should not be set for the READV operation.
	if sqe.IoPrio != 0 {
		return 0, linuxerr.EINVAL
	}
	// buf_index should not be set for the READV operation.
	if sqe.BufIndexOrGroup != 0 {
		return 0, linuxerr.EINVAL
	}

	// AddressSpaceActive is set to true as we are doing this from the task goroutine.And this is a
	// case as we currently don't support neither IOPOLL nor SQPOLL modes.
	dst, err := t.IovecsIOSequence(hostarch.Addr(sqe.AddrOrSpliceOff), int(sqe.Len), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if err != nil {
		return 0, err
	}
	file := t.GetFile(sqe.Fd)
	if file == nil {
		return 0, linuxerr.EBADF
	}
	defer file.DecRef(t)
	n, err := file.PRead(t, dst, 0, vfs.ReadOptions{})
	if err != nil {
		return 0, err
	}

	return int32(n), nil
}

// updateCq updates a completion queue by adding a given completion queue entry.
func (fd *FileDescription) updateCq(cqes *safemem.BlockSeq, cqe *linux.IOUringCqe, cqTail uint32) error {
	cqeSize := uint32((*linux.IOUringCqe)(nil).SizeBytes())
	if cqes.NumBlocks() == 1 && !cqes.Head().NeedSafecopy() {
		cqe.MarshalBytes(cqes.Head().ToSlice()[cqTail*cqeSize : (cqTail+1)*cqeSize])

		return nil
	}

	buf := make([]byte, cqes.NumBytes())
	cqe.MarshalBytes(buf)
	cp, cperr := safemem.CopySeq(cqes.DropFirst64(uint64(cqTail*cqeSize)), safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)))
	if cp == 0 {
		return cperr
	}

	return nil
}

// sqEntriesFile implements memmap.Mappable for SQ entries.
type sqEntriesFile struct {
	mf *pgalloc.MemoryFile
	fr memmap.FileRange
}

// AddMapping implements memmap.Mappable.AddMapping.
func (sqemf *sqEntriesFile) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (sqemf *sqEntriesFile) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (sqemf *sqEntriesFile) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (sqemf *sqEntriesFile) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	if required.End > sqemf.fr.Length() {
		return nil, &memmap.BusError{linuxerr.EFAULT}
	}

	if source := optional.Intersect(memmap.MappableRange{0, sqemf.fr.Length()}); source.Length() != 0 {
		return []memmap.Translation{
			{
				Source: source,
				File:   sqemf.mf,
				Offset: sqemf.fr.Start + source.Start,
				Perms:  at,
			},
		}, nil
	}

	return nil, linuxerr.EFAULT
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (sqemf *sqEntriesFile) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// ringBuffersFile implements memmap.Mappable for SQ and CQ ring buffers.
type ringsBufferFile struct {
	mf *pgalloc.MemoryFile
	fr memmap.FileRange
}

// AddMapping implements memmap.Mappable.AddMapping.
func (rbmf *ringsBufferFile) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (rbmf *ringsBufferFile) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (rbmf *ringsBufferFile) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (rbmf *ringsBufferFile) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	if required.End > rbmf.fr.Length() {
		return nil, &memmap.BusError{linuxerr.EFAULT}
	}

	if source := optional.Intersect(memmap.MappableRange{0, rbmf.fr.Length()}); source.Length() != 0 {
		return []memmap.Translation{
			{
				Source: source,
				File:   rbmf.mf,
				Offset: rbmf.fr.Start + source.Start,
				Perms:  at,
			},
		}, nil
	}

	return nil, linuxerr.EFAULT
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (rbmf *ringsBufferFile) InvalidateUnsavable(ctx context.Context) error {
	return nil
}
