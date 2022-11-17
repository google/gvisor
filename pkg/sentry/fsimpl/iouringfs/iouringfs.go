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
	"sync"

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

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	ioRings *safemem.BlockSeq
	sqes    *safemem.BlockSeq
	cqes    *safemem.BlockSeq
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

	if err := iouringfd.populateIORings(params); err != nil {
		return nil, err
	}

	if err := iouringfd.cacheSqesMapping(); err != nil {
		return nil, err
	}
	if err := iouringfd.cacheCqesMapping(); err != nil {
		return nil, err
	}

	return &iouringfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *FileDescription) Release(context.Context) {
	fd.rbmf.mf.DecRef(fd.rbmf.fr)
	fd.sqemf.mf.DecRef(fd.sqemf.fr)
}

// unmarshalIORings handles unmarshalling IORings struct considering that there could be more than
// one block in the BlockSeq.
func unmarshalIORings(ioRings *linux.IORings, bs *safemem.BlockSeq) error {
	if bs.NumBlocks() == 1 && !bs.Head().NeedSafecopy() {
		ioRings.UnmarshalBytes(bs.Head().TakeFirst((*linux.IORings)(nil).SizeBytes()).ToSlice())

		return nil
	}

	buf := make([]byte, (*linux.IORings)(nil).SizeBytes())
	cp, cperr := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), *bs)
	if cp == 0 {
		return cperr
	}
	ioRings.UnmarshalBytes(buf)

	return nil
}

// marshalIORings handles marshalling IORings struct considering that there could be more than one
// BlockSeq.
func marshalIORings(ioRings *linux.IORings, bs *safemem.BlockSeq) error {
	if bs.NumBlocks() == 1 && !bs.Head().NeedSafecopy() {
		ioRings.MarshalBytes(bs.Head().TakeFirst((*linux.IORings)(nil).SizeBytes()).ToSlice())
	}

	buf := make([]byte, (*linux.IORings)(nil).SizeBytes())
	ioRings.MarshalBytes(buf)
	cp, cperr := safemem.CopySeq(*bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)))
	if cp == 0 {
		return cperr
	}

	return nil
}

// unmarshalSqe handles unmarshalling SQE struct considering that there could be more than one block
// in the BlockSeq.
func unmarshalSqe(sqe *linux.IOUringSqe, sqes *safemem.BlockSeq, sqHead uint32) error {
	sqeSize := uint32((*linux.IOUringSqe)(nil).SizeBytes())
	if sqes.NumBlocks() == 1 && !sqes.Head().NeedSafecopy() {
		sqe.UnmarshalBytes(sqes.Head().ToSlice()[sqHead*sqeSize : (sqHead+1)*sqeSize])

		return nil
	}

	buf := make([]byte, sqes.NumBytes())
	cp, cperr := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[sqHead*sqeSize:(sqHead+1)*sqeSize])), *sqes)
	if cp == 0 {
		return cperr
	}
	sqe.UnmarshalBytes(buf)

	return nil
}

// populateIORings populates IORings struct backed by the allocated memory.
func (fd *FileDescription) populateIORings(params *linux.IOUringParams) error {
	bs, err := fd.rbmf.mf.MapInternal(fd.rbmf.fr, hostarch.ReadWrite)
	if err != nil {
		return err
	}

	fd.ioRings = &bs

	var ioRings linux.IORings
	if err = unmarshalIORings(&ioRings, &bs); err != nil {
		return err
	}

	ioRings.SqRingMask = params.SqEntries - 1
	ioRings.CqRingMask = params.CqEntries - 1
	ioRings.SqRingEntries = params.SqEntries
	ioRings.CqRingEntries = params.CqEntries

	if err = marshalIORings(&ioRings, &bs); err != nil {
		return err
	}

	return nil
}

// cacheSqesMapping caches the beginning of an area for the SQEs backed by the allocated memory.
func (fd *FileDescription) cacheSqesMapping() error {
	bs, err := fd.sqemf.mf.MapInternal(fd.sqemf.fr, hostarch.ReadWrite)
	if err != nil {
		return err
	}
	fd.sqes = &bs

	return nil
}

// cacheCqesMapping caches the beginning of an area for the CQEs backed by the allocated memory.
func (fd *FileDescription) cacheCqesMapping() error {
	bs := *fd.ioRings
	cqesOffset := uint64(hostarch.Addr((*linux.IORings)(nil).SizeBytes()))
	cqesOffset, ok := hostarch.CacheLineRoundUp(cqesOffset)
	if !ok {
		return linuxerr.EOVERFLOW
	}
	bs = bs.DropFirst(int(cqesOffset))
	fd.cqes = &bs

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

// ProcessSubmissions processes submission requests.
func (fd *FileDescription) ProcessSubmissions(t *kernel.Task, toSubmit uint32, minComplete uint32, flags uint32) (int, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	var ioRings linux.IORings
	err := fd.getIORings(&ioRings)
	if err != nil {
		return -1, err
	}

	sqes := fd.sqes
	cqes := fd.cqes

	var sqe linux.IOUringSqe
	sqHead := atomicbitops.FromUint32(ioRings.Sq.Head)
	sqTail := atomicbitops.FromUint32(ioRings.Sq.Tail)
	cqHead := atomicbitops.FromUint32(ioRings.Cq.Head)
	cqTail := atomicbitops.FromUint32(ioRings.Cq.Tail)

	submitted := uint32(0)
	for toSubmit > submitted {
		sqHeadMasked := sqHead.Load() & ioRings.SqRingMask
		cqTailMasked := cqTail.Load() & ioRings.CqRingMask
		// This means that the submission queue is empty.
		if sqHead == sqTail {
			return int(submitted), nil
		}

		if err = unmarshalSqe(&sqe, sqes, sqHeadMasked); err != nil {
			return -1, err
		}

		cqe := fd.ProcessSubmission(t, &sqe, flags)
		sqHead.Add(1)
		if (cqTail.Load()-cqHead.Load())/ioRings.CqRingEntries == 1 {
			ioRings.CqOverflow++
		} else {
			if err = fd.updateCq(cqes, cqe, cqTailMasked); err != nil {
				return -1, err
			}
			cqTail.Add(1)
		}
		submitted++
	}
	ioRings.Sq.Head = sqHead.Load()
	ioRings.Cq.Tail = cqTail.Load()

	if err = marshalIORings(&ioRings, fd.ioRings); err != nil {
		return -1, err
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
	file := t.GetFileVFS2(sqe.Fd)
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

// getIORings unmarshalls IORings struct backed by the allocated memory.
func (fd *FileDescription) getIORings(ioRings *linux.IORings) error {
	if err := unmarshalIORings(ioRings, fd.ioRings); err != nil {
		return err
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
