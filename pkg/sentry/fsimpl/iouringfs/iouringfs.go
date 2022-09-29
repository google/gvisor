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
// it on anonfs.
package iouringfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// FileDescription implements vfs.FileDescriptionImpl for file-based IO_URING.
// It is based on io_rings struct. See io_uring/io_uring.c.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	rbmf  ringsBufferFile
	sqemf sqEntriesFile
}

var _ vfs.FileDescriptionImpl = (*fileDescription)(nil)

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
		if params.CqEntries > linux.IORING_MAX_CQ_ENTRIES {
			return nil, linuxerr.EINVAL
		}
		numCqEntries = params.CqEntries
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
	sqEntriesSize := uint64(numSqEntries * 64)
	sqEntriesSize = uint64(hostarch.Addr(sqEntriesSize).MustRoundUp())

	sqefr, err := mfp.MemoryFile().Allocate(sqEntriesSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, linuxerr.ENOMEM
	}

	iouringfd := &fileDescription{
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

	return &iouringfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release(context.Context) {
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *fileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	var mf memmap.Mappable
	switch opts.Offset {
	case linux.IORING_OFF_SQ_RING, linux.IORING_OFF_CQ_RING:
		mf = &fd.rbmf
	case linux.IORING_OFF_SQES:
		mf = &fd.sqemf
	default:
		return linuxerr.EINVAL
	}

	return vfs.GenericConfigureMMap(&fd.vfsfd, mf, opts)
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
	expectedAccessType := hostarch.AccessType{
		Read:    true,
		Write:   true,
		Execute: false,
	}
	if at != expectedAccessType {
		return nil, &memmap.BusError{linuxerr.EPERM}
	}

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
	expectedAccessType := hostarch.AccessType{
		Read:    true,
		Write:   true,
		Execute: false,
	}
	if at != expectedAccessType {
		return nil, &memmap.BusError{linuxerr.EPERM}
	}

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
