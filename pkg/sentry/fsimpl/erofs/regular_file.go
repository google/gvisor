// Copyright 2023 The gVisor Authors.
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

package erofs

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type regularFileFD struct {
	fileDescription

	// offMu protects off.
	offMu sync.Mutex `state:"nosave"`

	// off is the file offset.
	// +checklocks:offMu
	off int64
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	if dst.NumBytes() == 0 {
		return 0, nil
	}

	data, err := fd.inode().Data()
	if err != nil {
		return 0, err
	}
	r := &regularFileReader{
		data: data,
		off:  uint64(offset),
	}
	return dst.CopyOutFrom(ctx, r)
}

type regularFileReader struct {
	data safemem.BlockSeq
	off  uint64
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (r *regularFileReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if r.off >= r.data.NumBytes() {
		return 0, io.EOF
	}
	cp, err := safemem.CopySeq(dsts, r.data.DropFirst(int(r.off)))
	r.off += cp
	return cp, err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.offMu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EROFS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EROFS
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.offMu.Lock()
	defer fd.offMu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// use offset as specified
	case linux.SEEK_CUR:
		offset += fd.off
	case linux.SEEK_END:
		offset += int64(fd.inode().Size())
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd.inode(), opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (i *inode) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	i.mapsMu.Lock()
	i.mappings.AddMapping(ms, ar, offset, writable)
	i.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (i *inode) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	i.mapsMu.Lock()
	i.mappings.RemoveMapping(ms, ar, offset, writable)
	i.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (i *inode) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	i.AddMapping(ctx, ms, dstAR, offset, writable)
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (i *inode) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	pgend, _ := hostarch.PageRoundUp(i.Size())
	if required.End > pgend {
		if required.Start >= pgend {
			return nil, &memmap.BusError{io.EOF}
		}
		required.End = pgend
	}
	if optional.End > pgend {
		optional.End = pgend
	}
	if at.Write {
		return nil, &memmap.BusError{linuxerr.EROFS}
	}
	offset, err := i.DataOffset()
	if err != nil {
		return nil, &memmap.BusError{err}
	}
	mr := optional
	return []memmap.Translation{
		{
			Source: mr,
			File:   &i.fs.mf,
			Offset: mr.Start + offset,
			Perms:  at,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (i *inode) InvalidateUnsavable(ctx context.Context) error {
	i.mapsMu.Lock()
	i.mappings.InvalidateAll(memmap.InvalidateOpts{})
	i.mapsMu.Unlock()
	return nil
}

// +stateify savable
type imageMemmapFile struct {
	memmap.NoBufferedIOFallback

	image *erofs.Image
}

// IncRef implements memmap.File.IncRef.
func (mf *imageMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {}

// DecRef implements memmap.File.DecRef.
func (mf *imageMemmapFile) DecRef(fr memmap.FileRange) {}

// MapInternal implements memmap.File.MapInternal.
func (mf *imageMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if at.Write {
		return safemem.BlockSeq{}, &memmap.BusError{linuxerr.EROFS}
	}
	bytes, err := mf.image.BytesAt(fr.Start, fr.Length())
	if err != nil {
		return safemem.BlockSeq{}, &memmap.BusError{err}
	}
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bytes)), nil
}

// FD implements memmap.File.FD.
func (mf *imageMemmapFile) FD() int {
	return mf.image.FD()
}
