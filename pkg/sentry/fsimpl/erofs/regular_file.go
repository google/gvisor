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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
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

	return dst.CopyOutFrom(ctx, &regularFileReader{inode: fd.inode(), off: uint64(offset)})
}

type regularFileReader struct {
	inode *inode
	off   uint64
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (r *regularFileReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	var done uint64
	for !dsts.IsEmpty() {
		if r.off >= r.inode.Size() {
			return done, io.EOF
		}
		e, err := r.inode.MapBlocks(r.off)
		if err != nil {
			return done, err
		}
		within := r.off - e.Off
		dst := dsts.TakeFirst64(min(e.Length-within, r.inode.Size()-r.off))
		var n uint64
		switch {
		case !e.Mapped:
			n, err = safemem.ZeroSeq(dst)
		case r.inode.fs.useReadForIO:
			n, err = hostfd.Preadv2(int32(r.inode.fs.image.FD()), dst, int64(e.ImageOff+within), 0 /* flags */)
		default:
			var data []byte
			if data, err = r.inode.fs.image.BytesAt(e.ImageOff+within, dst.NumBytes()); err == nil {
				n, err = safemem.CopySeq(dst, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data)))
			}
		}
		r.off += n
		done += n
		if err != nil || n < dst.NumBytes() {
			return done, err
		}
		dsts = dsts.DropFirst64(n)
	}
	return done, nil
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
	if opts.MaxPerms.Write && !opts.Private {
		return linuxerr.EINVAL
	}
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
	var beyondEOF bool
	if required.End > pgend {
		if required.Start >= pgend {
			return nil, &memmap.BusError{io.EOF}
		}
		beyondEOF = true
		required.End = pgend
	}
	if optional.End > pgend {
		optional.End = pgend
	}
	if at.Write {
		// This shouldn't be possible due to the check in ConfigureMMap().
		inodeTranslateWriteWarnOnce.Do(func() {
			log.Traceback("erofs.inode.Translate: unexpected access type %v", at)
		})
		return nil, &memmap.BusError{linuxerr.EROFS}
	}
	// TODO: Tail-packed inline data isn't block aligned in the image, so
	// regular files with inline data can't be mapped. The image should be
	// created with the "-E noinline_data" option, which was introduced for
	// the DAX feature support in Linux [1].
	// [1] https://github.com/erofs/erofs-utils/commit/60549d52c3b636f0ddd1d51b0c1517c1dee22595
	if i.DataLayout() == erofs.InodeDataLayoutFlatInline {
		return nil, &memmap.BusError{linuxerr.ENOTSUP}
	}
	var ts []memmap.Translation
	for off := required.Start; off < required.End; {
		e, err := i.MapBlocks(off)
		if err != nil {
			return ts, &memmap.BusError{err}
		}
		t := memmap.Translation{Perms: hostarch.ReadExecute}
		if e.Mapped {
			t.Source = memmap.MappableRange{Start: max(e.Off, optional.Start), End: min(e.Off+e.Length, optional.End)}
			t.File = &i.fs.mf
			t.Offset = e.ImageOff + t.Source.Start - e.Off
		} else {
			t.Source = memmap.MappableRange{Start: off, End: off + hostarch.PageSize}
			t.File = i.fs.memoryFile
			t.Offset = i.fs.zeroPage.Start
		}
		ts = append(ts, t)
		off = t.Source.End
	}
	if beyondEOF {
		return ts, &memmap.BusError{io.EOF}
	}
	return ts, nil
}

var inodeTranslateWriteWarnOnce sync.Once

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (i *inode) InvalidateUnsavable(ctx context.Context) error {
	i.mapsMu.Lock()
	i.mappings.InvalidateAll(memmap.InvalidateOpts{})
	i.mapsMu.Unlock()
	return nil
}

// +stateify savable
type imageMemmapFile struct {
	memmap.DefaultMemoryType
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

// DataFD implements memmap.File.DataFD.
func (mf *imageMemmapFile) DataFD(fr memmap.FileRange) (int, error) {
	return mf.FD(), nil
}

// FD implements memmap.File.FD.
func (mf *imageMemmapFile) FD() int {
	return mf.image.FD()
}
