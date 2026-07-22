// Copyright 2026 The gVisor Authors.
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

package tmpfs

import (
	"archive/tar"
	"encoding/binary"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// MemoryFileOf returns the pgalloc.MemoryFile used by the given tmpfs
// filesystem. If vfsfs is not a tmpfs filesystem, MemoryFileOf returns nil.
func MemoryFileOf(vfsfs *vfs.Filesystem) *pgalloc.MemoryFile {
	if fs, _ := vfsfs.Impl().(*filesystem); fs != nil {
		return fs.mf
	}
	return nil
}

// ResourceIDOf returns the filesystem checkpoint ResourceID of the given tmpfs
// filesystem, or the zero ResourceID if vfsfs is not a tmpfs filesystem.
func ResourceIDOf(vfsfs *vfs.Filesystem) checkpoint.ResourceID {
	if fs, _ := vfsfs.Impl().(*filesystem); fs != nil {
		return fs.resourceID
	}
	return checkpoint.ResourceID{}
}

// FSCheckpointWrite serializes the given tmpfs filesystem to dst. The contents
// of its regular files are not written to dst; instead, callers must
// separately save and restore the contents of the filesystem's MemoryFile. If
// vfsfs is not a tmpfs filesystem, FSCheckpointWrite returns an error.
//
// Preconditions: The Kernel must be paused and quiesced.
func FSCheckpointWrite(ctx context.Context, vfsfs *vfs.Filesystem, dst io.Writer) error {
	fs, _ := vfsfs.Impl().(*filesystem)
	if fs == nil {
		return fmt.Errorf("non-tmpfs filesystem: %T", vfsfs.Impl())
	}
	return fs.tarWrite(ctx, dst, &fsckptTarWriterCallbacks{
		regularFiles: make(map[*regularFile]*fsckptRegularFile),
	})
}

// FSCheckpointWriteShared is like FSCheckpointWrite, except that it is used for
// tmpfs filesystems whose MemoryFile is the shared/main MemoryFile, whose
// contents cannot be saved as a whole. Instead of recording MemoryFile offsets,
// it writes each regular file's pages directly to the pages file via amfs
// (which must be a registration of the filesystem's MemoryFile) and records the
// resulting pages file offsets in the tar archive. On restore, the contents are
// loaded back into freshly-allocated pages via
// pgalloc.AsyncPagesFileLoad.LoadRangesInto (see fsckptTarReaderCallbacks). If
// vfsfs is not a tmpfs filesystem, FSCheckpointWriteShared returns an error.
//
// Preconditions: The Kernel must be paused and quiesced.
func FSCheckpointWriteShared(ctx context.Context, vfsfs *vfs.Filesystem, amfs *pgalloc.AsyncMemoryFileSave, dst io.Writer) error {
	fs, _ := vfsfs.Impl().(*filesystem)
	if fs == nil {
		return fmt.Errorf("non-tmpfs filesystem: %T", vfsfs.Impl())
	}
	return fs.tarWrite(ctx, dst, &fsckptSharedTarWriterCallbacks{amfs: amfs})
}

// fsckptSharedTarWriterCallbacks implements tarWriterCallbacks for a tmpfs
// filesystem backed by the shared/main MemoryFile. It writes each regular
// file's pages to the pages file (without copying) and stores the resulting
// pages file offsets in the tar archive. The on-tar format is identical to
// fsckptTarWriterCallbacks; only the meaning of the stored offsets differs (they
// are pages file offsets rather than offsets into the filesystem's MemoryFile),
// which the reader handles via its relocate field.
type fsckptSharedTarWriterCallbacks struct {
	amfs *pgalloc.AsyncMemoryFileSave
}

// regularFileNumSegments returns the number of segments in rf.data.
//
// Preconditions: rf.dataMu must be locked.
func regularFileNumSegments(rf *regularFile) int64 {
	n := int64(0)
	for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		n++
	}
	return n
}

func (cb *fsckptSharedTarWriterCallbacks) regularFileSize(rf *regularFile) int64 {
	rf.dataMu.RLock()
	defer rf.dataMu.RUnlock()
	return 8 /* size */ + regularFileNumSegments(rf)*int64((*fsckptRegularFileSegment)(nil).SizeBytes())
}

func (cb *fsckptSharedTarWriterCallbacks) regularFileWrite(ctx context.Context, rf *regularFile, tw *tar.Writer) error {
	rf.dataMu.RLock()
	defer rf.dataMu.RUnlock()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], rf.size.RacyLoad())
	if _, err := tw.Write(buf[:]); err != nil {
		return fmt.Errorf("failed to write file size to tar: %w", err)
	}
	segs := make([]fsckptRegularFileSegment, 0, regularFileNumSegments(rf))
	for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		// Write this segment's pages to the pages file (read directly from the
		// shared MemoryFile, without copying) and record the pages file offset.
		pagesFileOffset := cb.amfs.WriteRange(seg.FileRangeOf(seg.Range()))
		segs = append(segs, fsckptRegularFileSegment{
			Start: seg.Start(),
			End:   seg.End(),
			Value: pagesFileOffset,
		})
	}
	if _, err := WriteCheckpointRegularFileSegmentSlice(tw, segs); err != nil {
		return fmt.Errorf("failed to write file segments to tar: %w", err)
	}
	return nil
}

// fsckptTarWriterCallbacks implements tarWriterCallbacks by storing MemoryFile
// offsets containing regular file data in the tar archive.
type fsckptTarWriterCallbacks struct {
	regularFiles map[*regularFile]*fsckptRegularFile
}

type fsckptRegularFile struct {
	size uint64
	data []fsckptRegularFileSegment
}

// fsckptRegularFileSegment is equivalent to fsutil.FileRangeFlatSegment, but
// is marshalable.
//
// +marshal slice:CheckpointRegularFileSegmentSlice
type fsckptRegularFileSegment struct {
	Start uint64
	End   uint64
	Value uint64
}

func (cb *fsckptTarWriterCallbacks) checkpointRegularFile(rf *regularFile) *fsckptRegularFile {
	crf := cb.regularFiles[rf]
	if crf == nil {
		rf.dataMu.RLock()
		defer rf.dataMu.RUnlock()
		crf = &fsckptRegularFile{
			size: rf.size.RacyLoad(),
		}
		for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			crf.data = append(crf.data, fsckptRegularFileSegment{
				Start: seg.Start(),
				End:   seg.End(),
				Value: seg.Value(),
			})
		}
		cb.regularFiles[rf] = crf
	}
	return crf
}

func (cb *fsckptTarWriterCallbacks) regularFileSize(rf *regularFile) int64 {
	crf := cb.checkpointRegularFile(rf)
	return 8 /* size */ + int64(len(crf.data))*int64((*fsckptRegularFileSegment)(nil).SizeBytes())
}

func (cb *fsckptTarWriterCallbacks) regularFileWrite(ctx context.Context, rf *regularFile, tw *tar.Writer) error {
	crf := cb.checkpointRegularFile(rf)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], crf.size)
	if _, err := tw.Write(buf[:]); err != nil {
		return fmt.Errorf("failed to write file size to tar: %w", err)
	}
	if _, err := WriteCheckpointRegularFileSegmentSlice(tw, crf.data); err != nil {
		return fmt.Errorf("failed to write file segments to tar: %w", err)
	}
	return nil
}

// fsckptTarReaderCallbacks implements tarReaderCallbacks by storing MemoryFile
// offsets containing regular file data in the tar archive.
type fsckptTarReaderCallbacks struct {
	fs *filesystem

	// relocate indicates that the filesystem's MemoryFile (fs.mf) is the
	// shared/main MemoryFile, so the offsets stored in the tar archive are pages
	// file offsets (written by FSCheckpointWriteShared) rather than offsets into
	// fs.mf. In this case, regularFileSetContents allocates fresh pages in fs.mf
	// and records, in relocFRs/relocOffs, the pages that must be loaded from the
	// pages file; the caller (GetFilesystem) then loads them via
	// pgalloc.AsyncPagesFileLoad.LoadRangesInto.
	relocate bool

	// relocFRs and relocOffs accumulate the freshly-allocated ranges of fs.mf
	// and their corresponding pages file offsets when relocate is true.
	relocFRs  []memmap.FileRange
	relocOffs []uint64

	regularFiles map[*tar.Header]*fsckptRegularFile
}

func (cb *fsckptTarReaderCallbacks) regularFileRead(ctx context.Context, hdr *tar.Header, tr *tar.Reader) error {
	if hdr.Size < 8 {
		return fmt.Errorf("header size %d too small for regular file size", hdr.Size)
	}
	remSize := hdr.Size - 8
	segSize := int64((*fsckptRegularFileSegment)(nil).SizeBytes())
	if remSize%segSize != 0 {
		return fmt.Errorf("header size %d is not 8 + integer multiple of %d", hdr.Size, segSize)
	}
	var buf [8]byte
	if _, err := io.ReadFull(tr, buf[:]); err != nil {
		return fmt.Errorf("failed to read file size from tar: %w", err)
	}
	crf := &fsckptRegularFile{
		size: binary.LittleEndian.Uint64(buf[:]),
		data: make([]fsckptRegularFileSegment, remSize/segSize),
	}
	if _, err := ReadCheckpointRegularFileSegmentSlice(tr, crf.data); err != nil {
		return fmt.Errorf("failed to read file segments from tar: %w", err)
	}
	cb.regularFiles[hdr] = crf
	return nil
}

func (cb *fsckptTarReaderCallbacks) regularFileSetContents(ctx context.Context, hdr *tar.Header, rf *regularFile) error {
	crf := cb.regularFiles[hdr]
	rf.inode.mu.Lock()
	defer rf.inode.mu.Unlock()
	rf.dataMu.Lock()
	defer rf.dataMu.Unlock()
	rf.size.Store(uint64(crf.size))
	gap := rf.data.FirstGap()
	n := uint64(0)
	for _, rfseg := range crf.data {
		value := rfseg.Value
		if cb.relocate {
			// The filesystem is backed by the shared/main MemoryFile, so
			// rfseg.Value is a pages file offset rather than an offset into
			// fs.mf. Allocate fresh pages in fs.mf to hold the file's contents
			// (using AllocateAndWritePopulate to match the normal tmpfs shmem
			// write path; see regularFileReadWriter.WriteFromBlocks) and record
			// them to be loaded from the pages file later by GetFilesystem.
			length := rfseg.End - rfseg.Start
			dstFR, err := cb.fs.mf.Allocate(length, pgalloc.AllocOpts{
				Kind: cb.fs.usage,
				Mode: pgalloc.AllocateAndWritePopulate,
			})
			if err != nil {
				return fmt.Errorf("failed to allocate memory for restored file: %w", err)
			}
			cb.relocFRs = append(cb.relocFRs, dstFR)
			cb.relocOffs = append(cb.relocOffs, value)
			value = dstFR.Start
		}
		gap = rf.data.Insert(gap, memmap.MappableRange{rfseg.Start, rfseg.End}, value).NextGap()
		n += (rfseg.End - rfseg.Start) / hostarch.PageSize
	}
	if !cb.fs.accountPages(n) {
		return fmt.Errorf("restored filesystem would exceed size limit of %d pages", cb.fs.maxSizeInPages)
	}
	return nil
}
