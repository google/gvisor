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
		// TODO: Only save MemoryFile pages if they are stored in
		// regularFile.data. This would allow us to save tmpfs filesystems
		// using the main MemoryFile, without saving the whole MemoryFile
		// (including unrelated application memory). It would also avoid saving
		// MemoryFile pages that are referenced by e.g. a previous MM.Pin but
		// no longer owned by a regularFile; in such cases, the holder of the
		// extra reference won't be restored by filesystem checkpointing,
		// causing the referenced pages to be leaked.
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
	fs           *filesystem
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
		gap = rf.data.Insert(gap, memmap.MappableRange{rfseg.Start, rfseg.End}, rfseg.Value).NextGap()
		n += (rfseg.End - rfseg.Start) / hostarch.PageSize
	}
	if !cb.fs.accountPages(n) {
		return fmt.Errorf("restored filesystem would exceed size limit of %d pages", cb.fs.maxSizeInPages)
	}
	return nil
}
