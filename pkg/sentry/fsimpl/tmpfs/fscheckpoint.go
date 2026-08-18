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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
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
	rf.size.Store(crf.size)

	gap := rf.data.FirstGap()
	n := uint64(0)
	for _, rfseg := range crf.data {
		gap = rf.data.Insert(gap, memmap.MappableRange{Start: rfseg.Start, End: rfseg.End}, rfseg.Value).NextGap()
		n += (rfseg.End - rfseg.Start) / hostarch.PageSize
	}
	if !cb.fs.accountPages(n) {
		return fmt.Errorf("restored filesystem would exceed size limit of %d pages", cb.fs.maxSizeInPages)
	}
	return nil
}

// tarRestore restores the tmpfs filesystem from a tar stream containing
// filesystem checkpoint data by clearing in-memory metadata and reloading from
// tar.
//
// Preconditions: The kernel must be paused and quiesced.
func (fs *filesystem) tarRestore(ctx context.Context, src io.Reader) error {
	tr := tar.NewReader(src)
	cb := &fsckptTarReaderCallbacks{
		fs:           fs,
		regularFiles: make(map[*tar.Header]*fsckptRegularFile),
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.clearAllFileMappingsLocked(ctx)
	if fs.root != nil && fs.root.inode != nil && fs.root.inode.isDir() {
		fs.root.wipeChildrenLocked(ctx)
	}

	return fs.readFromTar(ctx, tr, cb)
}

// clearAllFileMappingsLocked clears and invalidates mappings for all regular
// files in the filesystem (including unlinked-but-open files).
//
// In split restore scenarios (e.g. Sentry state from checkpoint T1 combined with
// a filesystem checkpoint from T2):
//  1. Inodes and file descriptors are reconstituted from T1, but the backing
//     pgalloc.MemoryFile is loaded from T2 (or freshly initialized). Without
//     invalidation, rf.data would reference T1 frame offsets in T2's MemoryFile,
//     leading to cross-file data corruption on reads or a panic in
//     MemoryFile.DecRef ("DecRef called with 0 references") when the file is
//     closed.
//  2. By iterating fs.regularFiles, we ensure that every regularFile—whether
//     linked in a directory or unlinked-but-held-open by an active file
//     descriptor—has its active memory mappings invalidated via
//     rf.mappings.Invalidate (which unmaps address space and drops PMAs/frame
//     references).
//  3. We then clear rf.data to an empty set and reset rf.size to 0, unaccounting
//     any previously tracked pages in fs.pagesUsed.
//
// Files present in the incoming T2 filesystem archive will subsequently have
// their contents and rf.data repopulated by readFromTar.
//
// Files deleted at T2 or unlinked open files safely remain size 0 with no
// dangling MemoryFile page references. If an application retained an open
// file descriptor or mmap mapping to such a file across restore:
//   - Reads on the open file descriptor will return EOF (0 bytes).
//   - Accessing memory-mapped pages will fault beyond EOF (size 0), causing the
//     kernel to deliver SIGBUS to the process, matching standard Linux behavior
//     for truncated/emptied files.
func (fs *filesystem) clearAllFileMappingsLocked(ctx context.Context) {
	log.Debugf("clearAllFileMappingsLocked start, fs.pagesUsed = %d", fs.pagesUsed.Load())
	fs.regularFilesMu.Lock()
	rfs := make([]*regularFile, 0, len(fs.regularFiles))
	for rf := range fs.regularFiles {
		rfs = append(rfs, rf)
	}
	fs.regularFilesMu.Unlock()

	for _, rf := range rfs {
		fs.clearRegularFileMappingsLocked(ctx, rf)
	}
	log.Debugf("clearAllFileMappingsLocked done, fs.pagesUsed = %d", fs.pagesUsed.Load())
}

func (fs *filesystem) clearRegularFileMappingsLocked(ctx context.Context, rf *regularFile) {
	if rf == nil {
		return
	}
	rf.inode.mu.Lock()
	rf.mapsMu.Lock()
	oldSize := rf.size.Load()
	log.Debugf("clearRegularFileMappingsLocked: regularFile ino %d, size %d", rf.inode.ino, oldSize)
	for seg := rf.mappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		log.Debugf("  mapping segment: %v", seg.Range())
		for m := range seg.Value() {
			log.Debugf("    mapping: space %T (%p), range %v, writable %v", m.MappingSpace, m.MappingSpace, m.AddrRange, m.Writable)
		}
	}
	if oldSize > 0 {
		log.Debugf("clearRegularFileMappingsLocked: invalidating mappings for ino %d, size %d", rf.inode.ino, oldSize)
		rf.mappings.Invalidate(memmap.MappableRange{Start: 0, End: offsetPageEnd(int64(oldSize))}, memmap.InvalidateOpts{
			InvalidatePrivate: true,
		})
	}
	rf.mapsMu.Unlock()

	rf.dataMu.Lock()
	pages := uint64(0)
	for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		pages += seg.Range().Length() / hostarch.PageSize
	}
	log.Debugf("clearRegularFileMappingsLocked: regularFile ino %d, pages to unaccount %d, fs.pagesUsed = %d", rf.inode.ino, pages, fs.pagesUsed.Load())
	fs.unaccountPages(pages)
	rf.data = fsutil.FileRangeSet{}
	rf.size.Store(0)
	rf.dataMu.Unlock()
	rf.inode.mu.Unlock()
}
