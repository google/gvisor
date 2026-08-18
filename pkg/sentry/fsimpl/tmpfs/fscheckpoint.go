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
	rf.size.Store(uint64(crf.size))

	// The regularFile object was restored from the sentry state file, which
	// might contain outdated page mappings (in a mixed restore scenario
	// where filesystem state is restored from a different/newer checkpoint
	// than the sentry state). We must discard these old mappings to avoid
	// overlap panics and data corruption (multiple files mapping to the
	// same MemoryFile page) when we apply the new mappings from the
	// filesystem tar.
	//
	// This unaccounting is a no-op when mixed restore is not done, as the
	// restored mappings will already match the tar. If split checkpoint
	// restore is not specified at all, CompleteRestore returns early, and
	// this function is not called.
	//
	// Unaccount the pages used by the old mappings first.
	oldPages := uint64(0)
	for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		oldPages += seg.Range().Length() / hostarch.PageSize
	}
	cb.fs.unaccountPages(oldPages)

	// Clear the old mappings. The new mappings from the filesystem tar will
	// be applied below.
	rf.data = fsutil.FileRangeSet{}

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

// tarRestore restores the contents of regular files in the filesystem from a
// tar stream containing split filesystem checkpoint data.
//
// Unlike tarRead, which creates new inodes, tarRestore assumes that the
// directory structure and inodes have already been restored from the Sentry
// state file, and only updates the data mappings of existing regular files.
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

	return fs.mergeFromTar(ctx, tr, cb)
}

// clearAllFileMappingsLocked recursively walks the filesystem starting from the
// root and clears/invalidates mappings for all regular files.
//
// This is required for mixed restore scenarios where the sentry state is
// restored from a different (older) checkpoint than the filesystem. In this
// case:
//  1. We must invalidate active process memory mappings (mmaps) to the old
//     files so they don't point to stale pages.
//  2. We must clear sentry internal data mappings (rf.data) for all files. If
//     a file in the restored sentry state is not present in the new filesystem
//     checkpoint, its mappings will remain empty (size 0). This prevents
//     sentry from referencing unallocated or reallocated pages in the new
//     MemoryFile, which would otherwise cause panics during cleanup or exit.
func (fs *filesystem) clearAllFileMappingsLocked(ctx context.Context) {
	log.Debugf("clearAllFileMappingsLocked start, fs.pagesUsed = %d", fs.pagesUsed.Load())
	if fs.root == nil {
		log.Debugf("clearAllFileMappingsLocked: root is nil")
		return
	}
	fs.clearDentryMappingsLocked(ctx, fs.root)
	log.Debugf("clearAllFileMappingsLocked done, fs.pagesUsed = %d", fs.pagesUsed.Load())
}

func (fs *filesystem) clearDentryMappingsLocked(ctx context.Context, d *dentry) {
	if d == nil {
		log.Debugf("clearDentryMappingsLocked: dentry is nil")
		return
	}
	if d.inode == nil {
		return
	}
	switch impl := d.inode.impl.(type) {
	case *directory:
		for _, child := range impl.childMap {
			fs.clearDentryMappingsLocked(ctx, child)
		}
	case *regularFile:
		impl.inode.mu.Lock()
		impl.mapsMu.Lock()
		oldSize := impl.size.Load()
		log.Debugf("clearDentryMappingsLocked: regularFile ino %d, name %q, size %d", impl.inode.ino, d.name, oldSize)
		for seg := impl.mappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			log.Debugf("  mapping segment: %v", seg.Range())
			for m := range seg.Value() {
				log.Debugf("    mapping: space %T (%p), range %v, writable %v", m.MappingSpace, m.MappingSpace, m.AddrRange, m.Writable)
			}
		}
		if oldSize > 0 {
			log.Debugf("clearDentryMappingsLocked: invalidating mappings for ino %d, size %d", impl.inode.ino, oldSize)
			impl.mappings.Invalidate(memmap.MappableRange{Start: 0, End: offsetPageEnd(int64(oldSize))}, memmap.InvalidateOpts{
				InvalidatePrivate: true,
			})
		}
		impl.mapsMu.Unlock()

		impl.dataMu.Lock()
		pages := uint64(0)
		for seg := impl.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			pages += seg.Range().Length() / hostarch.PageSize
		}
		log.Debugf("clearDentryMappingsLocked: regularFile ino %d, pages to unaccount %d, fs.pagesUsed = %d", impl.inode.ino, pages, fs.pagesUsed.Load())
		fs.unaccountPages(pages)
		impl.data = fsutil.FileRangeSet{}
		impl.size.Store(0)
		impl.dataMu.Unlock()
		impl.inode.mu.Unlock()
	}
}
