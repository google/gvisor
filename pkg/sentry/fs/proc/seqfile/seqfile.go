// Copyright 2018 The gVisor Authors.
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

package seqfile

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/device"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SeqHandle is a helper handle to seek in the file.
type SeqHandle interface{}

// SeqData holds the data for one unit in the file.
//
// +stateify savable
type SeqData struct {
	// The data to be returned to the user.
	Buf []byte

	// A seek handle used to find the next valid unit in ReadSeqFiledata.
	Handle SeqHandle
}

// SeqSource is a data source for a SeqFile file.
type SeqSource interface {
	// NeedsUpdate returns true if the consumer of SeqData should call
	// ReadSeqFileData again. Generation is the generation returned by
	// ReadSeqFile or 0.
	NeedsUpdate(generation int64) bool

	// Returns a slice of SeqData ordered by unit and the current
	// generation. The first entry in the slice is greater than the handle.
	// If handle is nil then all known records are returned. Generation
	// must always be greater than 0.
	ReadSeqFileData(ctx context.Context, handle SeqHandle) ([]SeqData, int64)
}

// SeqGenerationCounter is a counter to keep track if the SeqSource should be
// updated. SeqGenerationCounter is not thread-safe and should be protected
// with a mutex.
type SeqGenerationCounter struct {
	// The generation that the SeqData is at.
	generation int64
}

// SetGeneration sets the generation to the new value, be careful to not set it
// to a value less than current.
func (s *SeqGenerationCounter) SetGeneration(generation int64) {
	s.generation = generation
}

// Update increments the current generation.
func (s *SeqGenerationCounter) Update() {
	s.generation++
}

// Generation returns the current generation counter.
func (s *SeqGenerationCounter) Generation() int64 {
	return s.generation
}

// IsCurrent returns whether the given generation is current or not.
func (s *SeqGenerationCounter) IsCurrent(generation int64) bool {
	return s.Generation() == generation
}

// SeqFile is used to provide dynamic files that can be ordered by record.
//
// +stateify savable
type SeqFile struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopRelease    `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotAllocatable `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`
	fsutil.InodeNotTruncatable `state:"nosave"`
	fsutil.InodeVirtual        `state:"nosave"`

	fsutil.InodeSimpleExtendedAttributes
	fsutil.InodeSimpleAttributes

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	SeqSource

	source     []SeqData
	generation int64
	lastRead   int64
}

var _ fs.InodeOperations = (*SeqFile)(nil)

// NewSeqFile returns a seqfile suitable for use by external consumers.
func NewSeqFile(ctx context.Context, source SeqSource) *SeqFile {
	return &SeqFile{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		SeqSource:             source,
	}
}

// NewSeqFileInode returns an Inode with SeqFile InodeOperations.
func NewSeqFileInode(ctx context.Context, source SeqSource, msrc *fs.MountSource) *fs.Inode {
	iops := NewSeqFile(ctx, source)
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialFile,
	}
	return fs.NewInode(ctx, iops, msrc, sattr)
}

// UnstableAttr returns unstable attributes of the SeqFile.
func (s *SeqFile) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, err := s.InodeSimpleAttributes.UnstableAttr(ctx, inode)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	uattr.ModificationTime = ktime.NowFromContext(ctx)
	return uattr, nil
}

// GetFile implements fs.InodeOperations.GetFile.
func (s *SeqFile) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &seqFileOperations{seqFile: s}), nil
}

// findIndexAndOffset finds the unit that corresponds to a certain offset.
// Returns the unit and the offset within the unit. If there are not enough
// units len(data) and leftover offset is returned.
func findIndexAndOffset(data []SeqData, offset int64) (int, int64) {
	for i, buf := range data {
		l := int64(len(buf.Buf))
		if offset < l {
			return i, offset
		}
		offset -= l
	}
	return len(data), offset
}

// updateSourceLocked requires that s.mu is held.
func (s *SeqFile) updateSourceLocked(ctx context.Context, record int) {
	var h SeqHandle
	if record == 0 {
		h = nil
	} else {
		h = s.source[record-1].Handle
	}
	// Save what we have previously read.
	s.source = s.source[:record]
	var newSource []SeqData
	newSource, s.generation = s.SeqSource.ReadSeqFileData(ctx, h)
	s.source = append(s.source, newSource...)
}

// seqFileOperations implements fs.FileOperations.
//
// +stateify savable
type seqFileOperations struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	seqFile *SeqFile
}

var _ fs.FileOperations = (*seqFileOperations)(nil)

// Write implements fs.FileOperations.Write.
func (*seqFileOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EACCES
}

// Read implements fs.FileOperations.Read.
func (sfo *seqFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	sfo.seqFile.mu.Lock()
	defer sfo.seqFile.mu.Unlock()

	sfo.seqFile.NotifyAccess(ctx)
	defer func() { sfo.seqFile.lastRead = offset }()

	updated := false

	// Try to find where we should start reading this file.
	i, recordOffset := findIndexAndOffset(sfo.seqFile.source, offset)
	if i == len(sfo.seqFile.source) {
		// Ok, we're at EOF. Let's first check to see if there might be
		// more data available to us. If there is more data, add it to
		// the end and try reading again.
		if !sfo.seqFile.SeqSource.NeedsUpdate(sfo.seqFile.generation) {
			return 0, io.EOF
		}
		oldLen := len(sfo.seqFile.source)
		sfo.seqFile.updateSourceLocked(ctx, len(sfo.seqFile.source))
		updated = true
		// We know that we had consumed everything up until this point
		// so we search in the new slice instead of starting over.
		i, recordOffset = findIndexAndOffset(sfo.seqFile.source[oldLen:], recordOffset)
		i += oldLen
		// i is at most the length of the slice which is
		// len(sfo.seqFile.source) - oldLen. So at most i will be equal to
		// len(sfo.seqFile.source).
		if i == len(sfo.seqFile.source) {
			return 0, io.EOF
		}
	}

	var done int64
	// We're reading parts of a record, finish reading the current object
	// before continuing on to the next. We don't refresh our data source
	// before this record is completed.
	if recordOffset != 0 {
		n, err := dst.CopyOut(ctx, sfo.seqFile.source[i].Buf[recordOffset:])
		done += int64(n)
		dst = dst.DropFirst(n)
		if dst.NumBytes() == 0 || err != nil {
			return done, err
		}
		i++
	}

	// Next/New unit, update the source file if necessary. Make an extra
	// check to see if we've seeked backwards and if so always update our
	// data source.
	if !updated && (sfo.seqFile.SeqSource.NeedsUpdate(sfo.seqFile.generation) || sfo.seqFile.lastRead > offset) {
		sfo.seqFile.updateSourceLocked(ctx, i)
		// recordOffset is 0 here and we won't update records behind the
		// current one so recordOffset is still 0 even though source
		// just got updated. Just read the next record.
	}

	// Finish by reading all the available data.
	for _, buf := range sfo.seqFile.source[i:] {
		n, err := dst.CopyOut(ctx, buf.Buf)
		done += int64(n)
		dst = dst.DropFirst(n)
		if dst.NumBytes() == 0 || err != nil {
			return done, err
		}
	}

	// If the file shrank (entries not yet read were removed above)
	// while we tried to read we can end up with nothing read.
	if done == 0 && dst.NumBytes() != 0 {
		return 0, io.EOF
	}
	return done, nil
}
