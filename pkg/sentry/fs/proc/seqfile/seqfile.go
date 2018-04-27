// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// SeqHandle is a helper handle to seek in the file.
type SeqHandle interface{}

// SeqData holds the data for one unit in the file.
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
	ReadSeqFileData(handle SeqHandle) ([]SeqData, int64)
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
type SeqFile struct {
	ramfs.Entry

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	SeqSource

	source     []SeqData
	generation int64
	lastRead   int64
}

// NewSeqFile returns a seqfile suitable for use by external consumers.
func NewSeqFile(ctx context.Context, source SeqSource) *SeqFile {
	s := &SeqFile{SeqSource: source}
	s.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0444))
	return s
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
	return fs.NewInode(iops, msrc, sattr)
}

// UnstableAttr returns unstable attributes of the SeqFile.
func (s *SeqFile) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, _ := s.Entry.UnstableAttr(ctx, inode)
	uattr.ModificationTime = ktime.NowFromContext(ctx)
	return uattr, nil
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

// DeprecatedPreadv reads from the file at the given offset.
func (s *SeqFile) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Entry.NotifyAccess(ctx)
	defer func() { s.lastRead = offset }()

	updated := false

	// Try to find where we should start reading this file.
	i, recordOffset := findIndexAndOffset(s.source, offset)
	if i == len(s.source) {
		// Ok, we're at EOF. Let's first check to see if there might be
		// more data available to us. If there is more data, add it to
		// the end and try reading again.
		if !s.SeqSource.NeedsUpdate(s.generation) {
			return 0, io.EOF
		}
		oldLen := len(s.source)
		s.updateSourceLocked(len(s.source))
		updated = true
		// We know that we had consumed everything up until this point
		// so we search in the new slice instead of starting over.
		i, recordOffset = findIndexAndOffset(s.source[oldLen:], recordOffset)
		i += oldLen
		// i is at most the length of the slice which is
		// len(s.source) - oldLen. So at most i will be equal to
		// len(s.source).
		if i == len(s.source) {
			return 0, io.EOF
		}
	}

	var done int64
	// We're reading parts of a record, finish reading the current object
	// before continuing on to the next. We don't refresh our data source
	// before this record is completed.
	if recordOffset != 0 {
		n, err := dst.CopyOut(ctx, s.source[i].Buf[recordOffset:])
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
	if !updated && (s.SeqSource.NeedsUpdate(s.generation) || s.lastRead > offset) {
		s.updateSourceLocked(i)
		// recordOffset is 0 here and we won't update records behind the
		// current one so recordOffset is still 0 even though source
		// just got updated. Just read the next record.
	}

	// Finish by reading all the available data.
	for _, buf := range s.source[i:] {
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

// updateSourceLocked requires that s.mu is held.
func (s *SeqFile) updateSourceLocked(record int) {
	var h SeqHandle
	if record == 0 {
		h = nil
	} else {
		h = s.source[record-1].Handle
	}
	// Save what we have previously read.
	s.source = s.source[:record]
	var newSource []SeqData
	newSource, s.generation = s.SeqSource.ReadSeqFileData(h)
	s.source = append(s.source, newSource...)
}

// DeprecatedPwritev is always denied.
func (*SeqFile) DeprecatedPwritev(context.Context, usermem.IOSequence, int64) (int64, error) {
	return 0, ramfs.ErrDenied
}
