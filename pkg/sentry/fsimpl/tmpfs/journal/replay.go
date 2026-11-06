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

package journal

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// File type bits of InodeRecord.Mode, as in Linux's S_IFMT.
const (
	modeTypeMask = 0170000
	modeSocket   = 0140000
	modeSymlink  = 0120000
	modeRegular  = 0100000
	modeBlock    = 0060000
	modeDir      = 0040000
	modeChar     = 0020000
	modeFifo     = 0010000
)

// maxFileOffset is the largest page-aligned regular file offset.
const maxFileOffset = (uint64(1) << 63) - hostarch.PageSize

// Extent maps file offsets [Off, Off+Len) of a regular file to filestore
// offsets [MFOff, MFOff+Len).
type Extent struct {
	Off   uint64
	Len   uint64
	MFOff uint64
}

// Inode is the replayed state of one inode.
type Inode struct {
	InodeRecord

	// Nlink is the link count, computed from the directory entries.
	Nlink uint32

	// Children maps names to inode numbers. It is only set for
	// directories.
	Children map[string]uint64

	// Extents holds the extents of a regular file, sorted by Off.
	Extents []Extent

	// extents holds the extents of a regular file during replay.
	extents fsutil.FileRangeSet

	// links is the number of directory entries that refer to the inode.
	links uint32

	// parent is the parent of a linked directory, or 0.
	parent uint64
}

func (i *Inode) fileType() uint32 {
	return i.Mode & modeTypeMask
}

// State is the filesystem state held by a journal.
type State struct {
	// Root is the root inode number. Root is 0 if the journal is new.
	Root uint64

	// NextIno is greater than every inode number in the journal.
	NextIno uint64

	// Inodes maps inode numbers to inodes. It only holds inodes that are
	// reachable from Root.
	Inodes map[uint64]*Inode

	// used holds the filestore ranges referenced by extents, sorted and
	// merged.
	used []memmap.FileRange
}

func newState() *State {
	return &State{Inodes: make(map[uint64]*Inode)}
}

// Empty returns true if s holds no filesystem.
func (s *State) Empty() bool {
	return s.Root == 0
}

// UsedRanges returns the filestore ranges referenced by s, sorted and merged.
func (s *State) UsedRanges() []memmap.FileRange {
	return s.used
}

// parseRecord parses the record at offset off of region. It returns ok ==
// false if there is no valid record with sequence number seq at off; this is
// the end of the log.
func parseRecord(region []byte, off, seq uint64) (typ RecordType, payload []byte, size uint64, ok bool) {
	if off > uint64(len(region)) {
		return 0, nil, 0, false
	}
	rem := uint64(len(region)) - off
	if rem < recordHeaderSize+recordCRCSize {
		return 0, nil, 0, false
	}
	rec := region[off:]
	if binary.LittleEndian.Uint32(rec[0:]) != recordMagic {
		return 0, nil, 0, false
	}
	payloadLen := uint64(binary.LittleEndian.Uint32(rec[4:]))
	size = recordSize(payloadLen)
	if size > rem {
		return 0, nil, 0, false
	}
	if binary.LittleEndian.Uint64(rec[8:]) != seq {
		return 0, nil, 0, false
	}
	if binary.LittleEndian.Uint16(rec[18:]) != 0 || binary.LittleEndian.Uint32(rec[20:]) != 0 {
		return 0, nil, 0, false
	}
	crc := binary.LittleEndian.Uint32(rec[recordHeaderSize+payloadLen:])
	if crc32.Checksum(rec[4:recordHeaderSize+payloadLen], castagnoli()) != crc {
		return 0, nil, 0, false
	}
	typ = RecordType(binary.LittleEndian.Uint16(rec[16:]))
	return typ, rec[recordHeaderSize : recordHeaderSize+payloadLen], size, true
}

// replayRegion replays the records in region and validates the result. It
// returns the state, the offset of the end of the log, and the sequence
// number that the next record must have.
func replayRegion(region []byte, startSeq, filestoreSize uint64) (*State, uint64, uint64, error) {
	st := newState()
	off := uint64(regionHeaderSize)
	seq := startSeq
	for {
		typ, payload, size, ok := parseRecord(region, off, seq)
		if !ok {
			break
		}
		if seq == startSeq && typ != RecordRoot {
			return nil, 0, 0, fmt.Errorf("first record is %v, want %v", typ, RecordRoot)
		}
		if err := st.apply(typ, payload, filestoreSize); err != nil {
			return nil, 0, 0, fmt.Errorf("record %d (%v): %w", seq, typ, err)
		}
		off += size
		seq++
	}
	if seq != startSeq {
		if err := st.finalize(); err != nil {
			return nil, 0, 0, err
		}
	}
	return st, off, seq, nil
}

func checkName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > MaxNameLen || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("invalid name %q", name)
	}
	return nil
}

func checkExtent(off, length, mfOff, filestoreSize uint64, set bool) error {
	if length == 0 || !hostarch.IsPageAligned(off) || !hostarch.IsPageAligned(length) || !hostarch.IsPageAligned(mfOff) {
		return fmt.Errorf("extent [%#x, +%#x) -> %#x is empty or not page-aligned", off, length, mfOff)
	}
	if off > maxFileOffset || length > maxFileOffset-off {
		return fmt.Errorf("extent [%#x, +%#x) exceeds the maximum file size", off, length)
	}
	if set && (mfOff > filestoreSize || length > filestoreSize-mfOff) {
		return fmt.Errorf("extent [%#x, +%#x) -> %#x exceeds the filestore size %#x", off, length, mfOff, filestoreSize)
	}
	return nil
}

// dir returns the directory with inode number ino.
func (s *State) dir(ino uint64) (*Inode, error) {
	d, ok := s.Inodes[ino]
	if !ok {
		return nil, fmt.Errorf("directory %d does not exist", ino)
	}
	if d.fileType() != modeDir {
		return nil, fmt.Errorf("inode %d is not a directory", ino)
	}
	return d, nil
}

// unlink removes the entry name from dir.
func (s *State) unlink(dir *Inode, name string) (*Inode, error) {
	childIno, ok := dir.Children[name]
	if !ok {
		return nil, fmt.Errorf("directory %d has no entry %q", dir.Ino, name)
	}
	child := s.Inodes[childIno]
	delete(dir.Children, name)
	child.links--
	if child.fileType() == modeDir {
		child.parent = 0
	}
	return child, nil
}

// link adds the entry name in dir for child.
func (s *State) link(dir *Inode, name string, child *Inode) error {
	if _, ok := dir.Children[name]; ok {
		return fmt.Errorf("directory %d already has an entry %q", dir.Ino, name)
	}
	if child.Ino == s.Root {
		return fmt.Errorf("cannot link the root directory")
	}
	if child.fileType() == modeDir {
		if child.parent != 0 {
			return fmt.Errorf("directory %d already has parent %d", child.Ino, child.parent)
		}
		child.parent = dir.Ino
	}
	dir.Children[name] = child.Ino
	child.links++
	return nil
}

func (s *State) applyInode(r *InodeRecord) error {
	if r.Ino == 0 {
		return fmt.Errorf("inode number 0")
	}
	typ := r.Mode & modeTypeMask
	switch typ {
	case modeSocket, modeSymlink, modeRegular, modeBlock, modeDir, modeChar, modeFifo:
	default:
		return fmt.Errorf("inode %d has invalid mode %#o", r.Ino, r.Mode)
	}
	if r.Mode&^(modeTypeMask|07777) != 0 {
		return fmt.Errorf("inode %d has invalid mode %#o", r.Ino, r.Mode)
	}
	if typ != modeRegular && r.Size != 0 {
		return fmt.Errorf("inode %d of type %#o has size %d", r.Ino, typ, r.Size)
	}
	if r.Size > maxFileOffset {
		return fmt.Errorf("inode %d has size %d", r.Ino, r.Size)
	}
	if (typ == modeSymlink) != (r.Target != "") {
		return fmt.Errorf("inode %d of type %#o has symlink target %q", r.Ino, typ, r.Target)
	}
	if typ != modeChar && typ != modeBlock && (r.RdevMajor != 0 || r.RdevMinor != 0) {
		return fmt.Errorf("inode %d of type %#o has a device number", r.Ino, typ)
	}
	for i := range r.Xattrs {
		if r.Xattrs[i].Name == "" || strings.IndexByte(r.Xattrs[i].Name, 0) >= 0 {
			return fmt.Errorf("inode %d has invalid xattr name %q", r.Ino, r.Xattrs[i].Name)
		}
		for k := 0; k < i; k++ {
			if r.Xattrs[k].Name == r.Xattrs[i].Name {
				return fmt.Errorf("inode %d has duplicate xattr %q", r.Ino, r.Xattrs[i].Name)
			}
		}
	}
	if i, ok := s.Inodes[r.Ino]; ok {
		if i.fileType() != typ {
			return fmt.Errorf("inode %d changed type from %#o to %#o", r.Ino, i.fileType(), typ)
		}
		i.InodeRecord = *r
		return nil
	}
	if len(s.Inodes) >= MaxInodes {
		return fmt.Errorf("more than %d inodes", MaxInodes)
	}
	i := &Inode{InodeRecord: *r}
	if typ == modeDir {
		i.Children = make(map[string]uint64)
	}
	s.Inodes[r.Ino] = i
	if r.Ino >= s.NextIno {
		s.NextIno = r.Ino + 1
	}
	return nil
}

// apply applies one record to s.
func (s *State) apply(typ RecordType, payload []byte, filestoreSize uint64) error {
	d := decoder{buf: payload}
	switch typ {
	case RecordRoot:
		root, next := d.u64(), d.u64()
		if err := d.done(); err != nil {
			return err
		}
		if s.Root != 0 {
			return fmt.Errorf("duplicate root record")
		}
		if root == 0 || next <= root {
			return fmt.Errorf("invalid root %d or next inode number %d", root, next)
		}
		s.Root = root
		s.NextIno = next

	case RecordInode:
		var r InodeRecord
		if err := r.decode(&d); err != nil {
			return err
		}
		if err := d.done(); err != nil {
			return err
		}
		return s.applyInode(&r)

	case RecordInodeFree:
		ino := d.u64()
		if err := d.done(); err != nil {
			return err
		}
		i, ok := s.Inodes[ino]
		if !ok {
			// The inode was not linked when the snapshot was taken.
			return nil
		}
		if ino == s.Root {
			return fmt.Errorf("cannot free the root directory")
		}
		if i.links != 0 {
			return fmt.Errorf("inode %d is freed with %d links", ino, i.links)
		}
		if len(i.Children) != 0 {
			return fmt.Errorf("directory %d is freed with %d entries", ino, len(i.Children))
		}
		delete(s.Inodes, ino)

	case RecordDirentAdd:
		parent, child := d.u64(), d.u64()
		name := d.str16(MaxNameLen)
		if err := d.done(); err != nil {
			return err
		}
		if err := checkName(name); err != nil {
			return err
		}
		dir, err := s.dir(parent)
		if err != nil {
			return err
		}
		c, ok := s.Inodes[child]
		if !ok {
			return fmt.Errorf("entry %q refers to missing inode %d", name, child)
		}
		return s.link(dir, name, c)

	case RecordDirentDel:
		parent := d.u64()
		name := d.str16(MaxNameLen)
		if err := d.done(); err != nil {
			return err
		}
		if err := checkName(name); err != nil {
			return err
		}
		dir, err := s.dir(parent)
		if err != nil {
			return err
		}
		_, err = s.unlink(dir, name)
		return err

	case RecordRename:
		oldParent, newParent, flags := d.u64(), d.u64(), d.u32()
		oldName := d.str16(MaxNameLen)
		newName := d.str16(MaxNameLen)
		if err := d.done(); err != nil {
			return err
		}
		if flags&^renameExchange != 0 {
			return fmt.Errorf("invalid rename flags %#x", flags)
		}
		if err := checkName(oldName); err != nil {
			return err
		}
		if err := checkName(newName); err != nil {
			return err
		}
		oldDir, err := s.dir(oldParent)
		if err != nil {
			return err
		}
		newDir, err := s.dir(newParent)
		if err != nil {
			return err
		}
		if oldParent == newParent && oldName == newName {
			if _, ok := oldDir.Children[oldName]; !ok {
				return fmt.Errorf("directory %d has no entry %q", oldParent, oldName)
			}
			return nil
		}
		renamed, err := s.unlink(oldDir, oldName)
		if err != nil {
			return err
		}
		if flags&renameExchange != 0 {
			replaced, err := s.unlink(newDir, newName)
			if err != nil {
				return err
			}
			if err := s.link(oldDir, oldName, replaced); err != nil {
				return err
			}
		} else if _, ok := newDir.Children[newName]; ok {
			replaced, err := s.unlink(newDir, newName)
			if err != nil {
				return err
			}
			if len(replaced.Children) != 0 {
				return fmt.Errorf("rename replaces non-empty directory %d", replaced.Ino)
			}
		}
		return s.link(newDir, newName, renamed)

	case RecordExtentSet, RecordExtentClear:
		ino, off, length := d.u64(), d.u64(), d.u64()
		var mfOff uint64
		if typ == RecordExtentSet {
			mfOff = d.u64()
		}
		if err := d.done(); err != nil {
			return err
		}
		if err := checkExtent(off, length, mfOff, filestoreSize, typ == RecordExtentSet); err != nil {
			return err
		}
		i, ok := s.Inodes[ino]
		if !ok {
			// The inode was not linked when the snapshot was taken.
			return nil
		}
		if i.fileType() != modeRegular {
			return fmt.Errorf("extent for inode %d of type %#o", ino, i.fileType())
		}
		mr := memmap.MappableRange{Start: off, End: off + length}
		i.extents.RemoveRange(mr)
		if typ == RecordExtentSet {
			i.extents.InsertRange(mr, mfOff)
		}

	default:
		return fmt.Errorf("unknown record type")
	}
	return nil
}

// finalize drops unlinked inodes, checks the tree and the extents, and
// computes link counts and used filestore ranges.
func (s *State) finalize() error {
	if s.Root == 0 {
		return fmt.Errorf("journal has no root record")
	}
	root, err := s.dir(s.Root)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if root.links != 0 {
		return fmt.Errorf("root directory has %d links", root.links)
	}

	// Find the inodes that are reachable from the root. Since each directory
	// has at most one parent, this walk cannot visit an inode twice through
	// directories.
	reachable := make(map[uint64]struct{}, len(s.Inodes))
	stack := []uint64{s.Root}
	for len(stack) > 0 {
		ino := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := reachable[ino]; ok {
			continue
		}
		reachable[ino] = struct{}{}
		for _, c := range s.Inodes[ino].Children {
			stack = append(stack, c)
		}
	}
	for ino, i := range s.Inodes {
		if _, ok := reachable[ino]; ok {
			continue
		}
		if i.links != 0 {
			// Linked but not reachable: the inode is in a directory cycle
			// or in a subtree that is detached from the root.
			return fmt.Errorf("inode %d is linked but not reachable from the root", ino)
		}
		// The inode was unlinked but still open. Drop it, which frees its
		// extents.
		delete(s.Inodes, ino)
	}

	var all []memmap.FileRange
	for _, i := range s.Inodes {
		switch i.fileType() {
		case modeDir:
			i.Nlink = 2
			for _, c := range i.Children {
				if s.Inodes[c].fileType() == modeDir {
					i.Nlink++
				}
			}
		default:
			i.Nlink = i.links
		}
		if i.fileType() != modeRegular {
			continue
		}
		// Pages past the end of the file are not part of it. Truncation
		// removes them, but a crash during a write can leave them.
		pgend, _ := hostarch.PageRoundUp(i.Size)
		i.extents.RemoveRange(memmap.MappableRange{Start: pgend, End: maxFileOffset})
		for seg := i.extents.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			fr := seg.FileRange()
			i.Extents = append(i.Extents, Extent{Off: seg.Start(), Len: seg.Range().Length(), MFOff: fr.Start})
			all = append(all, fr)
		}
		i.extents.RemoveAll()
	}

	sort.Slice(all, func(a, b int) bool { return all[a].Start < all[b].Start })
	for k := 1; k < len(all); k++ {
		if all[k].Start < all[k-1].End {
			return fmt.Errorf("filestore range %v is used by more than one file range", all[k].Intersect(all[k-1]))
		}
	}
	for _, fr := range all {
		if n := len(s.used); n != 0 && s.used[n-1].End == fr.Start {
			s.used[n-1].End = fr.End
			continue
		}
		s.used = append(s.used, fr)
	}
	return nil
}
