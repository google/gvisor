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
	"errors"
	"fmt"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// This file implements the metadata journal of a tmpfs. See
// package journal.
//
// Every change to the metadata of a journaled tmpfs appends records to the
// journal:
//
//   - Namespace changes append records while filesystem.mu is locked for
//     writing. A record that deletes a directory entry is appended before the
//     entry's inode can be released.
//
//   - INODE records are built and appended while inode.mu is locked, so that
//     the records for one inode are appended in the order of its changes.
//
//   - Extent records are appended while regularFile.dataMu is locked for
//     writing. EXTENT_CLEAR records are appended before the pages are
//     returned to the MemoryFile, so that no page is ever referenced by two
//     files in the journal. Newly allocated pages are always zeroed, so an
//     EXTENT_SET record that precedes the data copy can only expose zeros.
//
// Compaction locks filesystem.mu for reading, then each inode's inode.mu and
// regularFile.dataMu in turn while it writes the inode's snapshot records.
//
// Atime updates by reads are not journaled; the next INODE record or
// snapshot of the inode records them.


func (fs *filesystem) startJournal(j *journal.Journal) error {
	fs.mu.Lock()
	if fs.released {
		fs.mu.Unlock()
		return fmt.Errorf("tmpfs filesystem was released")
	}
	fs.journal.Store(j)
	fs.journaled.Store(true)
	fs.mu.Unlock()
	if err := fs.compactJournal(); err != nil {
		fs.journal.Store(nil)
		return fmt.Errorf("failed to compact tmpfs journal: %w", err)
	}
	return nil
}

// stopJournal stops journaling. Later changes to fs are not journaled, so
// that releasing the filesystem does not delete its contents from the
// journal.
func (fs *filesystem) stopJournal() {
	j := fs.journal.Swap(nil)
	if j == nil {
		return
	}
	j.Close()
}

// snapshotWriter is implemented by journal.Snapshot, which writes snapshot
// records, and by journal.SnapshotSizer, which computes their size.
type snapshotWriter interface {
	Inode(r *journal.InodeRecord)
	DirentAdd(parent uint64, name string, child uint64)
	ExtentSet(ino, off, length, mfOff uint64)
}

// compactionAttempts is the number of times that compactJournal tries to
// write a snapshot whose region overflows because the filesystem grew during
// the compaction.
const compactionAttempts = 3

// compactJournal writes a snapshot of fs to the journal.
func (fs *filesystem) compactJournal() error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	j := fs.journal.Load()
	// Compute the size of the snapshot first, so that the journal can
	// make its region large enough. Files can grow between the two passes,
	// and records are appended during the compaction; the journal leaves
	// room for both, and the size doubles on each retry.
	var sizer journal.SnapshotSizer
	fs.snapshotLocked(&sizer)
	size := sizer.Size()
	var err error
	for attempt := 0; attempt < compactionAttempts; attempt++ {
		var s *journal.Snapshot
		s, err = j.BeginSnapshot(fs.root.inode.ino, fs.nextInoMinusOne.Load()+1, size)
		if err != nil {
			return err
		}
		fs.snapshotLocked(s)
		if err = s.Commit(); !errors.Is(err, journal.ErrSnapshotOverflow) {
			return err
		}
		log.Infof("tmpfs: journal snapshot overflowed its region; retrying: %v", err)
		size *= 2
	}
	return err
}

// snapshotLocked writes snapshot records for all inodes in fs to s.
//
// Preconditions: filesystem.mu must be locked.
func (fs *filesystem) snapshotLocked(s snapshotWriter) {
	visited := make(map[*inode]struct{})
	fs.root.inode.snapshot(s)
	visited[fs.root.inode] = struct{}{}
	fs.root.snapshotChildrenLocked(s, visited)
}

// snapshotChildrenLocked writes snapshot records for the children of d,
// recursively.
//
// Preconditions: filesystem.mu must be locked.
func (d *dentry) snapshotChildrenLocked(s snapshotWriter, visited map[*inode]struct{}) {
	dir, ok := d.inode.impl.(*directory)
	if !ok {
		return
	}
	for name, child := range dir.childMap {
		if _, ok := visited[child.inode]; !ok {
			visited[child.inode] = struct{}{}
			child.inode.snapshot(s)
			child.snapshotChildrenLocked(s, visited)
		}
		s.DirentAdd(d.inode.ino, name, child.inode.ino)
	}
}

// snapshot writes the snapshot records of i.
func (i *inode) snapshot(s snapshotWriter) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var r journal.InodeRecord
	i.fillJournalRecord(&r)
	rf, ok := i.impl.(*regularFile)
	if !ok {
		s.Inode(&r)
		return
	}
	rf.dataMu.RLock()
	defer rf.dataMu.RUnlock()
	s.Inode(&r)
	for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		s.ExtentSet(i.ino, seg.Start(), seg.Range().Length(), seg.Value())
	}
}

// fillJournalRecord sets r to the state of i.
//
// +checklocks:i.mu
func (i *inode) fillJournalRecord(r *journal.InodeRecord) {
	*r = journal.InodeRecord{
		Ino:   i.ino,
		Mode:  i.mode.Load(),
		UID:   i.uid.Load(),
		GID:   i.gid.Load(),
		Atime: i.atime.Load(),
		Mtime: i.mtime.Load(),
		Ctime: i.ctime.Load(),
		Btime: i.btime.Load(),
	}
	switch impl := i.impl.(type) {
	case *regularFile:
		r.Size = impl.size.Load()
	case *symlink:
		r.Target = impl.target
	case *deviceFile:
		r.RdevMajor = impl.major
		r.RdevMinor = impl.minor
	}
	if xattrs := i.xattrs.RawXattrs(); len(xattrs) != 0 {
		r.Xattrs = make([]journal.Xattr, 0, len(xattrs)+2)
		for name, value := range xattrs {
			r.Xattrs = append(r.Xattrs, journal.Xattr{Name: name, Value: value})
		}
		sort.Slice(r.Xattrs, func(a, b int) bool { return r.Xattrs[a].Name < r.Xattrs[b].Name })
	}
	// ACLs are stored outside i.xattrs. Record them in their xattr
	// representation; KUIDs and KGIDs are not mapped.
	if acl := i.accessACL.Load(); acl != nil {
		r.Xattrs = append(r.Xattrs, journal.Xattr{Name: linux.XATTR_NAME_POSIX_ACL_ACCESS, Value: string(acl.Serialize(auth.NewRootUserNamespace()))})
	}
	if acl := i.defaultACL.Load(); acl != nil {
		r.Xattrs = append(r.Xattrs, journal.Xattr{Name: linux.XATTR_NAME_POSIX_ACL_DEFAULT, Value: string(acl.Serialize(auth.NewRootUserNamespace()))})
	}
}

// rebuildFromJournal creates the files in st in fs. The MemoryFile of fs
// must already have adopted st.UsedRanges().
//
// Preconditions:
//   - fs.root is an empty directory.
//   - st is not empty.
func (fs *filesystem) rebuildFromJournal(ctx context.Context, st *journal.State) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	rootState := st.Inodes[st.Root]
	if rootState == nil || linux.FileMode(rootState.Mode).FileType() != linux.ModeDirectory {
		return fmt.Errorf("journal root %d is not a directory", st.Root)
	}
	root := fs.root.inode
	root.ino = st.Root
	if err := root.setFromJournal(rootState); err != nil {
		return err
	}
	inodes := map[uint64]*inode{st.Root: root}
	if err := fs.rebuildChildrenLocked(st, rootState, root.impl.(*directory), inodes); err != nil {
		return err
	}
	fs.nextInoMinusOne.Store(st.NextIno - 1)
	return nil
}

// rebuildChildrenLocked creates the children of dir from their state in st,
// recursively.
//
// Preconditions: filesystem.mu must be locked for writing.
func (fs *filesystem) rebuildChildrenLocked(st *journal.State, dirState *journal.Inode, dir *directory, inodes map[uint64]*inode) error {
	// Sort names so that rebuilding is deterministic.
	names := make([]string, 0, len(dirState.Children))
	for name := range dirState.Children {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		childIno := dirState.Children[name]
		childState := st.Inodes[childIno]
		if child, ok := inodes[childIno]; ok {
			// Another hard link to a non-directory.
			dir.insertChildLocked(fs.newDentry(child), name)
			continue
		}
		child, err := fs.newInodeFromJournal(childState)
		if err != nil {
			return fmt.Errorf("inode %d: %w", childIno, err)
		}
		inodes[childIno] = child
		if childDir, ok := child.impl.(*directory); ok {
			dir.inode.incRef() // child directory holds a reference to parent
			dir.insertChildLocked(&childDir.dentry, name)
			if err := fs.rebuildChildrenLocked(st, childState, childDir, inodes); err != nil {
				return err
			}
			continue
		}
		dir.insertChildLocked(fs.newDentry(child), name)
	}
	return nil
}

// newInodeFromJournal creates an inode from its state in a journal.
//
// Preconditions: filesystem.mu must be locked for writing.
func (fs *filesystem) newInodeFromJournal(st *journal.Inode) (*inode, error) {
	mode := linux.FileMode(st.Mode)
	kuid, kgid := auth.KUID(st.UID), auth.KGID(st.GID)
	var (
		i   *inode
		err error
	)
	switch mode.FileType() {
	case linux.ModeRegular:
		i, err = fs.newRegularFile(kuid, kgid, mode, nil /* parentDir */)
	case linux.ModeDirectory:
		var dir *directory
		dir, err = fs.newDirectory(kuid, kgid, mode, nil /* parentDir */)
		if err == nil {
			i = &dir.inode
		}
	case linux.ModeSymlink:
		// Mirror the page accounting of SymlinkAt; see symlinkFromTar.
		if len(st.Target) >= shortSymlinkLen && !fs.accountPages(1) {
			return nil, fmt.Errorf("no space for symlink target")
		}
		i, err = fs.newSymlink(kuid, kgid, mode, st.Target, nil /* parentDir */)
	case linux.ModeNamedPipe:
		i, err = fs.newNamedPipe(kuid, kgid, mode, nil /* parentDir */)
	case linux.ModeSocket:
		// The bound endpoint does not survive the sentry.
		i, err = fs.newSocketFile(kuid, kgid, mode, nil /* ep */, nil /* parentDir */)
	case linux.ModeCharacterDevice, linux.ModeBlockDevice:
		i, err = fs.newDeviceFileFromJournal(kuid, kgid, mode, st.RdevMajor, st.RdevMinor)
	default:
		return nil, fmt.Errorf("unsupported file type %#o", mode.FileType())
	}
	if err != nil {
		return nil, err
	}
	i.ino = st.Ino
	if err := i.setFromJournal(st); err != nil {
		return nil, err
	}
	return i, nil
}

// newDeviceFileFromJournal creates a device file. Unlike newDeviceFileLocked,
// it never returns the shared overlay whiteout. The first whiteout that it
// creates becomes the shared whiteout.
//
// Preconditions: filesystem.mu must be locked for writing.
func (fs *filesystem) newDeviceFileFromJournal(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, major, minor uint32) (*inode, error) {
	file := &deviceFile{
		major: major,
		minor: minor,
		kind:  vfs.CharDevice,
	}
	if mode.FileType() == linux.ModeBlockDevice {
		file.kind = vfs.BlockDevice
	}
	if err := file.inode.init(file, fs, kuid, kgid, mode, nil /* parentDir */); err != nil {
		return nil, err
	}
	if fs.ovlWhiteout == nil && isOvlWhiteoutDev(mode, major, minor) {
		fs.ovlWhiteout = file
	}
	return &file.inode, nil
}

// setFromJournal sets the attributes, extended attributes, link count and
// regular file data of i from st.
func (i *inode) setFromJournal(st *journal.Inode) error {
	i.mode.Store(st.Mode)
	i.uid.Store(st.UID)
	i.gid.Store(st.GID)
	i.atime.Store(st.Atime)
	i.mtime.Store(st.Mtime)
	i.ctime.Store(st.Ctime)
	i.btime.Store(st.Btime)
	nlink := st.Nlink
	if dev, ok := i.impl.(*deviceFile); ok && i.fs.ovlWhiteout == dev {
		// The filesystem holds an extra link on the shared whiteout.
		nlink++
	}
	i.nlink = atomicbitops.FromUint32(nlink)

	var xattrs map[string]string
	for _, x := range st.Xattrs {
		switch x.Name {
		case linux.XATTR_NAME_POSIX_ACL_ACCESS, linux.XATTR_NAME_POSIX_ACL_DEFAULT:
			acl, err := vfs.ParsePosixACL([]byte(x.Value), auth.NewRootUserNamespace())
			if err != nil {
				return fmt.Errorf("invalid ACL %q: %w", x.Name, err)
			}
			if x.Name == linux.XATTR_NAME_POSIX_ACL_ACCESS {
				i.accessACL.Store(acl)
			} else {
				i.defaultACL.Store(acl)
			}
		default:
			if strings.HasPrefix(x.Name, linux.XATTR_SYSTEM_PREFIX) {
				return fmt.Errorf("unsupported xattr %q", x.Name)
			}
			if xattrs == nil {
				xattrs = make(map[string]string, len(st.Xattrs))
			}
			xattrs[x.Name] = x.Value
		}
	}
	if xattrs != nil {
		i.xattrs.SetRawXattrs(xattrs)
	}

	rf, ok := i.impl.(*regularFile)
	if !ok {
		return nil
	}
	var pages uint64
	for _, e := range st.Extents {
		pages += e.Len >> hostarch.PageShift
	}
	if !i.fs.accountPages(pages) {
		return fmt.Errorf("file would exceed the filesystem size limit of %d pages", i.fs.maxSizeInPages)
	}
	rf.dataMu.Lock()
	defer rf.dataMu.Unlock()
	rf.size.Store(st.Size)
	gap := rf.data.FirstGap()
	for _, e := range st.Extents {
		gap = rf.data.Insert(gap, memmap.MappableRange{Start: e.Off, End: e.Off + e.Len}, e.MFOff).NextGap()
	}
	return nil
}
