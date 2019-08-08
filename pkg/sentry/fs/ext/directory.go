// Copyright 2019 The gVisor Authors.
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

package ext

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// directory represents a directory inode. It holds the childList in memory.
type directory struct {
	inode inode

	// mu serializes the changes to childList.
	// Lock Order (outermost locks must be taken first):
	//   directory.mu
	//     filesystem.mu
	mu sync.Mutex

	// childList is a list containing (1) child dirents and (2) fake dirents
	// (with diskDirent == nil) that represent the iteration position of
	// directoryFDs. childList is used to support directoryFD.IterDirents()
	// efficiently. childList is protected by mu.
	childList direntList

	// childMap maps the child's filename to the dirent structure stored in
	// childList. This adds some data replication but helps in faster path
	// traversal. For consistency, key == childMap[key].diskDirent.FileName().
	// Immutable.
	childMap map[string]*dirent
}

// newDirectroy is the directory constructor.
func newDirectroy(inode inode, newDirent bool) (*directory, error) {
	file := &directory{inode: inode, childMap: make(map[string]*dirent)}
	file.inode.impl = file

	// Initialize childList by reading dirents from the underlying file.
	if inode.diskInode.Flags().Index {
		// TODO(b/134676337): Support hash tree directories. Currently only the '.'
		// and '..' entries are read in.

		// Users cannot navigate this hash tree directory yet.
		log.Warningf("hash tree directory being used which is unsupported")
		return file, nil
	}

	// The dirents are organized in a linear array in the file data.
	// Extract the file data and decode the dirents.
	regFile, err := newRegularFile(inode)
	if err != nil {
		return nil, err
	}

	// buf is used as scratch space for reading in dirents from disk and
	// unmarshalling them into dirent structs.
	buf := make([]byte, disklayout.DirentSize)
	size := inode.diskInode.Size()
	for off, inc := uint64(0), uint64(0); off < size; off += inc {
		toRead := size - off
		if toRead > disklayout.DirentSize {
			toRead = disklayout.DirentSize
		}
		if n, err := regFile.impl.ReadAt(buf[:toRead], int64(off)); uint64(n) < toRead {
			return nil, err
		}

		var curDirent dirent
		if newDirent {
			curDirent.diskDirent = &disklayout.DirentNew{}
		} else {
			curDirent.diskDirent = &disklayout.DirentOld{}
		}
		binary.Unmarshal(buf, binary.LittleEndian, curDirent.diskDirent)

		if curDirent.diskDirent.Inode() != 0 && len(curDirent.diskDirent.FileName()) != 0 {
			// Inode number and name length fields being set to 0 is used to indicate
			// an unused dirent.
			file.childList.PushBack(&curDirent)
			file.childMap[curDirent.diskDirent.FileName()] = &curDirent
		}

		// The next dirent is placed exactly after this dirent record on disk.
		inc = uint64(curDirent.diskDirent.RecordSize())
	}

	return file, nil
}

func (i *inode) isDir() bool {
	_, ok := i.impl.(*directory)
	return ok
}

// dirent is the directory.childList node.
type dirent struct {
	diskDirent disklayout.Dirent

	// direntEntry links dirents into their parent directory.childList.
	direntEntry
}

// directoryFD represents a directory file description. It implements
// vfs.FileDescriptionImpl.
type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	// Protected by directory.mu.
	iter *dirent
	off  int64
}

// Compiles only if directoryFD implements vfs.FileDescriptionImpl.
var _ vfs.FileDescriptionImpl = (*directoryFD)(nil)

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release() {
	if fd.iter == nil {
		return
	}

	dir := fd.inode().impl.(*directory)
	dir.mu.Lock()
	dir.childList.Remove(fd.iter)
	dir.mu.Unlock()
	fd.iter = nil
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	extfs := fd.filesystem()
	dir := fd.inode().impl.(*directory)

	dir.mu.Lock()
	defer dir.mu.Unlock()

	// Ensure that fd.iter exists and is not linked into dir.childList.
	var child *dirent
	if fd.iter == nil {
		// Start iteration at the beginning of dir.
		child = dir.childList.Front()
		fd.iter = &dirent{}
	} else {
		// Continue iteration from where we left off.
		child = fd.iter.Next()
		dir.childList.Remove(fd.iter)
	}
	for ; child != nil; child = child.Next() {
		// Skip other directoryFD iterators.
		if child.diskDirent != nil {
			childType, ok := child.diskDirent.FileType()
			if !ok {
				// We will need to read the inode off disk. Do not increment
				// ref count here because this inode is not being added to the
				// dentry tree.
				extfs.mu.Lock()
				childInode, err := extfs.getOrCreateInodeLocked(child.diskDirent.Inode())
				extfs.mu.Unlock()
				if err != nil {
					// Usage of the file description after the error is
					// undefined. This implementation would continue reading
					// from the next dirent.
					fd.off++
					dir.childList.InsertAfter(child, fd.iter)
					return err
				}
				childType = fs.ToInodeType(childInode.diskInode.Mode().FileType())
			}

			if !cb.Handle(vfs.Dirent{
				Name: child.diskDirent.FileName(),
				Type: fs.ToDirentType(childType),
				Ino:  uint64(child.diskDirent.Inode()),
				Off:  fd.off,
			}) {
				dir.childList.InsertBefore(child, fd.iter)
				return nil
			}
			fd.off++
		}
	}
	dir.childList.PushBack(fd.iter)
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *directoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if whence != linux.SEEK_SET && whence != linux.SEEK_CUR {
		return 0, syserror.EINVAL
	}

	dir := fd.inode().impl.(*directory)

	dir.mu.Lock()
	defer dir.mu.Unlock()

	// Find resulting offset.
	if whence == linux.SEEK_CUR {
		offset += fd.off
	}

	if offset < 0 {
		// lseek(2) specifies that EINVAL should be returned if the resulting offset
		// is negative.
		return 0, syserror.EINVAL
	}

	n := int64(len(dir.childMap))
	realWantOff := offset
	if realWantOff > n {
		realWantOff = n
	}
	realCurOff := fd.off
	if realCurOff > n {
		realCurOff = n
	}

	// Ensure that fd.iter exists and is linked into dir.childList so we can
	// intelligently seek from the optimal position.
	if fd.iter == nil {
		fd.iter = &dirent{}
		dir.childList.PushFront(fd.iter)
	}

	// Guess that iterating from the current position is optimal.
	child := fd.iter
	diff := realWantOff - realCurOff // Shows direction and magnitude of travel.

	// See if starting from the beginning or end is better.
	abDiff := diff
	if diff < 0 {
		abDiff = -diff
	}
	if abDiff > realWantOff {
		// Starting from the beginning is best.
		child = dir.childList.Front()
		diff = realWantOff
	} else if abDiff > (n - realWantOff) {
		// Starting from the end is best.
		child = dir.childList.Back()
		// (n - 1) because the last non-nil dirent represents the (n-1)th offset.
		diff = realWantOff - (n - 1)
	}

	for child != nil {
		// Skip other directoryFD iterators.
		if child.diskDirent != nil {
			if diff == 0 {
				if child != fd.iter {
					dir.childList.Remove(fd.iter)
					dir.childList.InsertBefore(child, fd.iter)
				}

				fd.off = offset
				return offset, nil
			}

			if diff < 0 {
				diff++
				child = child.Prev()
			} else {
				diff--
				child = child.Next()
			}
			continue
		}

		if diff < 0 {
			child = child.Prev()
		} else {
			child = child.Next()
		}
	}

	// Reaching here indicates that the offset is beyond the end of the childList.
	dir.childList.Remove(fd.iter)
	dir.childList.PushBack(fd.iter)
	fd.off = offset
	return offset, nil
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) ConfigureMMap(ctx context.Context, opts memmap.MMapOpts) error {
	// mmap(2) specifies that EACCESS should be returned for non-regular file fds.
	return syserror.EACCES
}
