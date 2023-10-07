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
	"sort"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (i *inode) getDirents() ([]vfs.Dirent, error) {
	// Fast path.
	i.dirMu.RLock()
	dirents := i.dirents
	i.dirMu.RUnlock()
	if dirents != nil {
		return dirents, nil
	}

	// Slow path.
	i.dirMu.Lock()
	defer i.dirMu.Unlock()

	off := int64(1)
	if err := i.IterDirents(func(name string, typ uint8, nid uint64) error {
		dirents = append(dirents, vfs.Dirent{
			Name:    name,
			Type:    linux.FileTypeToDirentType(typ),
			Ino:     nid,
			NextOff: off,
		})
		off++
		return nil
	}); err != nil {
		return nil, err
	}

	// "." and ".." should always be present.
	if len(dirents) < 2 {
		return nil, linuxerr.EUCLEAN
	}

	i.dirents = dirents
	return dirents, nil
}

func (i *inode) lookup(name string) (uint64, error) {
	// TODO: For simplicity, currently a lookup will cause all dirents to be
	// read and cached. But it hurts the performance of large directories.
	// We should do binary search on disk data directly (like Linux does).
	dirents, err := i.getDirents()
	if err != nil {
		return 0, err
	}

	// The dirents are sorted in alphabetical order. We do binary search
	// to find the target.
	idx := sort.Search(len(dirents), func(i int) bool {
		return dirents[i].Name >= name
	})
	if idx >= len(dirents) || dirents[idx].Name != name {
		return 0, linuxerr.ENOENT
	}
	return dirents[idx].Ino, nil
}

func (d *dentry) lookup(ctx context.Context, name string) (*dentry, error) {
	// Fast path, dentry already exists.
	d.dirMu.RLock()
	child, ok := d.childMap[name]
	d.dirMu.RUnlock()
	if ok {
		return child, nil
	}

	// Slow path, create a new dentry.
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	if child, ok := d.childMap[name]; ok {
		return child, nil
	}

	nid, err := d.inode.lookup(name)
	if err != nil {
		return nil, err
	}

	if d.childMap == nil {
		d.childMap = make(map[string]*dentry)
	}

	child, err = d.inode.fs.newDentry(nid)
	if err != nil {
		return nil, err
	}
	child.parent.Store(d)
	child.name = name
	d.childMap[name] = child
	return child, nil
}

// +stateify savable
type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	// mu protects off.
	mu sync.Mutex `state:"nosave"`
	// +checklocks:mu
	off int64
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	d := fd.dentry()
	dirents, err := d.inode.getDirents()
	if err != nil {
		return err
	}

	d.InotifyWithParent(ctx, linux.IN_ACCESS, 0, vfs.PathEvent)

	fd.mu.Lock()
	defer fd.mu.Unlock()

	for fd.off < int64(len(dirents)) {
		if err := cb.Handle(dirents[fd.off]); err != nil {
			return err
		}
		fd.off++
	}
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *directoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		// use offset as specified
	case linux.SEEK_CUR:
		offset += fd.off
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = offset
	return offset, nil
}
