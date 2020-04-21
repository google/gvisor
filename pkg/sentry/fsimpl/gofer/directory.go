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

package gofer

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

func (d *dentry) isDir() bool {
	return d.fileType() == linux.S_IFDIR
}

// Preconditions: filesystem.renameMu must be locked. d.dirMu must be locked.
// d.isDir(). child must be a newly-created dentry that has never had a parent.
func (d *dentry) cacheNewChildLocked(child *dentry, name string) {
	d.IncRef() // reference held by child on its parent
	child.parent = d
	child.name = name
	if d.children == nil {
		d.children = make(map[string]*dentry)
	}
	d.children[name] = child
}

// Preconditions: d.dirMu must be locked. d.isDir(). fs.opts.interop !=
// InteropModeShared.
func (d *dentry) cacheNegativeChildLocked(name string) {
	if d.children == nil {
		d.children = make(map[string]*dentry)
	}
	d.children[name] = nil
}

type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	mu      sync.Mutex
	off     int64
	dirents []vfs.Dirent
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release() {
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *directoryFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	d := fd.dentry()
	if fd.dirents == nil {
		ds, err := d.getDirents(ctx)
		if err != nil {
			return err
		}
		fd.dirents = ds
	}

	if d.fs.opts.interop != InteropModeShared {
		d.touchAtime(fd.vfsfd.Mount())
	}

	for fd.off < int64(len(fd.dirents)) {
		if err := cb.Handle(fd.dirents[fd.off]); err != nil {
			return err
		}
		fd.off++
	}
	return nil
}

// Preconditions: d.isDir(). There exists at least one directoryFD representing d.
func (d *dentry) getDirents(ctx context.Context) ([]vfs.Dirent, error) {
	// NOTE(b/135560623): 9P2000.L's readdir does not specify behavior in the
	// presence of concurrent mutation of an iterated directory, so
	// implementations may duplicate or omit entries in this case, which
	// violates POSIX semantics. Thus we read all directory entries while
	// holding d.dirMu to exclude directory mutations. (Note that it is
	// impossible for the client to exclude concurrent mutation from other
	// remote filesystem users. Since there is no way to detect if the server
	// has incorrectly omitted directory entries, we simply assume that the
	// server is well-behaved under InteropModeShared.) This is inconsistent
	// with Linux (which appears to assume that directory fids have the correct
	// semantics, and translates struct file_operations::readdir calls directly
	// to readdir RPCs), but is consistent with VFS1.

	// filesystem.renameMu is needed for d.parent, and must be locked before
	// dentry.dirMu.
	d.fs.renameMu.RLock()
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	if d.dirents != nil {
		d.fs.renameMu.RUnlock()
		return d.dirents, nil
	}

	// It's not clear if 9P2000.L's readdir is expected to return "." and "..",
	// so we generate them here.
	parent := genericParentOrSelf(d)
	dirents := []vfs.Dirent{
		{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     d.ino,
			NextOff: 1,
		},
		{
			Name:    "..",
			Type:    uint8(atomic.LoadUint32(&parent.mode) >> 12),
			Ino:     parent.ino,
			NextOff: 2,
		},
	}
	d.fs.renameMu.RUnlock()
	off := uint64(0)
	const count = 64 * 1024 // for consistency with the vfs1 client
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	if !d.handleReadable {
		// This should not be possible because a readable handle should have
		// been opened when the calling directoryFD was opened.
		panic("gofer.dentry.getDirents called without a readable handle")
	}
	for {
		p9ds, err := d.handle.file.readdir(ctx, off, count)
		if err != nil {
			return nil, err
		}
		if len(p9ds) == 0 {
			// Cache dirents for future directoryFDs if permitted.
			if d.fs.opts.interop != InteropModeShared {
				d.dirents = dirents
			}
			return dirents, nil
		}
		for _, p9d := range p9ds {
			if p9d.Name == "." || p9d.Name == ".." {
				continue
			}
			dirent := vfs.Dirent{
				Name:    p9d.Name,
				Ino:     p9d.QID.Path,
				NextOff: int64(len(dirents) + 1),
			}
			// p9 does not expose 9P2000.U's DMDEVICE, DMNAMEDPIPE, or
			// DMSOCKET.
			switch p9d.Type {
			case p9.TypeSymlink:
				dirent.Type = linux.DT_LNK
			case p9.TypeDir:
				dirent.Type = linux.DT_DIR
			default:
				dirent.Type = linux.DT_REG
			}
			dirents = append(dirents, dirent)
		}
		off = p9ds[len(p9ds)-1].Offset
	}
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *directoryFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		if offset < 0 {
			return 0, syserror.EINVAL
		}
		if offset == 0 {
			// Ensure that the next call to fd.IterDirents() calls
			// fd.dentry().getDirents().
			fd.dirents = nil
		}
		fd.off = offset
		return fd.off, nil
	case linux.SEEK_CUR:
		offset += fd.off
		if offset < 0 {
			return 0, syserror.EINVAL
		}
		// Don't clear fd.dirents in this case, even if offset == 0.
		fd.off = offset
		return fd.off, nil
	default:
		return 0, syserror.EINVAL
	}
}
