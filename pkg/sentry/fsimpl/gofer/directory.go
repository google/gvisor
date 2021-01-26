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
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (d *dentry) isDir() bool {
	return d.fileType() == linux.S_IFDIR
}

// Preconditions:
// * filesystem.renameMu must be locked.
// * d.dirMu must be locked.
// * d.isDir().
// * child must be a newly-created dentry that has never had a parent.
func (d *dentry) cacheNewChildLocked(child *dentry, name string) {
	d.IncRef() // reference held by child on its parent
	child.parent = d
	child.name = name
	if d.children == nil {
		d.children = make(map[string]*dentry)
	}
	d.children[name] = child
}

// Preconditions:
// * d.dirMu must be locked.
// * d.isDir().
func (d *dentry) cacheNegativeLookupLocked(name string) {
	// Don't cache negative lookups if InteropModeShared is in effect (since
	// this makes remote lookup unavoidable), or if d.isSynthetic() (in which
	// case the only files in the directory are those for which a dentry exists
	// in d.children). Instead, just delete any previously-cached dentry.
	if d.fs.opts.interop == InteropModeShared || d.isSynthetic() {
		delete(d.children, name)
		return
	}
	if d.children == nil {
		d.children = make(map[string]*dentry)
	}
	d.children[name] = nil
}

type createSyntheticOpts struct {
	name string
	mode linux.FileMode
	kuid auth.KUID
	kgid auth.KGID

	// The endpoint for a synthetic socket. endpoint should be nil if the file
	// being created is not a socket.
	endpoint transport.BoundEndpoint

	// pipe should be nil if the file being created is not a pipe.
	pipe *pipe.VFSPipe
}

// createSyntheticChildLocked creates a synthetic file with the given name
// in d.
//
// Preconditions:
// * d.dirMu must be locked.
// * d.isDir().
// * d does not already contain a child with the given name.
func (d *dentry) createSyntheticChildLocked(opts *createSyntheticOpts) {
	now := d.fs.clock.Now().Nanoseconds()
	child := &dentry{
		refs:      1, // held by d
		fs:        d.fs,
		ino:       d.fs.nextIno(),
		mode:      uint32(opts.mode),
		uid:       uint32(opts.kuid),
		gid:       uint32(opts.kgid),
		blockSize: usermem.PageSize, // arbitrary
		atime:     now,
		mtime:     now,
		ctime:     now,
		btime:     now,
		readFD:    -1,
		writeFD:   -1,
		mmapFD:    -1,
		nlink:     uint32(2),
	}
	refsvfs2.Register(child)
	switch opts.mode.FileType() {
	case linux.S_IFDIR:
		// Nothing else needs to be done.
	case linux.S_IFSOCK:
		child.endpoint = opts.endpoint
	case linux.S_IFIFO:
		child.pipe = opts.pipe
	default:
		panic(fmt.Sprintf("failed to create synthetic file of unrecognized type: %v", opts.mode.FileType()))
	}
	child.pf.dentry = child
	child.vfsd.Init(child)

	d.cacheNewChildLocked(child, opts.name)
	d.syntheticChildren++
}

// +stateify savable
type directoryFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	mu      sync.Mutex `state:"nosave"`
	off     int64
	dirents []vfs.Dirent
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *directoryFD) Release(context.Context) {
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

	d.InotifyWithParent(ctx, linux.IN_ACCESS, 0, vfs.PathEvent)
	if d.cachedMetadataAuthoritative() {
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

// Preconditions:
// * d.isDir().
// * There exists at least one directoryFD representing d.
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
	defer d.fs.renameMu.RUnlock()
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	if d.dirents != nil {
		return d.dirents, nil
	}

	// It's not clear if 9P2000.L's readdir is expected to return "." and "..",
	// so we generate them here.
	parent := genericParentOrSelf(d)
	dirents := []vfs.Dirent{
		{
			Name:    ".",
			Type:    linux.DT_DIR,
			Ino:     uint64(d.ino),
			NextOff: 1,
		},
		{
			Name:    "..",
			Type:    uint8(atomic.LoadUint32(&parent.mode) >> 12),
			Ino:     uint64(parent.ino),
			NextOff: 2,
		},
	}
	var realChildren map[string]struct{}
	if !d.isSynthetic() {
		if d.syntheticChildren != 0 && d.fs.opts.interop == InteropModeShared {
			// Record the set of children d actually has so that we don't emit
			// duplicate entries for synthetic children.
			realChildren = make(map[string]struct{})
		}
		off := uint64(0)
		const count = 64 * 1024 // for consistency with the vfs1 client
		d.handleMu.RLock()
		if d.readFile.isNil() {
			// This should not be possible because a readable handle should
			// have been opened when the calling directoryFD was opened.
			d.handleMu.RUnlock()
			panic("gofer.dentry.getDirents called without a readable handle")
		}
		for {
			p9ds, err := d.readFile.readdir(ctx, off, count)
			if err != nil {
				d.handleMu.RUnlock()
				return nil, err
			}
			if len(p9ds) == 0 {
				d.handleMu.RUnlock()
				break
			}
			for _, p9d := range p9ds {
				if p9d.Name == "." || p9d.Name == ".." {
					continue
				}
				dirent := vfs.Dirent{
					Name:    p9d.Name,
					Ino:     d.fs.inoFromQIDPath(p9d.QID.Path),
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
				if realChildren != nil {
					realChildren[p9d.Name] = struct{}{}
				}
			}
			off = p9ds[len(p9ds)-1].Offset
		}
	}
	// Emit entries for synthetic children.
	if d.syntheticChildren != 0 {
		for _, child := range d.children {
			if child == nil || !child.isSynthetic() {
				continue
			}
			if _, ok := realChildren[child.name]; ok {
				continue
			}
			dirents = append(dirents, vfs.Dirent{
				Name:    child.name,
				Type:    uint8(atomic.LoadUint32(&child.mode) >> 12),
				Ino:     uint64(child.ino),
				NextOff: int64(len(dirents) + 1),
			})
		}
	}
	// Cache dirents for future directoryFDs if permitted.
	if d.cachedMetadataAuthoritative() {
		d.dirents = dirents
	}
	return dirents, nil
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

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *directoryFD) Sync(ctx context.Context) error {
	return fd.dentry().syncRemoteFile(ctx)
}
