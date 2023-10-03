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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

func (d *dentry) isDir() bool {
	return d.fileType() == linux.S_IFDIR
}

// cacheNewChildLocked will cache the new child dentry, and will panic if a
// non-negative child is already cached. It is the caller's responsibility to
// check that the child does not exist before calling this method.
//
// Preconditions:
//   - filesystem.renameMu must be locked.
//   - If the addition to the dentry tree is due to a read-only operation (like
//     Walk), then d.opMu must be held for reading. Otherwise d.opMu must be
//     held for writing.
//   - d.childrenMu must be locked.
//   - d.isDir().
//   - child must be a newly-created dentry that has never had a parent.
//   - d.children[name] must be unset or nil (a "negative child")
//
// +checklocksread:d.opMu
// +checklocks:d.childrenMu
func (d *dentry) cacheNewChildLocked(child *dentry, name string) {
	d.IncRef() // reference held by child on its parent
	child.parent.Store(d)
	child.name = name
	if d.children == nil {
		d.children = make(map[string]*dentry)
	} else if c, ok := d.children[name]; ok {
		if c != nil {
			panic(fmt.Sprintf("cacheNewChildLocked collision; child with name=%q already cached", name))
		}

		// Cached child is negative. OK to cache over, but we must
		// update the count of negative children.
		d.negativeChildren--
	}
	d.children[name] = child
}

// Preconditions:
//   - d.childrenMu must be locked.
//   - d.isDir().
//   - name is not already a negative entry.
//
// +checklocks:d.childrenMu
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
	d.negativeChildren++

	if !d.negativeChildrenCache.isInited() {
		// Initializing cache with all negative children name at the first time
		// that negativeChildren increase upto max.
		if d.negativeChildren >= maxCachedNegativeChildren {
			d.negativeChildrenCache.init(maxCachedNegativeChildren)
			for childName, child := range d.children {
				if child == nil {
					d.negativeChildrenCache.add(childName)
				}
			}
		}
	} else if victim := d.negativeChildrenCache.add(name); victim != "" {
		// If victim is a negative entry in d.children, delete it.
		if child, ok := d.children[victim]; ok && child == nil {
			delete(d.children, victim)
			d.negativeChildren--
		}
	}
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

// newSyntheticDentry creates a synthetic file with the given name.
func (fs *filesystem) newSyntheticDentry(opts *createSyntheticOpts) *dentry {
	now := fs.clock.Now().Nanoseconds()
	child := &dentry{
		refs:      atomicbitops.FromInt64(1), // held by parent.
		fs:        fs,
		ino:       fs.nextIno(),
		mode:      atomicbitops.FromUint32(uint32(opts.mode)),
		uid:       atomicbitops.FromUint32(uint32(opts.kuid)),
		gid:       atomicbitops.FromUint32(uint32(opts.kgid)),
		blockSize: atomicbitops.FromUint32(hostarch.PageSize), // arbitrary
		atime:     atomicbitops.FromInt64(now),
		mtime:     atomicbitops.FromInt64(now),
		ctime:     atomicbitops.FromInt64(now),
		btime:     atomicbitops.FromInt64(now),
		readFD:    atomicbitops.FromInt32(-1),
		writeFD:   atomicbitops.FromInt32(-1),
		mmapFD:    atomicbitops.FromInt32(-1),
		nlink:     atomicbitops.FromUint32(2),
	}
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
	child.init(nil /* impl */)
	return child
}

// Preconditions:
//   - d.childrenMu must be locked.
//
// +checklocks:d.childrenMu
func (d *dentry) clearDirentsLocked() {
	d.dirents = nil
	d.childrenSet = nil
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
//   - d.isDir().
//   - There exists at least one directoryFD representing d.
func (d *dentry) getDirents(ctx context.Context) ([]vfs.Dirent, error) {
	// NOTE(b/135560623): 9P2000.L's readdir does not specify behavior in the
	// presence of concurrent mutation of an iterated directory, so
	// implementations may duplicate or omit entries in this case, which
	// violates POSIX semantics. Thus we read all directory entries while
	// holding d.opMu to exclude directory mutations. (Note that it is
	// impossible for the client to exclude concurrent mutation from other
	// remote filesystem users. Since there is no way to detect if the server
	// has incorrectly omitted directory entries, we simply assume that the
	// server is well-behaved under InteropModeShared.) This is inconsistent
	// with Linux (which appears to assume that directory fids have the correct
	// semantics, and translates struct file_operations::readdir calls directly
	// to readdir RPCs), but is consistent with VFS1.

	// filesystem.renameMu is needed for d.parent, and must be locked before
	// d.opMu.
	d.fs.renameMu.RLock()
	defer d.fs.renameMu.RUnlock()
	d.opMu.RLock()
	defer d.opMu.RUnlock()

	// d.childrenMu must be locked after d.opMu and held for the entire
	// function. This synchronizes concurrent getDirents() attempts.
	// getdents(2) advances the file offset. To get complete results from
	// multiple getdents(2) calls, the directory FD's offset needs to be
	// protected.
	d.childrenMu.Lock()
	defer d.childrenMu.Unlock()

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
			Type:    uint8(parent.mode.Load() >> 12),
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
		d.handleMu.RLock()
		if !d.isReadHandleOk() {
			// This should not be possible because a readable handle should
			// have been opened when the calling directoryFD was opened.
			panic("gofer.dentry.getDirents called without a readable handle")
		}
		err := d.getDirentsLocked(ctx, func(name string, key inoKey, dType uint8) {
			dirent := vfs.Dirent{
				Name:    name,
				Ino:     d.fs.inoFromKey(key),
				NextOff: int64(len(dirents) + 1),
				Type:    dType,
			}
			dirents = append(dirents, dirent)
			if realChildren != nil {
				realChildren[name] = struct{}{}
			}
		})
		d.handleMu.RUnlock()
		if err != nil {
			return nil, err
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
				Type:    uint8(child.mode.Load() >> 12),
				Ino:     uint64(child.ino),
				NextOff: int64(len(dirents) + 1),
			})
		}
	}
	// Cache dirents for future directoryFDs if permitted.
	if d.cachedMetadataAuthoritative() {
		d.dirents = dirents
		d.childrenSet = make(map[string]struct{}, len(dirents))
		for _, dirent := range d.dirents {
			d.childrenSet[dirent.Name] = struct{}{}
		}
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
			return 0, linuxerr.EINVAL
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
			return 0, linuxerr.EINVAL
		}
		// Don't clear fd.dirents in this case, even if offset == 0.
		fd.off = offset
		return fd.off, nil
	default:
		return 0, linuxerr.EINVAL
	}
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *directoryFD) Sync(ctx context.Context) error {
	return fd.dentry().syncRemoteFile(ctx)
}
