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
	"errors"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

var (
	// errResolveDirent indicates that the vfs.ResolvingPath.Component() does
	// not exist on the dentry tree but does exist on disk. So it has to be read in
	// using the in-memory dirent and added to the dentry tree. Usually indicates
	// the need to lock filesystem.mu for writing.
	errResolveDirent = errors.New("resolve path component using dirent")
)

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// mu serializes changes to the Dentry tree.
	mu sync.RWMutex

	// dev represents the underlying fs device. It does not require protection
	// because io.ReaderAt permits concurrent read calls to it. It translates to
	// the pread syscall which passes on the read request directly to the device
	// driver. Device drivers are intelligent in serving multiple concurrent read
	// requests in the optimal order (taking locality into consideration).
	dev io.ReaderAt

	// inodeCache maps absolute inode numbers to the corresponding Inode struct.
	// Inodes should be removed from this once their reference count hits 0.
	//
	// Protected by mu because most additions (see IterDirents) and all removals
	// from this corresponds to a change in the dentry tree.
	inodeCache map[uint32]*inode

	// sb represents the filesystem superblock. Immutable after initialization.
	sb disklayout.SuperBlock

	// bgs represents all the block group descriptors for the filesystem.
	// Immutable after initialization.
	bgs []disklayout.BlockGroup
}

// Compiles only if filesystem implements vfs.FilesystemImpl.
var _ vfs.FilesystemImpl = (*filesystem)(nil)

// stepLocked resolves rp.Component() in parent directory vfsd. The write
// parameter passed tells if the caller has acquired filesystem.mu for writing
// or not. If set to true, an existing inode on disk can be added to the dentry
// tree if not present already.
//
// stepLocked is loosely analogous to fs/namei.c:walk_component().
//
// Preconditions:
//     - filesystem.mu must be locked (for writing if write param is true).
//     - !rp.Done().
//     - inode == vfsd.Impl().(*Dentry).inode.
func stepLocked(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, inode *inode, write bool) (*vfs.Dentry, *inode, error) {
	if !inode.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	if err := inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, nil, err
	}

	for {
		nextVFSD, err := rp.ResolveComponent(vfsd)
		if err != nil {
			return nil, nil, err
		}
		if nextVFSD == nil {
			// Since the Dentry tree is not the sole source of truth for extfs, if it's
			// not in the Dentry tree, it might need to be pulled from disk.
			childDirent, ok := inode.impl.(*directory).childMap[rp.Component()]
			if !ok {
				// The underlying inode does not exist on disk.
				return nil, nil, syserror.ENOENT
			}

			if !write {
				// filesystem.mu must be held for writing to add to the dentry tree.
				return nil, nil, errResolveDirent
			}

			// Create and add the component's dirent to the dentry tree.
			fs := rp.Mount().Filesystem().Impl().(*filesystem)
			childInode, err := fs.getOrCreateInodeLocked(childDirent.diskDirent.Inode())
			if err != nil {
				return nil, nil, err
			}
			// incRef because this is being added to the dentry tree.
			childInode.incRef()
			child := newDentry(childInode)
			vfsd.InsertChild(&child.vfsd, rp.Component())

			// Continue as usual now that nextVFSD is not nil.
			nextVFSD = &child.vfsd
		}
		nextInode := nextVFSD.Impl().(*dentry).inode
		if nextInode.isSymlink() && rp.ShouldFollowSymlink() {
			if err := rp.HandleSymlink(inode.impl.(*symlink).target); err != nil {
				return nil, nil, err
			}
			continue
		}
		rp.Advance()
		return nextVFSD, nextInode, nil
	}
}

// walkLocked resolves rp to an existing file. The write parameter
// passed tells if the caller has acquired filesystem.mu for writing or not.
// If set to true, additions can be made to the dentry tree while walking.
// If errResolveDirent is returned, the walk needs to be continued with an
// upgraded filesystem.mu.
//
// walkLocked is loosely analogous to Linux's fs/namei.c:path_lookupat().
//
// Preconditions:
//     - filesystem.mu must be locked (for writing if write param is true).
func walkLocked(rp *vfs.ResolvingPath, write bool) (*vfs.Dentry, *inode, error) {
	vfsd := rp.Start()
	inode := vfsd.Impl().(*dentry).inode
	for !rp.Done() {
		var err error
		vfsd, inode, err = stepLocked(rp, vfsd, inode, write)
		if err != nil {
			return nil, nil, err
		}
	}
	if rp.MustBeDir() && !inode.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	return vfsd, inode, nil
}

// walkParentLocked resolves all but the last path component of rp to an
// existing directory. It does not check that the returned directory is
// searchable by the provider of rp. The write parameter passed tells if the
// caller has acquired filesystem.mu for writing or not. If set to true,
// additions can be made to the dentry tree while walking.
// If errResolveDirent is returned, the walk needs to be continued with an
// upgraded filesystem.mu.
//
// walkParentLocked is loosely analogous to Linux's fs/namei.c:path_parentat().
//
// Preconditions:
//     - filesystem.mu must be locked (for writing if write param is true).
//     - !rp.Done().
func walkParentLocked(rp *vfs.ResolvingPath, write bool) (*vfs.Dentry, *inode, error) {
	vfsd := rp.Start()
	inode := vfsd.Impl().(*dentry).inode
	for !rp.Final() {
		var err error
		vfsd, inode, err = stepLocked(rp, vfsd, inode, write)
		if err != nil {
			return nil, nil, err
		}
	}
	if !inode.isDir() {
		return nil, nil, syserror.ENOTDIR
	}
	return vfsd, inode, nil
}

// walk resolves rp to an existing file. If parent is set to true, it resolves
// the rp till the parent of the last component which should be an existing
// directory. If parent is false then resolves rp entirely. Attemps to resolve
// the path as far as it can with a read lock and upgrades the lock if needed.
func (fs *filesystem) walk(rp *vfs.ResolvingPath, parent bool) (*vfs.Dentry, *inode, error) {
	var (
		vfsd  *vfs.Dentry
		inode *inode
		err   error
	)

	// Try walking with the hopes that all dentries have already been pulled out
	// of disk. This reduces congestion (allows concurrent walks).
	fs.mu.RLock()
	if parent {
		vfsd, inode, err = walkParentLocked(rp, false)
	} else {
		vfsd, inode, err = walkLocked(rp, false)
	}
	fs.mu.RUnlock()

	if err == errResolveDirent {
		// Upgrade lock and continue walking. Lock upgrading in the middle of the
		// walk is fine as this is a read only filesystem.
		fs.mu.Lock()
		if parent {
			vfsd, inode, err = walkParentLocked(rp, true)
		} else {
			vfsd, inode, err = walkLocked(rp, true)
		}
		fs.mu.Unlock()
	}

	return vfsd, inode, err
}

// getOrCreateInodeLocked gets the inode corresponding to the inode number passed in.
// It creates a new one with the given inode number if one does not exist.
// The caller must increment the ref count if adding this to the dentry tree.
//
// Precondition: must be holding fs.mu for writing.
func (fs *filesystem) getOrCreateInodeLocked(inodeNum uint32) (*inode, error) {
	if in, ok := fs.inodeCache[inodeNum]; ok {
		return in, nil
	}

	in, err := newInode(fs, inodeNum)
	if err != nil {
		return nil, err
	}

	fs.inodeCache[inodeNum] = in
	return in, nil
}

// statTo writes the statfs fields to the output parameter.
func (fs *filesystem) statTo(stat *linux.Statfs) {
	stat.Type = uint64(fs.sb.Magic())
	stat.BlockSize = int64(fs.sb.BlockSize())
	stat.Blocks = fs.sb.BlocksCount()
	stat.BlocksFree = fs.sb.FreeBlocksCount()
	stat.BlocksAvailable = fs.sb.FreeBlocksCount()
	stat.Files = uint64(fs.sb.InodesCount())
	stat.FilesFree = uint64(fs.sb.FreeInodesCount())
	stat.NameLength = disklayout.MaxFileName
	stat.FragmentSize = int64(fs.sb.BlockSize())
	// TODO(b/134676337): Set Statfs.Flags and Statfs.FSID.
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	vfsd, inode, err := fs.walk(rp, false)
	if err != nil {
		return nil, err
	}

	if opts.CheckSearchable {
		if !inode.isDir() {
			return nil, syserror.ENOTDIR
		}
		if err := inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}

	inode.incRef()
	return vfsd, nil
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	vfsd, inode, err := fs.walk(rp, false)
	if err != nil {
		return nil, err
	}

	// EROFS is returned if write access is needed.
	if vfs.MayWriteFileWithOpenFlags(opts.Flags) || opts.Flags&(linux.O_CREAT|linux.O_EXCL|linux.O_TMPFILE) != 0 {
		return nil, syserror.EROFS
	}
	return inode.open(rp, vfsd, opts.Flags)
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	_, inode, err := fs.walk(rp, false)
	if err != nil {
		return "", err
	}
	symlink, ok := inode.impl.(*symlink)
	if !ok {
		return "", syserror.EINVAL
	}
	return symlink.target, nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	_, inode, err := fs.walk(rp, false)
	if err != nil {
		return linux.Statx{}, err
	}
	var stat linux.Statx
	inode.statTo(&stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	if _, _, err := fs.walk(rp, false); err != nil {
		return linux.Statfs{}, err
	}

	var stat linux.Statfs
	fs.statTo(&stat)
	return stat, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// This is a readonly filesystem for now.
	return nil
}

// The vfs.FilesystemImpl functions below return EROFS because their respective
// man pages say that EROFS must be returned if the path resolves to a file on
// this read-only filesystem.

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	if rp.Done() {
		return syserror.EEXIST
	}

	if _, _, err := fs.walk(rp, true); err != nil {
		return err
	}

	return syserror.EROFS
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}

	if _, _, err := fs.walk(rp, true); err != nil {
		return err
	}

	return syserror.EROFS
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	if rp.Done() {
		return syserror.EEXIST
	}

	_, _, err := fs.walk(rp, true)
	if err != nil {
		return err
	}

	return syserror.EROFS
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry, opts vfs.RenameOptions) error {
	if rp.Done() {
		return syserror.ENOENT
	}

	_, _, err := fs.walk(rp, false)
	if err != nil {
		return err
	}

	return syserror.EROFS
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	_, inode, err := fs.walk(rp, false)
	if err != nil {
		return err
	}

	if !inode.isDir() {
		return syserror.ENOTDIR
	}

	return syserror.EROFS
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	_, _, err := fs.walk(rp, false)
	if err != nil {
		return err
	}

	return syserror.EROFS
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	if rp.Done() {
		return syserror.EEXIST
	}

	_, _, err := fs.walk(rp, true)
	if err != nil {
		return err
	}

	return syserror.EROFS
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	_, inode, err := fs.walk(rp, false)
	if err != nil {
		return err
	}

	if inode.isDir() {
		return syserror.EISDIR
	}

	return syserror.EROFS
}
