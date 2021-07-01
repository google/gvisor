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

// Package tmpfs is a filesystem implementation backed by memory.
package tmpfs

import (
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

var fsInfo = fs.Info{
	Type: linux.TMPFS_MAGIC,

	// tmpfs currently does not support configurable size limits. In Linux,
	// such a tmpfs mount will return f_blocks == f_bfree == f_bavail == 0 from
	// statfs(2). However, many applications treat this as having a size limit
	// of 0. To work around this, claim to have a very large but non-zero size,
	// chosen to ensure that BlockSize * Blocks does not overflow int64 (which
	// applications may also handle incorrectly).
	// TODO(b/29637826): allow configuring a tmpfs size and enforce it.
	TotalBlocks: math.MaxInt64 / hostarch.PageSize,
	FreeBlocks:  math.MaxInt64 / hostarch.PageSize,
}

// rename implements fs.InodeOperations.Rename for tmpfs nodes.
func rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	// Don't allow renames across different mounts.
	if newParent.MountSource != oldParent.MountSource {
		return linuxerr.EXDEV
	}

	op := oldParent.InodeOperations.(*Dir)
	np := newParent.InodeOperations.(*Dir)
	return ramfs.Rename(ctx, op.ramfsDir, oldName, np.ramfsDir, newName, replacement)
}

// Dir is a directory.
//
// +stateify savable
type Dir struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeIsDirTruncate  `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`
	fsutil.InodeVirtual        `state:"nosave"`

	// Ideally this would be embedded, so that we "inherit" all of the
	// InodeOperations implemented by ramfs.Dir for free.
	//
	// However, ramfs.dirFileOperations stores a pointer to a ramfs.Dir,
	// and our save/restore package does not allow saving a pointer to an
	// embedded field elsewhere.
	//
	// Thus, we must make the ramfs.Dir is a field, and we delegate all the
	// InodeOperation methods to it.
	ramfsDir *ramfs.Dir

	// kernel is used to allocate memory as storage for tmpfs Files.
	kernel *kernel.Kernel
}

var _ fs.InodeOperations = (*Dir)(nil)

// NewDir returns a new directory.
func NewDir(ctx context.Context, contents map[string]*fs.Inode, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource, parent *fs.Inode) (*fs.Inode, error) {
	// If the parent has setgid enabled, the new directory enables it and changes
	// its GID.
	if parent != nil {
		parentUattr, err := parent.UnstableAttr(ctx)
		if err != nil {
			return nil, err
		}
		if parentUattr.Perms.SetGID {
			owner.GID = parentUattr.Owner.GID
			perms.SetGID = true
		}
	}

	d := &Dir{
		ramfsDir: ramfs.NewDir(ctx, contents, owner, perms),
		kernel:   kernel.KernelFromContext(ctx),
	}

	// Manually set the CreateOps.
	d.ramfsDir.CreateOps = d.newCreateOps()

	return fs.NewInode(ctx, d, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Directory,
	}), nil
}

// afterLoad is invoked by stateify.
func (d *Dir) afterLoad() {
	// Per NewDir, manually set the CreateOps.
	d.ramfsDir.CreateOps = d.newCreateOps()
}

// GetFile implements fs.InodeOperations.GetFile.
func (d *Dir) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return d.ramfsDir.GetFile(ctx, dirent, flags)
}

// AddLink implements fs.InodeOperations.AddLink.
func (d *Dir) AddLink() {
	d.ramfsDir.AddLink()
}

// DropLink implements fs.InodeOperations.DropLink.
func (d *Dir) DropLink() {
	d.ramfsDir.DropLink()
}

// Bind implements fs.InodeOperations.Bind.
func (d *Dir) Bind(ctx context.Context, dir *fs.Inode, name string, ep transport.BoundEndpoint, perms fs.FilePermissions) (*fs.Dirent, error) {
	return d.ramfsDir.Bind(ctx, dir, name, ep, perms)
}

// Create implements fs.InodeOperations.Create.
func (d *Dir) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perms fs.FilePermissions) (*fs.File, error) {
	return d.ramfsDir.Create(ctx, dir, name, flags, perms)
}

// CreateLink implements fs.InodeOperations.CreateLink.
func (d *Dir) CreateLink(ctx context.Context, dir *fs.Inode, oldname, newname string) error {
	return d.ramfsDir.CreateLink(ctx, dir, oldname, newname)
}

// CreateHardLink implements fs.InodeOperations.CreateHardLink.
func (d *Dir) CreateHardLink(ctx context.Context, dir *fs.Inode, target *fs.Inode, name string) error {
	return d.ramfsDir.CreateHardLink(ctx, dir, target, name)
}

// CreateDirectory implements fs.InodeOperations.CreateDirectory.
func (d *Dir) CreateDirectory(ctx context.Context, dir *fs.Inode, name string, perms fs.FilePermissions) error {
	return d.ramfsDir.CreateDirectory(ctx, dir, name, perms)
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
func (d *Dir) CreateFifo(ctx context.Context, dir *fs.Inode, name string, perms fs.FilePermissions) error {
	return d.ramfsDir.CreateFifo(ctx, dir, name, perms)
}

// GetXattr implements fs.InodeOperations.GetXattr.
func (d *Dir) GetXattr(ctx context.Context, i *fs.Inode, name string, size uint64) (string, error) {
	return d.ramfsDir.GetXattr(ctx, i, name, size)
}

// SetXattr implements fs.InodeOperations.SetXattr.
func (d *Dir) SetXattr(ctx context.Context, i *fs.Inode, name, value string, flags uint32) error {
	return d.ramfsDir.SetXattr(ctx, i, name, value, flags)
}

// ListXattr implements fs.InodeOperations.ListXattr.
func (d *Dir) ListXattr(ctx context.Context, i *fs.Inode, size uint64) (map[string]struct{}, error) {
	return d.ramfsDir.ListXattr(ctx, i, size)
}

// RemoveXattr implements fs.InodeOperations.RemoveXattr.
func (d *Dir) RemoveXattr(ctx context.Context, i *fs.Inode, name string) error {
	return d.ramfsDir.RemoveXattr(ctx, i, name)
}

// Lookup implements fs.InodeOperations.Lookup.
func (d *Dir) Lookup(ctx context.Context, i *fs.Inode, p string) (*fs.Dirent, error) {
	return d.ramfsDir.Lookup(ctx, i, p)
}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (d *Dir) NotifyStatusChange(ctx context.Context) {
	d.ramfsDir.NotifyStatusChange(ctx)
}

// Remove implements fs.InodeOperations.Remove.
func (d *Dir) Remove(ctx context.Context, i *fs.Inode, name string) error {
	return d.ramfsDir.Remove(ctx, i, name)
}

// RemoveDirectory implements fs.InodeOperations.RemoveDirectory.
func (d *Dir) RemoveDirectory(ctx context.Context, i *fs.Inode, name string) error {
	return d.ramfsDir.RemoveDirectory(ctx, i, name)
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (d *Dir) UnstableAttr(ctx context.Context, i *fs.Inode) (fs.UnstableAttr, error) {
	return d.ramfsDir.UnstableAttr(ctx, i)
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (d *Dir) SetPermissions(ctx context.Context, i *fs.Inode, p fs.FilePermissions) bool {
	return d.ramfsDir.SetPermissions(ctx, i, p)
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (d *Dir) SetOwner(ctx context.Context, i *fs.Inode, owner fs.FileOwner) error {
	return d.ramfsDir.SetOwner(ctx, i, owner)
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (d *Dir) SetTimestamps(ctx context.Context, i *fs.Inode, ts fs.TimeSpec) error {
	return d.ramfsDir.SetTimestamps(ctx, i, ts)
}

// newCreateOps builds the custom CreateOps for this Dir.
func (d *Dir) newCreateOps() *ramfs.CreateOps {
	return &ramfs.CreateOps{
		NewDir: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			return NewDir(ctx, nil, fs.FileOwnerFromContext(ctx), perms, dir.MountSource, dir)
		},
		NewFile: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			// If the parent has setgid enabled, change the GID of the new file.
			owner := fs.FileOwnerFromContext(ctx)
			parentUattr, err := dir.UnstableAttr(ctx)
			if err != nil {
				return nil, err
			}
			if parentUattr.Perms.SetGID {
				owner.GID = parentUattr.Owner.GID
			}

			uattr := fs.WithCurrentTime(ctx, fs.UnstableAttr{
				Owner: owner,
				Perms: perms,
				// Always start unlinked.
				Links: 0,
			})
			iops := NewInMemoryFile(ctx, usage.Tmpfs, uattr)
			return fs.NewInode(ctx, iops, dir.MountSource, fs.StableAttr{
				DeviceID:  tmpfsDevice.DeviceID(),
				InodeID:   tmpfsDevice.NextIno(),
				BlockSize: hostarch.PageSize,
				Type:      fs.RegularFile,
			}), nil
		},
		NewSymlink: func(ctx context.Context, dir *fs.Inode, target string) (*fs.Inode, error) {
			return NewSymlink(ctx, target, fs.FileOwnerFromContext(ctx), dir.MountSource), nil
		},
		NewBoundEndpoint: func(ctx context.Context, dir *fs.Inode, socket transport.BoundEndpoint, perms fs.FilePermissions) (*fs.Inode, error) {
			return NewSocket(ctx, socket, fs.FileOwnerFromContext(ctx), perms, dir.MountSource), nil
		},
		NewFifo: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			return NewFifo(ctx, fs.FileOwnerFromContext(ctx), perms, dir.MountSource), nil
		},
	}
}

// Rename implements fs.InodeOperations.Rename.
func (d *Dir) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// StatFS implements fs.InodeOperations.StatFS.
func (*Dir) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}

// Allocate implements fs.InodeOperations.Allocate.
func (d *Dir) Allocate(ctx context.Context, node *fs.Inode, offset, length int64) error {
	return d.ramfsDir.Allocate(ctx, node, offset, length)
}

// Release implements fs.InodeOperations.Release.
func (d *Dir) Release(ctx context.Context) {
	d.ramfsDir.Release(ctx)
}

// Symlink is a symlink.
//
// +stateify savable
type Symlink struct {
	ramfs.Symlink
}

// NewSymlink returns a new symlink with the provided permissions.
func NewSymlink(ctx context.Context, target string, owner fs.FileOwner, msrc *fs.MountSource) *fs.Inode {
	s := &Symlink{Symlink: *ramfs.NewSymlink(ctx, owner, target)}
	return fs.NewInode(ctx, s, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Symlink,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (s *Symlink) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// StatFS returns the tmpfs info.
func (s *Symlink) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}

// Socket is a socket.
//
// +stateify savable
type Socket struct {
	ramfs.Socket
	fsutil.InodeNotTruncatable `state:"nosave"`
	fsutil.InodeNotAllocatable `state:"nosave"`
}

// NewSocket returns a new socket with the provided permissions.
func NewSocket(ctx context.Context, socket transport.BoundEndpoint, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource) *fs.Inode {
	s := &Socket{Socket: *ramfs.NewSocket(ctx, socket, owner, perms)}
	return fs.NewInode(ctx, s, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Socket,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (s *Socket) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// StatFS returns the tmpfs info.
func (s *Socket) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}

// Fifo is a tmpfs named pipe.
//
// +stateify savable
type Fifo struct {
	fs.InodeOperations
}

// NewFifo creates a new named pipe.
func NewFifo(ctx context.Context, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource) *fs.Inode {
	// First create a pipe.
	p := pipe.NewPipe(true /* isNamed */, pipe.DefaultPipeSize)

	// Build pipe InodeOperations.
	iops := pipe.NewInodeOperations(ctx, perms, p)

	// Wrap the iops with our Fifo.
	fifoIops := &Fifo{iops}

	// Build a new Inode.
	return fs.NewInode(ctx, fifoIops, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: hostarch.PageSize,
		Type:      fs.Pipe,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (f *Fifo) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// StatFS returns the tmpfs info.
func (*Fifo) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}
