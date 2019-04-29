// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

var fsInfo = fs.Info{
	Type: linux.TMPFS_MAGIC,

	// TODO(b/29637826): allow configuring a tmpfs size and enforce it.
	TotalBlocks: 0,
	FreeBlocks:  0,
}

// rename implements fs.InodeOperations.Rename for tmpfs nodes.
func rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	op, ok := oldParent.InodeOperations.(*Dir)
	if !ok {
		return syserror.EXDEV
	}
	np, ok := newParent.InodeOperations.(*Dir)
	if !ok {
		return syserror.EXDEV
	}
	return ramfs.Rename(ctx, op.ramfsDir, oldName, np.ramfsDir, newName, replacement)
}

// Dir is a directory.
//
// +stateify savable
type Dir struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeIsDirTruncate  `state:"nosave"`
	fsutil.InodeNoopRelease    `state:"nosave"`
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
func NewDir(ctx context.Context, contents map[string]*fs.Inode, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource) *fs.Inode {
	d := &Dir{
		ramfsDir: ramfs.NewDir(ctx, contents, owner, perms),
		kernel:   kernel.KernelFromContext(ctx),
	}

	// Manually set the CreateOps.
	d.ramfsDir.CreateOps = d.newCreateOps()

	return fs.NewInode(d, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Directory,
	})
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

// Getxattr implements fs.InodeOperations.Getxattr.
func (d *Dir) Getxattr(i *fs.Inode, name string) (string, error) {
	return d.ramfsDir.Getxattr(i, name)
}

// Setxattr implements fs.InodeOperations.Setxattr.
func (d *Dir) Setxattr(i *fs.Inode, name, value string) error {
	return d.ramfsDir.Setxattr(i, name, value)
}

// Listxattr implements fs.InodeOperations.Listxattr.
func (d *Dir) Listxattr(i *fs.Inode) (map[string]struct{}, error) {
	return d.ramfsDir.Listxattr(i)
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
			return NewDir(ctx, nil, fs.FileOwnerFromContext(ctx), perms, dir.MountSource), nil
		},
		NewFile: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			uattr := fs.WithCurrentTime(ctx, fs.UnstableAttr{
				Owner: fs.FileOwnerFromContext(ctx),
				Perms: perms,
				// Always start unlinked.
				Links: 0,
			})
			iops := NewInMemoryFile(ctx, usage.Tmpfs, uattr)
			return fs.NewInode(iops, dir.MountSource, fs.StableAttr{
				DeviceID:  tmpfsDevice.DeviceID(),
				InodeID:   tmpfsDevice.NextIno(),
				BlockSize: usermem.PageSize,
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
func (d *Dir) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// StatFS implments fs.InodeOperations.StatFS.
func (*Dir) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
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
	return fs.NewInode(s, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Symlink,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (s *Symlink) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
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
}

// NewSocket returns a new socket with the provided permissions.
func NewSocket(ctx context.Context, socket transport.BoundEndpoint, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource) *fs.Inode {
	s := &Socket{Socket: *ramfs.NewSocket(ctx, socket, owner, perms)}
	return fs.NewInode(s, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Socket,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (s *Socket) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
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
	p := pipe.NewPipe(ctx, true /* isNamed */, pipe.DefaultPipeSize, usermem.PageSize)

	// Build pipe InodeOperations.
	iops := pipe.NewInodeOperations(ctx, perms, p)

	// Wrap the iops with our Fifo.
	fifoIops := &Fifo{iops}

	// Build a new Inode.
	return fs.NewInode(fifoIops, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Pipe,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (f *Fifo) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return rename(ctx, oldParent, oldName, newParent, newName, replacement)
}

// StatFS returns the tmpfs info.
func (*Fifo) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}
