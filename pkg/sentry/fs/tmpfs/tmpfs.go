// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
)

var fsInfo = fs.Info{
	Type: linux.TMPFS_MAGIC,

	// TODO: allow configuring a tmpfs size and enforce it.
	TotalBlocks: 0,
	FreeBlocks:  0,
}

// rename implements fs.InodeOperations.Rename for tmpfs nodes.
func rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	op, ok := oldParent.InodeOperations.(*Dir)
	if !ok {
		return ramfs.ErrCrossDevice
	}
	np, ok := newParent.InodeOperations.(*Dir)
	if !ok {
		return ramfs.ErrCrossDevice
	}
	return ramfs.Rename(ctx, &op.Dir, oldName, &np.Dir, newName)
}

// Dir is a directory.
//
// +stateify savable
type Dir struct {
	ramfs.Dir

	// platform is used to allocate storage for tmpfs Files.
	platform platform.Platform
}

// NewDir returns a new directory.
func NewDir(ctx context.Context, contents map[string]*fs.Inode, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource, platform platform.Platform) *fs.Inode {
	d := &Dir{platform: platform}
	d.InitDir(ctx, contents, owner, perms)

	// Manually set the CreateOps.
	d.CreateOps = d.newCreateOps()

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
	d.Dir.CreateOps = d.newCreateOps()
}

// newCreateOps builds the custom CreateOps for this Dir.
func (d *Dir) newCreateOps() *ramfs.CreateOps {
	return &ramfs.CreateOps{
		NewDir: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			return NewDir(ctx, nil, fs.FileOwnerFromContext(ctx), perms, dir.MountSource, d.platform), nil
		},
		NewFile: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			uattr := fs.WithCurrentTime(ctx, fs.UnstableAttr{
				Owner: fs.FileOwnerFromContext(ctx),
				Perms: perms,
				// Always start unlinked.
				Links: 0,
			})
			iops := NewInMemoryFile(ctx, usage.Tmpfs, uattr, d.platform)
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
		NewBoundEndpoint: func(ctx context.Context, dir *fs.Inode, socket unix.BoundEndpoint, perms fs.FilePermissions) (*fs.Inode, error) {
			return NewSocket(ctx, socket, fs.FileOwnerFromContext(ctx), perms, dir.MountSource), nil
		},
		NewFifo: func(ctx context.Context, dir *fs.Inode, perms fs.FilePermissions) (*fs.Inode, error) {
			return NewFifo(ctx, fs.FileOwnerFromContext(ctx), perms, dir.MountSource), nil
		},
	}
}

// Rename implements fs.InodeOperations.Rename.
func (d *Dir) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	return rename(ctx, oldParent, oldName, newParent, newName)
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
	s := &Symlink{}
	s.InitSymlink(ctx, owner, target)
	return fs.NewInode(s, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Symlink,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (s *Symlink) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	return rename(ctx, oldParent, oldName, newParent, newName)
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
}

// NewSocket returns a new socket with the provided permissions.
func NewSocket(ctx context.Context, socket unix.BoundEndpoint, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource) *fs.Inode {
	s := &Socket{}
	s.InitSocket(ctx, socket, owner, perms)
	return fs.NewInode(s, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Socket,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (s *Socket) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	return rename(ctx, oldParent, oldName, newParent, newName)
}

// StatFS returns the tmpfs info.
func (s *Socket) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}

// Fifo is a tmpfs named pipe.
//
// +stateify savable
type Fifo struct {
	ramfs.Entry
}

// NewFifo creates a new named pipe.
func NewFifo(ctx context.Context, owner fs.FileOwner, perms fs.FilePermissions, msrc *fs.MountSource) *fs.Inode {
	f := &Fifo{}
	f.InitEntry(ctx, owner, perms)
	iops := pipe.NewInodeOperations(f, pipe.NewPipe(ctx, true /* isNamed */, pipe.DefaultPipeSize, usermem.PageSize))
	return fs.NewInode(iops, msrc, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.Pipe,
	})
}

// Rename implements fs.InodeOperations.Rename.
func (f *Fifo) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	return rename(ctx, oldParent, oldName, newParent, newName)
}

// StatFS returns the tmpfs info.
func (*Fifo) StatFS(context.Context) (fs.Info, error) {
	return fsInfo, nil
}
