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

package ext4

import (
	"io"
	"io/ioutil"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/third_party/goext4"
)

// inodeOperations implements fs.InodeOperations.
//
// +stateify savable
type inodeOperations struct {
	// Embedded inode operations.
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotVirtual           `state:"nosave"`

	// TODO(b/134676337): Remove when write operations are supported.
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotTruncatable `state:"nosave"`

	// TODO(b/134676337): Implement when file operations are implemented.
	fsutil.InodeNotOpenable    `state:"nosave"`
	fsutil.InodeNotAllocatable `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`

	// blockGroupDescriptorList contains a list of all block descriptors in the
	// ext4 device. This will be required while browsing other inode.
	blockGroupDescriptorList *goext4.BlockGroupDescriptorList

	// ext4Inode conatins the ext4 inode structure defined in fs/ext4/ext4.h.
	ext4Inode *goext4.Inode

	// TODO(b/134676337): Add synchronization since the underlying file descriptor
	// is shared across all fs operations. readSeeker in the io.ReadSeeker which
	// wraps the underlying file descriptor to the ext4 device.
	readSeeker io.ReadSeeker
}

// newInode reads in the ext4 inode structure from the ext4 device and
// initializes the required structures.
//
// absoluteInodeNumber is used to identify an inode within the entire ext4
// device. It is different from relative inode numbers which are relative only
// to the block group the inode belongs to.
func newInode(bgdl *goext4.BlockGroupDescriptorList, msrc *fs.MountSource, absoluteInodeNumber uint64, rs io.ReadSeeker, inodeType fs.InodeType) (*fs.Inode, error) {
	bgd, err := bgdl.GetWithAbsoluteInode(int(absoluteInodeNumber))
	if err != nil {
		return nil, getSysError(err)
	}

	ext4Inode, err := goext4.NewInodeWithReadSeeker(bgd, rs, int(absoluteInodeNumber))
	if err != nil {
		return nil, getSysError(err)
	}

	inodeOps := inodeOperations{
		blockGroupDescriptorList: bgdl,
		ext4Inode:                ext4Inode,
		readSeeker:               rs,
	}

	// Use ext4 absolute inode numbers for InodeID since they are unique within this device.
	return fs.NewInode(
		&inodeOps, msrc, fs.StableAttr{
			Type:      inodeType,
			DeviceID:  ext4Device.DeviceID(),
			InodeID:   absoluteInodeNumber,
			BlockSize: int64(bgdl.Superblock().BlockSize()),
		}), nil
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (i *inodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	inodeData := i.ext4Inode.Data()

	return fs.UnstableAttr{
		Size:  int64(i.ext4Inode.Size()),
		Perms: fs.FilePermsFromMode(linux.FileMode(inodeData.IMode)),
		Owner: fs.FileOwner{
			UID: auth.KUID(inodeData.IUid),
			GID: auth.KGID(inodeData.IGid),
		},
		AccessTime:       time.FromUnix(int64(inodeData.IAtime), 0),
		ModificationTime: time.FromUnix(int64(inodeData.IMtime), 0),
		StatusChangeTime: time.FromUnix(int64(inodeData.ICtime), 0),
		Links:            uint64(i.ext4Inode.Links()),
	}, nil
}

// Lookup implements fs.InodeOperations.Lookup.
func (i *inodeOperations) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	if len(name) > goext4.FilenameMaxLen {
		return nil, syserror.ENAMETOOLONG
	}

	browser := goext4.NewDirectoryBrowser(i.readSeeker, i.ext4Inode)

	for {
		d, err := browser.Next()

		// Return a negative dirent so that the result is cached.
		if err == io.EOF {
			return fs.NewNegativeDirent(name), nil
		}

		if err != nil {
			return nil, getSysError(err)
		}

		if d.Name() != name {
			continue
		}

		childInode, err := newInode(
			i.blockGroupDescriptorList,
			dir.MountSource,
			uint64(d.Data().Inode),
			i.readSeeker,
			getInodeType(d.Data().FileType),
		)

		if err != nil {
			return nil, err
		}

		return fs.NewDirent(childInode, name), nil
	}
}

// Readlink implements fs.InodeOperations.Readlink.
func (i *inodeOperations) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if !fs.IsSymlink(inode.StableAttr) {
		return "", syscall.ENOLINK
	}

	nav := goext4.NewExtentNavigatorWithReadSeeker(i.readSeeker, i.ext4Inode)
	r := goext4.NewInodeReader(nav)

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return "", getSysError(err)
	}

	return string(b), nil
}

// Getlink implements fs.InodeOperations.Getlink.
func (i *inodeOperations) Getlink(ctx context.Context, inode *fs.Inode) (*fs.Dirent, error) {
	if !fs.IsSymlink(inode.StableAttr) {
		return nil, syserror.ENOLINK
	}
	return nil, fs.ErrResolveViaReadlink
}

// Bind implements fs.InodeOperations.Bind.
func (i *inodeOperations) Bind(context.Context, *fs.Inode, string, transport.BoundEndpoint, fs.FilePermissions) (*fs.Dirent, error) {
	return nil, syserror.EINVAL
}

// TODO(b/134676337): Implement functions below when write operations are
// supported.

// StatFS implements fs.InodeOperations.StatFS.
func (i *inodeOperations) StatFS(ctx context.Context) (fs.Info, error) {
	sb := i.blockGroupDescriptorList.Superblock()

	return fs.Info{
		Type:        linux.EXT4_SUPER_MAGIC,
		TotalBlocks: sb.BlockCount(),
		FreeBlocks:  sb.FreeBlockCount(),
		TotalFiles:  uint64(sb.Data().SInodesCount),
		FreeFiles:   uint64(sb.Data().SFreeInodesCount),
	}, nil
}

// AddLink implements fs.InodeOperations.AddLink, but is currently a noop.
// FIXME(b/63117438): Remove this from InodeOperations altogether.
func (*inodeOperations) AddLink() {}

// DropLink implements fs.InodeOperations.DropLink, but is currently a noop.
// FIXME(b/63117438): Remove this from InodeOperations altogether.
func (*inodeOperations) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
// FIXME(b/63117438): Remove this from InodeOperations altogether.
func (i *inodeOperations) NotifyStatusChange(ctx context.Context) {}

// TODO(b/134676337): Implement functions below when write operations are supported.

// Create implements fs.InodeOperations.Create.
func (i *inodeOperations) Create(context.Context, *fs.Inode, string, fs.FileFlags, fs.FilePermissions) (*fs.File, error) {
	return nil, syserror.EINVAL
}

// CreateLink implements fs.InodeOperations.CreateLink.
func (i *inodeOperations) CreateLink(context.Context, *fs.Inode, string, string) error {
	return syserror.EINVAL
}

// CreateHardLink implements fs.InodeOperations.CreateHardLink.
func (i *inodeOperations) CreateHardLink(context.Context, *fs.Inode, *fs.Inode, string) error {
	return syserror.EINVAL
}

// CreateDirectory implements fs.InodeOperations.CreateDirectory.
func (i *inodeOperations) CreateDirectory(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return syserror.EINVAL
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
func (i *inodeOperations) CreateFifo(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return syserror.EINVAL
}

// Remove implements fs.InodeOperations.Remove.
func (i *inodeOperations) Remove(context.Context, *fs.Inode, string) error {
	return syserror.EINVAL
}

// RemoveDirectory implements fs.InodeOperations.RemoveDirectory.
func (i *inodeOperations) RemoveDirectory(context.Context, *fs.Inode, string) error {
	return syserror.EINVAL
}

// Rename implements fs.FileOperations.Rename.
func (i *inodeOperations) Rename(context.Context, *fs.Inode, *fs.Inode, string, *fs.Inode, string, bool) error {
	return syserror.EINVAL
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (i *inodeOperations) SetPermissions(ctx context.Context, _ *fs.Inode, p fs.FilePermissions) bool {
	return false
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (i *inodeOperations) SetOwner(ctx context.Context, _ *fs.Inode, owner fs.FileOwner) error {
	return syserror.EINVAL
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (i *inodeOperations) SetTimestamps(ctx context.Context, _ *fs.Inode, ts fs.TimeSpec) error {
	return syserror.EINVAL
}
