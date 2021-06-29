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
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// inode represents an ext inode.
//
// inode uses the same inheritance pattern that pkg/sentry/vfs structures use.
// This has been done to increase memory locality.
//
// Implementations:
//    inode --
//           |-- dir
//           |-- symlink
//           |-- regular--
//                       |-- extent file
//                       |-- block map file
//
// +stateify savable
type inode struct {
	// refs is a reference count. refs is accessed using atomic memory operations.
	refs int64

	// fs is the containing filesystem.
	fs *filesystem

	// inodeNum is the inode number of this inode on disk. This is used to
	// identify inodes within the ext filesystem.
	inodeNum uint32

	// blkSize is the fs data block size. Same as filesystem.sb.BlockSize().
	blkSize uint64

	// diskInode gives us access to the inode struct on disk. Immutable.
	diskInode disklayout.Inode

	locks vfs.FileLocks

	// This is immutable. The first field of the implementations must have inode
	// as the first field to ensure temporality.
	impl interface{}
}

// incRef increments the inode ref count.
func (in *inode) incRef() {
	atomic.AddInt64(&in.refs, 1)
}

// tryIncRef tries to increment the ref count. Returns true if successful.
func (in *inode) tryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&in.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&in.refs, refs, refs+1) {
			return true
		}
	}
}

// decRef decrements the inode ref count and releases the inode resources if
// the ref count hits 0.
//
// Precondition: Must have locked filesystem.mu.
func (in *inode) decRef() {
	if refs := atomic.AddInt64(&in.refs, -1); refs == 0 {
		delete(in.fs.inodeCache, in.inodeNum)
	} else if refs < 0 {
		panic("ext.inode.decRef() called without holding a reference")
	}
}

// newInode is the inode constructor. Reads the inode off disk. Identifies
// inodes based on the absolute inode number on disk.
func newInode(fs *filesystem, inodeNum uint32) (*inode, error) {
	if inodeNum == 0 {
		panic("inode number 0 on ext filesystems is not possible")
	}

	inodeRecordSize := fs.sb.InodeSize()
	var diskInode disklayout.Inode
	if inodeRecordSize == disklayout.OldInodeSize {
		diskInode = &disklayout.InodeOld{}
	} else {
		diskInode = &disklayout.InodeNew{}
	}

	// Calculate where the inode is actually placed.
	inodesPerGrp := fs.sb.InodesPerGroup()
	blkSize := fs.sb.BlockSize()
	inodeTableOff := fs.bgs[getBGNum(inodeNum, inodesPerGrp)].InodeTable() * blkSize
	inodeOff := inodeTableOff + uint64(uint32(inodeRecordSize)*getBGOff(inodeNum, inodesPerGrp))

	if err := readFromDisk(fs.dev, int64(inodeOff), diskInode); err != nil {
		return nil, err
	}

	// Build the inode based on its type.
	args := inodeArgs{
		fs:        fs,
		inodeNum:  inodeNum,
		blkSize:   blkSize,
		diskInode: diskInode,
	}

	switch diskInode.Mode().FileType() {
	case linux.ModeSymlink:
		f, err := newSymlink(args)
		if err != nil {
			return nil, err
		}
		return &f.inode, nil
	case linux.ModeRegular:
		f, err := newRegularFile(args)
		if err != nil {
			return nil, err
		}
		return &f.inode, nil
	case linux.ModeDirectory:
		f, err := newDirectory(args, fs.sb.IncompatibleFeatures().DirentFileType)
		if err != nil {
			return nil, err
		}
		return &f.inode, nil
	default:
		// TODO(b/134676337): Return appropriate errors for sockets, pipes and devices.
		return nil, linuxerr.EINVAL
	}
}

type inodeArgs struct {
	fs        *filesystem
	inodeNum  uint32
	blkSize   uint64
	diskInode disklayout.Inode
}

func (in *inode) init(args inodeArgs, impl interface{}) {
	in.fs = args.fs
	in.inodeNum = args.inodeNum
	in.blkSize = args.blkSize
	in.diskInode = args.diskInode
	in.impl = impl
}

// open creates and returns a file description for the dentry passed in.
func (in *inode) open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := in.checkPermissions(rp.Credentials(), ats); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	switch in.impl.(type) {
	case *regularFile:
		var fd regularFileFD
		fd.LockFD.Init(&in.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case *directory:
		// Can't open directories writably. This check is not necessary for a read
		// only filesystem but will be required when write is implemented.
		if ats&vfs.MayWrite != 0 {
			return nil, syserror.EISDIR
		}
		var fd directoryFD
		fd.LockFD.Init(&in.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case *symlink:
		if opts.Flags&linux.O_PATH == 0 {
			// Can't open symlinks without O_PATH.
			return nil, syserror.ELOOP
		}
		var fd symlinkFD
		fd.LockFD.Init(&in.locks)
		if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	default:
		panic(fmt.Sprintf("unknown inode type: %T", in.impl))
	}
}

func (in *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, in.diskInode.Mode(), in.diskInode.UID(), in.diskInode.GID())
}

// statTo writes the statx fields to the output parameter.
func (in *inode) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK |
		linux.STATX_UID | linux.STATX_GID | linux.STATX_INO | linux.STATX_SIZE |
		linux.STATX_ATIME | linux.STATX_CTIME | linux.STATX_MTIME
	stat.Blksize = uint32(in.blkSize)
	stat.Mode = uint16(in.diskInode.Mode())
	stat.Nlink = uint32(in.diskInode.LinksCount())
	stat.UID = uint32(in.diskInode.UID())
	stat.GID = uint32(in.diskInode.GID())
	stat.Ino = uint64(in.inodeNum)
	stat.Size = in.diskInode.Size()
	stat.Atime = in.diskInode.AccessTime().StatxTimestamp()
	stat.Ctime = in.diskInode.ChangeTime().StatxTimestamp()
	stat.Mtime = in.diskInode.ModificationTime().StatxTimestamp()
	stat.DevMajor = linux.UNNAMED_MAJOR
	stat.DevMinor = in.fs.devMinor
	// TODO(b/134676337): Set stat.Blocks which is the number of 512 byte blocks
	// (including metadata blocks) required to represent this file.
}

// getBGNum returns the block group number that a given inode belongs to.
func getBGNum(inodeNum uint32, inodesPerGrp uint32) uint32 {
	return (inodeNum - 1) / inodesPerGrp
}

// getBGOff returns the offset at which the given inode lives in the block
// group's inode table, i.e. the index of the inode in the inode table.
func getBGOff(inodeNum uint32, inodesPerGrp uint32) uint32 {
	return (inodeNum - 1) % inodesPerGrp
}
