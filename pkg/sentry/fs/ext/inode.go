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
	"io"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/syserror"
)

// inode represents an ext inode.
//
// inode uses the same inheritance pattern that pkg/sentry/vfs structures use.
// This has been done to increase memory locality.
//
// Implementations:
//    inode --
//           |-- pipe
//           |-- dir
//           |-- symlink
//           |-- regular--
//                       |-- extent file
//                       |-- block map file
//                       |-- inline file
type inode struct {
	// refs is a reference count. refs is accessed using atomic memory operations.
	refs int64

	// inodeNum is the inode number of this inode on disk. This is used to
	// identify inodes within the ext filesystem.
	inodeNum uint32

	// dev represents the underlying device. Same as filesystem.dev.
	dev io.ReaderAt

	// blkSize is the fs data block size. Same as filesystem.sb.BlockSize().
	blkSize uint64

	// diskInode gives us access to the inode struct on disk. Immutable.
	diskInode disklayout.Inode

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
// Precondition: Must have locked fs.mu.
func (in *inode) decRef(fs *filesystem) {
	if refs := atomic.AddInt64(&in.refs, -1); refs == 0 {
		delete(fs.inodeCache, in.inodeNum)
	} else if refs < 0 {
		panic("ext.inode.decRef() called without holding a reference")
	}
}

// newInode is the inode constructor. Reads the inode off disk. Identifies
// inodes based on the absolute inode number on disk.
func newInode(ctx context.Context, fs *filesystem, inodeNum uint32) (*inode, error) {
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
	inode := inode{
		refs:      1,
		inodeNum:  inodeNum,
		dev:       fs.dev,
		blkSize:   blkSize,
		diskInode: diskInode,
	}

	switch diskInode.Mode().FileType() {
	case linux.ModeSymlink:
		f, err := newSymlink(inode)
		if err != nil {
			return nil, err
		}
		return &f.inode, nil
	case linux.ModeRegular:
		f, err := newRegularFile(inode)
		if err != nil {
			return nil, err
		}
		return &f.inode, nil
	case linux.ModeDirectory:
		return &newDirectroy(inode).inode, nil
	case linux.ModeNamedPipe:
		return &newNamedPipe(ctx, inode).inode, nil
	default:
		// TODO(b/134676337): Return appropriate errors for sockets and devices.
		return nil, syserror.EINVAL
	}
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
