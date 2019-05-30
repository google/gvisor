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

	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/third_party/goext4"
)

// inodeOperations implements fs.InodeOperations.
//
// +stateify savable
type inodeOperations struct {
	// TODO(ayushranjan): This is temporary for compilation purposes. Remove this and implement the required functions.
	fsutil.SimpleFileInode `state:"nosave"`

	// blockGroupDescriptorList contains a list of all block descriptors in the
	// ext4 device. This will be required while browsing other inode.
	blockGroupDescriptorList *goext4.BlockGroupDescriptorList

	// ext4Inode conatins the ext4 inode structure defined in fs/ext4/ext4.h.
	ext4Inode *goext4.Inode

	// readSeeker in the io.ReadSeeker which wraps the underlying file descriptor
	// to the ext4 device.
	readSeeker io.ReadSeeker
}

// NewInode reads in the ext4 inode structure from the ext4 device and
// initializes the required structures.
func NewInode(bgdl *goext4.BlockGroupDescriptorList, msrc *fs.MountSource, absoluteInodeNumber uint64, rs io.ReadSeeker) (*fs.Inode, error) {
	bgd, err := bgdl.GetWithAbsoluteInode(int(absoluteInodeNumber))
	if err != nil {
		return nil, err
	}

	ext4Inode, err := goext4.NewInodeWithReadSeeker(bgd, rs, int(absoluteInodeNumber))
	if err != nil {
		return nil, err
	}

	inodeOps := inodeOperations{blockGroupDescriptorList: bgdl, ext4Inode: ext4Inode, readSeeker: rs}
	return fs.NewInode(
		&inodeOps, msrc, fs.StableAttr{
			Type:      fs.BlockDevice,
			DeviceID:  Ext4Device.DeviceID(),
			InodeID:   absoluteInodeNumber, // Use ext4 absolute inode numbers for InodeID since they are unique for this device.
			BlockSize: int64(bgdl.Superblock().BlockSize()),
		}), nil
}
