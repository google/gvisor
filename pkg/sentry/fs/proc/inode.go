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

package proc

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// taskOwnedInodeOps wraps an fs.InodeOperations and overrides the UnstableAttr
// method to return the task as the owner.
//
// +stateify savable
type taskOwnedInodeOps struct {
	fs.InodeOperations

	// t is the task that owns this file.
	t *kernel.Task
}

// UnstableAttr implement fs.InodeOperations.UnstableAttr.
func (i *taskOwnedInodeOps) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, err := i.InodeOperations.UnstableAttr(ctx, inode)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	// Set the task owner as the file owner.
	creds := i.t.Credentials()
	uattr.Owner = fs.FileOwner{creds.EffectiveKUID, creds.EffectiveKGID}
	return uattr, nil
}

// staticFileInodeOps is an InodeOperations implementation that can be used to
// return file contents which are constant. This file is not writable and will
// always have mode 0444.
//
// +stateify savable
type staticFileInodeOps struct {
	fsutil.InodeDenyWriteChecker     `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopAllocate         `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeStaticFileGetter
}

var _ fs.InodeOperations = (*staticFileInodeOps)(nil)

// newStaticFileInode returns a procfs InodeOperations with static contents.
func newStaticProcInode(ctx context.Context, msrc *fs.MountSource, contents []byte) *fs.Inode {
	iops := &staticFileInodeOps{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		InodeStaticFileGetter: fsutil.InodeStaticFileGetter{
			Contents: contents,
		},
	}
	return newProcInode(iops, msrc, fs.SpecialFile, nil)
}

// newProcInode creates a new inode from the given inode operations.
func newProcInode(iops fs.InodeOperations, msrc *fs.MountSource, typ fs.InodeType, t *kernel.Task) *fs.Inode {
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      typ,
	}
	if t != nil {
		iops = &taskOwnedInodeOps{iops, t}
	}
	return fs.NewInode(iops, msrc, sattr)
}
