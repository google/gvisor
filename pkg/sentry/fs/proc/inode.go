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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// taskOwnedInodeOps wraps an fs.InodeOperations and overrides the UnstableAttr
// method to return either the task or root as the owner, depending on the
// task's dumpability.
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

	// By default, set the task owner as the file owner.
	creds := i.t.Credentials()
	uattr.Owner = fs.FileOwner{creds.EffectiveKUID, creds.EffectiveKGID}

	// Linux doesn't apply dumpability adjustments to world
	// readable/executable directories so that applications can stat
	// /proc/PID to determine the effective UID of a process. See
	// fs/proc/base.c:task_dump_owner.
	if fs.IsDir(inode.StableAttr) && uattr.Perms == fs.FilePermsFromMode(0555) {
		return uattr, nil
	}

	// If the task is not dumpable, then root (in the namespace preferred)
	// owns the file.
	var m *mm.MemoryManager
	i.t.WithMuLocked(func(t *kernel.Task) {
		m = t.MemoryManager()
	})

	if m == nil {
		uattr.Owner.UID = auth.RootKUID
		uattr.Owner.GID = auth.RootKGID
	} else if m.Dumpability() != mm.UserDumpable {
		if kuid := creds.UserNamespace.MapToKUID(auth.RootUID); kuid.Ok() {
			uattr.Owner.UID = kuid
		} else {
			uattr.Owner.UID = auth.RootKUID
		}
		if kgid := creds.UserNamespace.MapToKGID(auth.RootGID); kgid.Ok() {
			uattr.Owner.GID = kgid
		} else {
			uattr.Owner.GID = auth.RootKGID
		}
	}

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
	return newProcInode(ctx, iops, msrc, fs.SpecialFile, nil)
}

// newProcInode creates a new inode from the given inode operations.
func newProcInode(ctx context.Context, iops fs.InodeOperations, msrc *fs.MountSource, typ fs.InodeType, t *kernel.Task) *fs.Inode {
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      typ,
	}
	if t != nil {
		iops = &taskOwnedInodeOps{iops, t}
	}
	return fs.NewInode(ctx, iops, msrc, sattr)
}
