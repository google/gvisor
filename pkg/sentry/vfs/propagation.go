// Copyright 2022 The gVisor Authors.
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

package vfs

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func propTypeToString(pflag uint32) string {
	if pflag == 0 {
		return "0"
	}
	var (
		b   strings.Builder
		sep string
	)
	handleFlag := func(flag uint32, str string) {
		if pflag&flag != 0 {
			fmt.Fprintf(&b, "%s%s", sep, str)
			sep = "|"
			pflag &^= flag
		}
	}
	handleFlag(linux.MS_SHARED, "shared")
	handleFlag(linux.MS_PRIVATE, "private")
	handleFlag(linux.MS_SLAVE, "slave")
	handleFlag(linux.MS_UNBINDABLE, "unbindable")
	if pflag != 0 {
		fmt.Fprintf(&b, "%s%#x", sep, pflag)
	}
	return b.String()
}

// setPropagation sets the propagation on mnt for a propagation type.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) setPropagation(mnt *Mount, pflag uint32) error {
	switch pflag {
	case linux.MS_SHARED:
		if !mnt.isShared {
			id, err := vfs.allocateGroupID()
			if err != nil {
				return err
			}
			mnt.groupID = id
			mnt.sharedEntry.Init(mnt)
			mnt.isShared = true
		}
	case linux.MS_PRIVATE:
		if mnt.isShared {
			if mnt.sharedEntry.Empty() {
				vfs.freeGroupID(mnt.groupID)
			}
			mnt.sharedEntry.Remove()
			mnt.groupID = 0
			mnt.isShared = false
		}
	default:
		panic(fmt.Sprintf("unsupported propagation type: %s", propTypeToString(pflag)))
	}
	return nil
}

// addPeer adds oth to mnt's peer group. Both will have the same groupID
// and sharedList. vfs.mountMu must be locked.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) addPeer(mnt *Mount, new *Mount) {
	mnt.sharedEntry.Add(&new.sharedEntry)
	new.isShared = true
	new.groupID = mnt.groupID
}

// preparePropagationTree returns a mapping of propagated mounts to their future
// mountpoints. The new mounts are clones of mnt and are added to mnt's peer
// group if vd.mount and mnt are shared. All the cloned mounts and new
// mountpoints in the tree have an extra reference taken.
//
// +checklocks:vfs.mountMu
// +checklocksalias:mnt.vfs.mountMu=vfs.mountMu
func (vfs *VirtualFilesystem) preparePropagationTree(mnt *Mount, vd VirtualDentry) map[*Mount]VirtualDentry {
	tree := map[*Mount]VirtualDentry{}
	if !vd.mount.isShared {
		return tree
	}
	if !mnt.isShared {
		vfs.setPropagation(mnt, linux.MS_SHARED)
	}
	for peer := vd.mount.sharedEntry.Next(); peer != vd.mount; peer = peer.sharedEntry.Next() {
		// Skip newly added (disconnected) mounts.
		if peer.ns == nil {
			continue
		}
		peerVd := VirtualDentry{
			mount:  peer,
			dentry: vd.dentry,
		}
		peerVd.IncRef()
		clone := vfs.cloneMount(mnt, mnt.root, nil)
		tree[clone] = peerVd
	}
	return tree
}

// commitPropagationTree attaches to mounts in tree to the mountpoints they
// are mapped to. If there is an error attaching a mount, the method panics.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) commitPropagationTree(ctx context.Context, tree map[*Mount]VirtualDentry) {
	// The peer mounts should have no way of being dead if we've reached this
	// point so its safe to connect without checks.
	for mnt, vd := range tree {
		// If there is already a mount at this (parent, point), disconnect it and
		// reconnect it to the new mount once it is connected.
		vd.dentry.mu.Lock()
		child := vfs.mounts.Lookup(vd.mount, vd.dentry)
		vfs.mounts.seq.BeginWrite()
		if child != nil {
			vfs.delayDecRef(vfs.disconnectLocked(child))
		}
		vfs.connectLocked(mnt, vd, vd.mount.ns)
		vfs.delayDecRef(mnt)

		if child != nil {
			newmp := VirtualDentry{mnt, mnt.root}
			newmp.IncRef()
			vfs.connectLocked(child, newmp, newmp.mount.ns)
			vfs.delayDecRef(child)
		}
		vfs.mounts.seq.EndWrite()
		vd.dentry.mu.Unlock()
	}
}

// abortPropagationTree releases any references held by the mounts and
// mountpoints in the tree and removes the mounts from their peer groups.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) abortPropagationTree(ctx context.Context, tree map[*Mount]VirtualDentry) {
	for mnt, vd := range tree {
		vfs.delayDecRef(vd)
		vfs.delayDecRef(mnt)
		vfs.setPropagation(mnt, linux.MS_PRIVATE)
	}
}

// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) commitPendingTree(ctx context.Context, mnt *Mount) {
	for _, c := range mnt.pendingChildren {
		vfs.commitTree(ctx, c)
	}
	mnt.pendingChildren = nil
}

// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) commitTree(ctx context.Context, mnt *Mount) {
	mp := mnt.getKey()

	// If there is already a mount at this (parent, point), disconnect it from its
	// parent and reconnect it to mnt once mnt has been connected.
	child := vfs.mounts.Lookup(mp.mount, mp.dentry)
	vfs.mounts.seq.BeginWrite()
	if child != nil {
		vfs.delayDecRef(vfs.disconnectLocked(child))
	}
	vfs.connectLocked(mnt, mp, mp.mount.ns)
	vfs.delayDecRef(mnt)

	if child != nil {
		newmp := VirtualDentry{mnt, mnt.root}
		newmp.IncRef()
		vfs.connectLocked(child, newmp, newmp.mount.ns)
		vfs.delayDecRef(child)
	}
	vfs.mounts.seq.EndWrite()
	vfs.commitPendingTree(ctx, mnt)
}

// abortTree releases references on a pending mount and all its pending
// descendants.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) abortTree(ctx context.Context, mnt *Mount) {
	vfs.delayDecRef(mnt)
	vfs.delayDecRef(mnt.getKey())
	mnt.setKey(VirtualDentry{})
	vfs.setPropagation(mnt, linux.MS_PRIVATE)
	for _, c := range mnt.pendingChildren {
		vfs.abortTree(ctx, c)
	}
	mnt.pendingChildren = nil
}

// SetMountPropagationAt changes the propagation type of the mount pointed to by
// pop.
func (vfs *VirtualFilesystem) SetMountPropagationAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, propFlags uint32) error {
	// Check if flags is a power of 2. If not then more than one flag is set.
	if !bits.IsPowerOfTwo32(propFlags) {
		return linuxerr.EINVAL
	}
	vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
	if err != nil {
		return err
	}
	// See the similar defer in UmountAt for why this is in a closure.
	defer func() {
		vd.DecRef(ctx)
	}()
	if vd.dentry.isMounted() {
		if realmnt := vfs.getMountAt(ctx, vd.mount, vd.dentry); realmnt != nil {
			vd.mount.DecRef(ctx)
			vd.mount = realmnt
		}
	} else if vd.dentry != vd.mount.root {
		return linuxerr.EINVAL
	}
	vfs.SetMountPropagation(vd.mount, propFlags)
	return nil
}

// SetMountPropagation changes the propagation type of the mount.
func (vfs *VirtualFilesystem) SetMountPropagation(mnt *Mount, propFlags uint32) {
	vfs.lockMounts()
	defer vfs.unlockMounts(context.Background())
	if propFlags&(linux.MS_SHARED|linux.MS_PRIVATE) != 0 {
		vfs.setPropagation(mnt, propFlags)
	} else {
		panic(fmt.Sprintf("unsupported propagation type: %s", propTypeToString(propFlags)))
	}
}
