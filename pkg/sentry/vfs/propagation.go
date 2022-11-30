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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// PropagationType is a propagation flavor as described in
// https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt. Child
// and Unbindable are currently unimplemented.
// TODO(b/249777195): Support MS_SLAVE and MS_UNBINDABLE propagation types.
type PropagationType int

const (
	// Unknown represents an invalid/unknown propagation type.
	Unknown PropagationType = iota
	// Shared represents the shared propagation type.
	Shared
	// Private represents the private propagation type.
	Private
	// Child represents the child propagation type (MS_SLAVE).
	Child
	// Unbindable represents the unbindable propagation type.
	Unbindable
)

// PropagationTypeFromLinux returns the PropagationType corresponding to a
// linux mount flag, aka MS_SHARED.
func PropagationTypeFromLinux(propFlag uint64) PropagationType {
	switch propFlag {
	case linux.MS_SHARED:
		return Shared
	case linux.MS_PRIVATE:
		return Private
	case linux.MS_SLAVE:
		return Child
	case linux.MS_UNBINDABLE:
		return Unbindable
	default:
		return Unknown
	}
}

// setPropagation sets the propagation on mnt for a propagation type.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) setPropagation(mnt *Mount, ptype PropagationType) error {
	switch ptype {
	case Shared:
		id, err := vfs.allocateGroupID()
		if err != nil {
			return err
		}
		mnt.groupID = id
		mnt.sharedList = &sharedList{}
		mnt.sharedList.PushBack(mnt)
	case Private:
		if mnt.propType == Shared {
			mnt.sharedList.Remove(mnt)
			if mnt.sharedList.Empty() {
				vfs.freeGroupID(mnt.groupID)
			}
			mnt.sharedList = nil
			mnt.groupID = 0
		}
	default:
		panic(fmt.Sprintf("unsupported propagation type: %v", ptype))
	}
	mnt.propType = ptype
	return nil
}

// addPeer adds oth to mnt's peer group. Both will have the same groupID
// and sharedList. vfs.mountMu must be locked.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) addPeer(mnt *Mount, oth *Mount) {
	mnt.sharedList.PushBack(oth)
	oth.sharedList = mnt.sharedList
	oth.propType = mnt.propType
	oth.groupID = mnt.groupID
}

// mergePeerGroup merges oth and all its peers into mnt's peer group. Oth
// must have propagation type shared and vfs.mountMu must be locked.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) mergePeerGroup(mnt *Mount, oth *Mount) {
	peer := oth.sharedList.Front()
	for peer != nil {
		next := peer.sharedEntry.Next()
		vfs.setPropagation(peer, Private)
		vfs.addPeer(mnt, peer)
		peer = next
	}
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
	if vd.mount.propType == Private {
		return tree
	}
	if mnt.propType == Private {
		vfs.setPropagation(mnt, Shared)
	}
	var newPeerGroup []*Mount
	for peer := vd.mount.sharedList.Front(); peer != nil; peer = peer.sharedEntry.Next() {
		if peer == vd.mount {
			continue
		}
		peerVd := VirtualDentry{
			mount:  peer,
			dentry: vd.dentry,
		}
		peerVd.IncRef()
		clone := vfs.cloneMount(mnt, mnt.root, nil)
		tree[clone] = peerVd
		newPeerGroup = append(newPeerGroup, clone)
	}
	for _, newPeer := range newPeerGroup {
		vfs.addPeer(mnt, newPeer)
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
	vfs.mounts.seq.BeginWrite()
	for mnt, vd := range tree {
		vd.dentry.mu.Lock()
		// If mnt isn't connected yet, skip connecting during propagation.
		if mntns := vd.mount.ns; mntns != nil {
			vfs.connectLocked(mnt, vd, mntns)
		}
		vd.dentry.mu.Unlock()
		mnt.DecRef(ctx)
	}
	vfs.mounts.seq.EndWrite()
}

// abortPropagationTree releases any references held by the mounts and
// mountpoints in the tree and removes the mounts from their peer groups.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) abortPropagationTree(ctx context.Context, tree map[*Mount]VirtualDentry) {
	for mnt, vd := range tree {
		vd.DecRef(ctx)
		vfs.setPropagation(mnt, Private)
		mnt.DecRef(ctx)
	}
}

// SetMountPropagationAt changes the propagation type of the mount pointed to by
// pop.
func (vfs *VirtualFilesystem) SetMountPropagationAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, propType PropagationType) error {
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
	vfs.SetMountPropagation(vd.mount, propType)
	return nil
}

// SetMountPropagation changes the propagation type of the mount.
func (vfs *VirtualFilesystem) SetMountPropagation(mnt *Mount, propType PropagationType) {
	vfs.mountMu.Lock()
	defer vfs.mountMu.Unlock()
	if propType != mnt.propType {
		switch propType {
		case Shared, Private:
			vfs.setPropagation(mnt, propType)
		default:
			panic(fmt.Sprintf("unsupported propagation type: %v", propType))
		}
	}
	mnt.propType = propType
}
