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
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const (
	// The following constants are possible bits for the cloneType argument to
	// VirtualFilesystem.cloneMount() and related functions.
	// Analogous to CL_MAKE_SHARED in Linux.
	makeSharedClone = 1 << iota
	// Analogous to CL_SLAVE in Linux.
	makeFollowerClone
	// Analogous to CL_PRIVATE in Linux.
	makePrivateClone
	// Analogous to CL_SHARED_TO_SLAVE in Linux.
	sharedToFollowerClone
)

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
func (vfs *VirtualFilesystem) SetMountPropagation(mnt *Mount, propFlags uint32) error {
	vfs.lockMounts()
	defer vfs.unlockMounts(context.Background())
	if propFlags == linux.MS_SHARED {
		if err := vfs.allocMountGroupIDs(mnt, false); err != nil {
			return fmt.Errorf("allocMountGroupIDs: %v", err)
		}
	}
	vfs.setPropagation(mnt, propFlags)
	return nil
}

// setPropagation sets the propagation on mnt for a propagation type. This
// method is analogous to fs/pnode.c:change_mnt_propagation() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) setPropagation(mnt *Mount, propFlags uint32) {
	if propFlags == linux.MS_SHARED {
		mnt.isShared = true
		return
	}
	// pflag is MS_PRIVATE, MS_SLAVE, or MS_UNBINDABLE. The algorithm is the same
	// for MS_PRIVATE/MS_SLAVE/MS_UNBINDABLE, except that in the
	// private/unbindable case we clear the leader and followerEntry after the
	// procedure is finished.
	var leader *Mount
	if mnt.sharedEntry.Empty() {
		// If mnt is shared and in a peer group with only itself, just make it
		// private.
		if mnt.isShared {
			vfs.freeGroupID(mnt)
			mnt.isShared = false
		}
		// If mnt is not a follower to any other mount, make all of its followers
		// also private.
		leader = mnt.leader
		if leader == nil {
			for !mnt.followerList.Empty() {
				f := mnt.followerList.Front()
				mnt.followerList.Remove(f)
				f.leader = nil
			}
		}
	} else {
		// Pick a suitable new leader. Linux chooses the first peer that shares a
		// root dentry, or any peer if none matches that criteria.
		leader = mnt.sharedEntry.Next()
		for m := mnt.sharedEntry.Next(); m != mnt; m = m.sharedEntry.Next() {
			if m.root == mnt.root {
				leader = m
				break
			}
		}
		// Clear out mnt's shared attributes.
		mnt.sharedEntry.Remove()
		mnt.groupID = 0
		mnt.isShared = false
	}
	// Transfer all of mnt's followers to the new leader.
	for f := mnt.followerList.Front(); f != nil; f = f.followerEntry.Next() {
		f.leader = leader
	}
	// Remove mnt from its current follower list and add it to the new leader.
	if mnt.leader != nil {
		mnt.leader.followerList.Remove(mnt)
	}
	if leader != nil && propFlags == linux.MS_SLAVE {
		leader.followerList.PushFront(mnt)
		mnt.leader = leader
	} else {
		mnt.leader = nil
	}

	// Add mnts followers to leader's follower list. This also links all their
	// followerEntry together.
	if !mnt.followerList.Empty() && leader != nil {
		leader.followerList.PushBackList(&mnt.followerList)
	}
}

type propState struct {
	origSrc        *Mount
	prevSrc        *Mount
	prevDst        *Mount
	dstLeader      *Mount
	propList       map[*Mount]struct{}
	visitedLeaders map[*Mount]struct{}
}

// doPropagation returns a list of propagated mounts with their mount points
// set. The  mounts are clones of src and have an extra reference taken. If
// propagation fails at any point, the method returns all the mounts propagated
// up until that point so they can be properly released. This method is
// analogous to fs/pnode.c:propagate_mnt() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) doPropagation(ctx context.Context, src *Mount, dst VirtualDentry) (map[*Mount]struct{}, error) {
	if !dst.mount.isShared {
		return nil, nil
	}
	s := propState{
		origSrc:        src,
		prevSrc:        src,
		prevDst:        dst.mount,
		dstLeader:      dst.mount.leader,
		propList:       map[*Mount]struct{}{},
		visitedLeaders: map[*Mount]struct{}{},
	}
	for peer := dst.mount.sharedEntry.Next(); peer != dst.mount; peer = peer.sharedEntry.Next() {
		if err := vfs.propagateMount(ctx, peer, dst.dentry, &s); err != nil {
			return s.propList, err
		}
	}
	for follower := nextFollowerPeerGroup(dst.mount, dst.mount); follower != nil; follower = nextFollowerPeerGroup(follower, dst.mount) {
		peer := follower
		for {
			if err := vfs.propagateMount(ctx, peer, dst.dentry, &s); err != nil {
				return s.propList, err
			}
			peer = peer.sharedEntry.Next()
			if peer == follower {
				break
			}
		}
	}
	return s.propList, nil
}

// peers returns if two mounts are in the same peer group.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) peers(m1, m2 *Mount) bool {
	return m1.groupID == m2.groupID && m1.groupID != 0
}

// propagateMount propagates state.srcMount to dstMount at dstPoint.
// This method is analogous to fs/pnode.c:propagate_one() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) propagateMount(ctx context.Context, dstMnt *Mount, dstPoint *Dentry, state *propState) error {
	// Skip newly added mounts.
	if dstMnt.neverConnected() {
		return nil
	}
	mp := VirtualDentry{mount: dstMnt, dentry: dstPoint}
	if !mp.mount.fs.Impl().IsDescendant(VirtualDentry{dstMnt, dstMnt.root}, mp) {
		return nil
	}
	cloneType := 0
	if vfs.peers(dstMnt, state.prevDst) {
		cloneType = makeSharedClone
	} else {
		done := false
		// Get the most recent leader that we've propagated from in the tree.
		var leader, underLeader *Mount
		for underLeader = dstMnt; ; underLeader = leader {
			leader = underLeader.leader
			if _, ok := state.visitedLeaders[leader]; ok {
				break
			}
			if leader == state.dstLeader {
				break
			}
		}
		for {
			parent := state.prevSrc.parent()
			// Check that prevSrc is a follower, not a peer of the original.
			if vfs.peers(state.prevSrc, state.origSrc) {
				break
			}
			// Check if the mount prvSrc attached to (aka parent) has the same leader
			// as the most recently visited leader in the mount tree.
			done = parent.leader == leader
			// If the leader under the most recently visited leader is not peers with
			// the mount prevSrc attached to, then it's not part of this propagation
			// tree and we need to traverse up the tree to get to the real src.
			if done && vfs.peers(underLeader, parent) {
				break
			}
			// Traverse back up the propagation tree to get the proper src. We only
			// want to propagate from this mount's leader or peers of that leader.
			state.prevSrc = state.prevSrc.leader
			if done {
				break
			}
		}
		cloneType = makeFollowerClone
		if dstMnt.isShared {
			cloneType |= makeSharedClone
		}
	}
	clone, err := vfs.cloneMount(state.prevSrc, state.prevSrc.root, nil, cloneType)
	if err != nil {
		return err
	}
	mp.IncRef()
	clone.setKey(mp)
	state.propList[clone] = struct{}{}
	if dstMnt.leader != state.dstLeader {
		state.visitedLeaders[dstMnt.leader] = struct{}{}
	}
	state.prevDst = dstMnt
	state.prevSrc = clone
	if uint32(len(state.propList))+dstMnt.ns.mounts > MountMax {
		return linuxerr.ENOSPC
	}
	return nil
}

// nextFollowerPeerGroup iterates through the propagation tree and returns the
// first mount in each follower peer group under mnt. Once all the groups
// have been iterated through the method returns nil. This method is analogous
// to fs/pnode.c:next_group() in Linux.
func nextFollowerPeerGroup(mnt *Mount, start *Mount) *Mount {
	for {
		// If mnt has any followers, this loop returns that follower. Otherwise mnt
		// is updated until it is the last peer in its peer group. This has the
		// effect of moving down the propagation tree until the bottommost follower.
		// After that the loop moves across peers (if possible) to the last peer
		// in the group.
		for {
			if !mnt.neverConnected() && !mnt.followerList.Empty() {
				return mnt.followerList.Front()
			}
			next := mnt.sharedEntry.Next()
			if mnt.groupID == start.groupID {
				if next == start {
					return nil
				}
				// If mnt is shared+slave, its next follower will be the same as its
				// next peer.
			} else if mnt.isFollower() && mnt.followerEntry.Next() != next {
				break
			}
			mnt = next
		}
		// At this point mnt is the last peer in its shared+slave peer group.
		// This loop returns the next follower in mnt's leader's follower list. Once
		// the list of followers is exhausted it sets mnt to be the leader and
		// breaks out of the loop. This has the effect of moving across the tree
		// branches until all branches are exhausted. Then it moves up the tree to
		// the parent.
		for {
			leader := mnt.leader
			if mnt.followerEntry.Next() != nil {
				return mnt.followerEntry.Next()
			}
			mnt = leader.sharedEntry.Next()
			if leader.groupID == start.groupID {
				break
			}
			if leader.followerEntry.Next() == mnt {
				break
			}
			mnt = leader
		}
		if mnt == start {
			return nil
		}
	}
}

// nextPropMount iterates through the propagation tree rooted at start. It
// returns nil when there are no more mounts in the tree. Otherwise, it returns
// the next mount in the tree. It is analogous to fs/pnode.c:propagation_next()
// in Linux.
func nextPropMount(mnt, start *Mount) *Mount {
	m := mnt
	if !m.neverConnected() && !m.followerList.Empty() {
		return m.followerList.Front()
	}
	for {
		leader := m.leader
		if leader == start.leader {
			next := m.sharedEntry.Next()
			if next == start {
				return nil
			}
			return next
		} else if m.followerEntry.Next() != nil {
			return m.followerEntry.Next()
		}
		m = leader
	}
}

// arePropMountsBusy checks if all the mounts that mnt's parents propagate to
// have the correct number of references before a call to umount. It is
// analogous to fs/pnode.c:propagate_mount_busy() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) arePropMountsBusy(mnt *Mount) bool {
	parent := mnt.parent()
	if parent == nil {
		return !vfs.mountHasExpectedRefs(mnt)
	}
	if len(mnt.children) != 0 || !vfs.mountHasExpectedRefs(mnt) {
		return true
	}
	for m := nextPropMount(parent, parent); m != nil; m = nextPropMount(m, parent) {
		child := vfs.mounts.Lookup(m, mnt.point())
		if child == nil {
			continue
		}
		if len(child.children) != 0 && child.coveringMount() == nil {
			continue
		}
		if !vfs.mountHasExpectedRefs(child) {
			return true
		}
	}
	return false
}

// allocateGroupID returns a new mount group id if one is available, and
// error otherwise. If the group ID bitmap is full, double the size of the
// bitmap before allocating the new group id. It is analogous to
// fs/namespace.c:mnt_alloc_group_id() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) allocateGroupID() (uint32, error) {
	groupID, err := vfs.groupIDBitmap.FirstZero(1)
	if err != nil {
		if err := vfs.groupIDBitmap.Grow(uint32(vfs.groupIDBitmap.Size())); err != nil {
			return 0, err
		}
	}
	vfs.groupIDBitmap.Add(groupID)
	return groupID, nil
}

// freeGroupID marks a groupID as available for reuse. It is analogous to
// fs/namespace.c:mnt_release_group_id() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) freeGroupID(mnt *Mount) {
	vfs.groupIDBitmap.Remove(mnt.groupID)
	mnt.groupID = 0
}

// freeMountGroupIDs zeroes out all of the mounts' groupIDs and returns them
// to the pool of available ids. It is analogous to
// fs/namespace.c:cleanup_group_ids() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) freeMountGroupIDs(mnts []*Mount) {
	for _, m := range mnts {
		if m.groupID != 0 && m.isShared {
			vfs.freeGroupID(m)
		}
	}
}

// allocMountGroupIDs allocates a new group id for mnt. If recursive is true, it
// also allocates a new group id for all mounts children. It is analogous to
// fs/namespace.c:invent_group_ids() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) allocMountGroupIDs(mnt *Mount, recursive bool) error {
	var mnts []*Mount
	if recursive {
		mnts = mnt.submountsLocked()
	} else {
		mnts = []*Mount{mnt}
	}
	for _, m := range mnts {
		if m.groupID == 0 && !m.isShared {
			gid, err := vfs.allocateGroupID()
			m.groupID = gid
			if err != nil {
				vfs.freeMountGroupIDs(mnts)
				return err
			}
		}
	}
	return nil
}

// peerUnderRoot iterates through mnt's peers until it finds a mount that is in
// ns and is reachable from root. This method is analogous to
// fs/pnode.c:get_peer_under_root() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) peerUnderRoot(ctx context.Context, mnt *Mount, ns *MountNamespace, root VirtualDentry) *Mount {
	m := mnt
	for {
		if m.ns == ns {
			if vfs.isPathReachable(ctx, root, VirtualDentry{mnt, mnt.root}) {
				return m
			}
		}
		m = m.sharedEntry.Next()
		if m == mnt {
			break
		}
	}
	return nil
}

// isPathReachable returns true if vd is reachable from vfsroot. It is analogous
// to fs/namespace.c:is_path_reachable() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) isPathReachable(ctx context.Context, vfsroot VirtualDentry, vd VirtualDentry) bool {
	for vd.mount != vfsroot.mount && vd.mount.parent() != nil {
		vd = vd.mount.getKey()
	}
	return vd.mount == vfsroot.mount && vd.mount.fs.Impl().IsDescendant(vfsroot, vd)
}
