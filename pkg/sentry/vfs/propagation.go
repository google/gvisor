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

	propagationFlags = linux.MS_SHARED | linux.MS_PRIVATE | linux.MS_SLAVE | linux.MS_UNBINDABLE
)

// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) commitChildren(ctx context.Context, mnt *Mount) {
	for c := range mnt.children {
		if c.neverConnected() {
			vfs.commitMount(ctx, c)
		}
	}
}

// commitMount attaches mnt to the parent and mountpoint specified by its
// mountKey and recursively does the same for all of mnt's descendants.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) commitMount(ctx context.Context, mnt *Mount) {
	mp := mnt.getKey()

	// If there is already a mount at this (parent, point), disconnect it from its
	// parent and reconnect it to mnt once mnt has been connected.
	child := vfs.mounts.Lookup(mp.mount, mp.dentry)
	vfs.mounts.seq.BeginWrite()
	if child != nil {
		vfs.delayDecRef(vfs.disconnectLocked(child))
	}
	mp.dentry.mu.Lock()
	vfs.connectLocked(mnt, mp, mp.mount.ns)
	mp.dentry.mu.Unlock()
	vfs.delayDecRef(mnt)

	if child != nil {
		newmp := VirtualDentry{mnt, mnt.root}
		newmp.IncRef()
		newmp.dentry.mu.Lock()
		vfs.connectLocked(child, newmp, newmp.mount.ns)
		newmp.dentry.mu.Unlock()
		vfs.delayDecRef(child)
	}
	vfs.mounts.seq.EndWrite()
	vfs.commitChildren(ctx, mnt)
}

// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) abortUncomittedChildren(ctx context.Context, mnt *Mount) {
	for c := range mnt.children {
		if c.neverConnected() {
			vfs.abortUncommitedMount(ctx, c)
			delete(mnt.children, c)
		}
	}
}

// abortUncommitedMount releases references on mnt and all its descendants.
//
// Prerequisite: mnt is not connected, i.e. mnt.ns == nil.
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) abortUncommitedMount(ctx context.Context, mnt *Mount) {
	vfs.delayDecRef(mnt)
	vfs.delayDecRef(mnt.getKey())
	mnt.setKey(VirtualDentry{})
	vfs.setPropagation(mnt, linux.MS_PRIVATE)
	vfs.abortUncomittedChildren(ctx, mnt)
}

// SetMountPropagationAt changes the propagation type of the mount pointed to by
// pop.
func (vfs *VirtualFilesystem) SetMountPropagationAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, propFlag uint32) error {
	recursive := propFlag&linux.MS_REC != 0
	propFlag &= propagationFlags
	// Check if flags is a power of 2. If not then more than one flag is set.
	if !bits.IsPowerOfTwo32(propFlag) {
		return linuxerr.EINVAL
	}
	vd, err := vfs.getMountpoint(ctx, creds, pop)
	if err != nil {
		return err
	}
	defer vd.DecRef(ctx)
	vfs.SetMountPropagation(vd.mount, propFlag, recursive)
	return nil
}

// SetMountPropagation changes the propagation type of the mount.
func (vfs *VirtualFilesystem) SetMountPropagation(mnt *Mount, propFlag uint32, recursive bool) error {
	vfs.lockMounts()
	defer vfs.unlockMounts(context.Background())
	if propFlag == linux.MS_SHARED {
		if err := vfs.allocMountGroupIDs(mnt, recursive); err != nil {
			return err
		}
	}

	if !recursive {
		vfs.setPropagation(mnt, propFlag)
		return nil
	}
	for _, m := range mnt.submountsLocked() {
		vfs.setPropagation(m, propFlag)
	}
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
	if dstMnt.neverConnected() || dstMnt.umounted {
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
	clone, err := vfs.cloneMountTree(ctx, state.prevSrc, state.prevSrc.root, cloneType, nil)
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
	return dstMnt.ns.checkMountCount(ctx, clone)
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

// allocateGroupID populates mnt.groupID with a new group id if one is
// available, and returns an error otherwise. If the group ID bitmap is full,
// double the size of the bitmap before allocating the new group id. It is
// analogous to fs/namespace.c:mnt_alloc_group_id() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) allocateGroupID(mnt *Mount) error {
	groupID, err := vfs.groupIDBitmap.FirstZero(1)
	if err != nil {
		if err := vfs.groupIDBitmap.Grow(uint32(vfs.groupIDBitmap.Size())); err != nil {
			return linuxerr.ENOSPC
		}
		groupID, err = vfs.groupIDBitmap.FirstZero(1)
		if err != nil {
			return err
		}
	}
	vfs.groupIDBitmap.Add(groupID)
	mnt.groupID = groupID
	return nil
}

// freeGroupID marks a groupID as available for reuse. It is analogous to
// fs/namespace.c:mnt_release_group_id() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) freeGroupID(mnt *Mount) {
	vfs.groupIDBitmap.Remove(mnt.groupID)
	mnt.groupID = 0
}

// cleanupGroupIDs zeroes out all of the mounts' groupIDs and returns them
// to the pool of available ids. It is analogous to
// fs/namespace.c:cleanup_group_ids() in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) cleanupGroupIDs(mnts []*Mount) {
	for _, m := range mnts {
		if m.groupID != 0 && !m.isShared {
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
			if err := vfs.allocateGroupID(m); err != nil {
				vfs.cleanupGroupIDs(mnts)
				return err
			}
		}
	}
	return nil
}

// propagateUmount returns a list of mounts that the umount of mnts propagates
// to.
//
// Prerequisites: all the mounts in mnts have had vfs.umount() called on them.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) propagateUmount(mnts []*Mount) []*Mount {
	const (
		umountVisited = iota
		umountRestore
	)
	var toUmount []*Mount
	noChildren := make(map[*Mount]struct{})
	// Processed contains all the mounts that the algorithm has processed so far.
	// If the mount maps to umountRestore, it should be restored after processing
	// all the mounts. This happens in cases where a mount was speculatively
	// unmounted that had children or is a cover mount.
	processed := make(map[*Mount]int)

	// Iterate through the mounts from the leafs back to the root.
	for i := len(mnts) - 1; i >= 0; i-- {
		mnt := mnts[i]

		// If a mount has already been visited we know all its peers and followers
		// have been visited so there's no need to visit them again.
		if _, ok := processed[mnt]; ok {
			continue
		}
		processed[mnt] = umountVisited

		parent := mnt.parent()
		if parent == nil {
			continue
		}
		for m := nextPropMount(parent, parent); m != nil; m = nextPropMount(m, parent) {
			child := vfs.mounts.Lookup(m, mnt.point())
			if child == nil {
				continue
			}
			if _, ok := processed[child]; ok {
				// If the child has been visited we know its peer group and followers
				// have all been visited so there's no need to visit them again. We can
				// skip this propagation subtree by setting the iterator to be the last
				// mount in the follower group.
				if !child.followerList.Empty() {
					m = child.followerList.Back()
				}
				continue
			} else if child.umounted {
				// If this child has already been marked for unmounting, just mark it
				// as visited and move on. This means it was either part of the original
				// mount list passed to this method or was umounted from another mount's
				// propagation. In either case we can consider all its peers and
				// followers as visited.
				processed[child] = umountVisited
				continue
			}

			// This loop starts at the child we are propagating the umount to and
			// iterates through the child's parents. It continues as until it
			// encounters a parent that's been visited.
		loop:
			for {
				if _, ok := noChildren[child]; ok || child.umounted {
					break
				}
				// If there are any children that have mountpoint != parent's root then
				// the current mount cannot be unmounted.
				for gchild := range child.children {
					if gchild.point() == child.root {
						continue
					}
					_, isProcessed := processed[gchild]
					_, hasNoChildren := noChildren[gchild]
					if isProcessed && hasNoChildren {
						continue
					}
					processed[child] = umountRestore
					break loop
				}
				if child.locked {
					processed[child] = umountRestore
					noChildren[child] = struct{}{}
				} else {
					vfs.umount(child)
					toUmount = append(toUmount, child)
				}
				// If this parent was a mount that had to be restored because it had
				// children, it might be safe to umount now that its child is gone. If
				// it has been visited then it's already being umounted.
				child = child.parent()
				if _, ok := processed[child]; !ok {
					break
				}
			}
		}
	}

	// Add all the children of mounts marked for umount to the umount list. This
	// excludes "cover" mounts (mounts whose mount point is equal to their
	// parent's root) which will be reparented in the next step.
	for i := 0; i < len(toUmount); i++ {
		umount := toUmount[i]
		for child := range umount.children {
			if child.point() == umount.root {
				processed[child] = umountRestore
			} else {
				vfs.umount(child)
				toUmount = append(toUmount, child)
			}
		}
	}

	vfs.mounts.seq.BeginWrite()
	for m, status := range processed {
		if status == umountVisited {
			continue
		}
		mp := m.getKey()
		for mp.mount.umounted {
			mp = mp.mount.getKey()
		}
		if mp != m.getKey() {
			vfs.changeMountpoint(m, mp)
		}
	}
	vfs.mounts.seq.EndWrite()

	return toUmount
}

// unlockPropagationMounts sets locked to false for every mount that a umount
// of mnt propagates to. It is analogous to fs/pnode.c:propagate_mount_unlock()
// in Linux.
//
// +checklocks:vfs.mountMu
func (vfs *VirtualFilesystem) unlockPropagationMounts(mnt *Mount) {
	parent := mnt.parent()
	if parent == nil {
		return
	}
	for m := nextPropMount(parent, parent); m != nil; m = nextPropMount(m, parent) {
		child := vfs.mounts.Lookup(m, mnt.point())
		if child == nil {
			continue
		}
		child.locked = false
	}
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
