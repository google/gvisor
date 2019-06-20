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

package fs

import (
	"fmt"
	"math"
	"path"
	"strings"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

// DefaultTraversalLimit provides a sensible default traversal limit that may
// be passed to FindInode and FindLink. You may want to provide other options in
// individual syscall implementations, but for internal functions this will be
// sane.
const DefaultTraversalLimit = 10

const invalidMountID = math.MaxUint64

// Mount represents a mount in the file system. It holds the root dirent for the
// mount. It also points back to the dirent or mount where it was mounted over,
// so that it can be restored when unmounted. The chained mount can be either:
//   - Mount: when it's mounted on top of another mount point.
//   - Dirent: when it's mounted on top of a dirent. In this case the mount is
//     called an "undo" mount and only 'root' is set. All other fields are
//     either invalid or nil.
//
// +stateify savable
type Mount struct {
	// ID is a unique id for this mount. It may be invalidMountID if this is
	// used to cache a dirent that was mounted over.
	ID uint64

	// ParentID is the parent's mount unique id. It may be invalidMountID if this
	// is the root mount or if this is used to cache a dirent that was mounted
	// over.
	ParentID uint64

	// root is the root Dirent of this mount. A reference on this Dirent must be
	// held through the lifetime of the Mount which contains it.
	root *Dirent

	// previous is the existing dirent or mount that this object was mounted over.
	// It's nil for the root mount and for the last entry in the chain (always an
	// "undo" mount).
	previous *Mount
}

// newMount creates a new mount, taking a reference on 'root'. Caller must
// release the reference when it's done with the mount.
func newMount(id, pid uint64, root *Dirent) *Mount {
	root.IncRef()
	return &Mount{
		ID:       id,
		ParentID: pid,
		root:     root,
	}
}

// newRootMount creates a new root mount (no parent), taking a reference on
// 'root'. Caller must release the reference when it's done with the mount.
func newRootMount(id uint64, root *Dirent) *Mount {
	root.IncRef()
	return &Mount{
		ID:       id,
		ParentID: invalidMountID,
		root:     root,
	}
}

// newUndoMount creates a new undo mount, taking a reference on 'd'. Caller must
// release the reference when it's done with the mount.
func newUndoMount(d *Dirent) *Mount {
	d.IncRef()
	return &Mount{
		ID:       invalidMountID,
		ParentID: invalidMountID,
		root:     d,
	}
}

// Root returns the root dirent of this mount. Callers must call DecRef on the
// returned dirent.
func (m *Mount) Root() *Dirent {
	m.root.IncRef()
	return m.root
}

// IsRoot returns true if the mount has no parent.
func (m *Mount) IsRoot() bool {
	return !m.IsUndo() && m.ParentID == invalidMountID
}

// IsUndo returns true if 'm' is an undo mount that should be used to restore
// the original dirent during unmount only and it's not a valid mount.
func (m *Mount) IsUndo() bool {
	if m.ID == invalidMountID {
		if m.ParentID != invalidMountID {
			panic(fmt.Sprintf("Undo mount with valid parentID: %+v", m))
		}
		return true
	}
	return false
}

// MountNamespace defines a VFS root. It contains collection of Mounts that are
// mounted inside the Dirent tree rooted at the Root Dirent. It provides
// methods for traversing the Dirent, and for mounting/unmounting in the tree.
//
// Note that this does not correspond to a "mount namespace" in the Linux. It
// is more like a unique VFS instance.
//
// It's possible for different processes to have different MountNamespaces. In
// this case, the file systems exposed to the processes are completely
// distinct.
//
// +stateify savable
type MountNamespace struct {
	refs.AtomicRefCount

	// userns is the user namespace associated with this mount namespace.
	//
	// All privileged operations on this mount namespace must have
	// appropriate capabilities in this userns.
	//
	// userns is immutable.
	userns *auth.UserNamespace

	// root is the root directory.
	root *Dirent

	// mu protects mounts and mountID counter.
	mu sync.Mutex `state:"nosave"`

	// mounts is a map of mounted Dirent -> Mount object. There are three
	// possible cases:
	//   - Dirent is mounted over a mount point: the stored Mount object will be
	//     the Mount for that mount point.
	//   - Dirent is mounted over a regular (non-mount point) Dirent: the stored
	//     Mount object will be an "undo" mount containing the mounted-over
	//     Dirent.
	//   - Dirent is the root mount: the stored Mount object will be a root mount
	//     containing the Dirent itself.
	mounts map[*Dirent]*Mount

	// mountID is the next mount id to assign.
	mountID uint64
}

// NewMountNamespace returns a new MountNamespace, with the provided node at the
// root, and the given cache size. A root must always be provided.
func NewMountNamespace(ctx context.Context, root *Inode) (*MountNamespace, error) {
	creds := auth.CredentialsFromContext(ctx)

	// Set the root dirent and id on the root mount. The reference returned from
	// NewDirent will be donated to the MountNamespace constructed below.
	d := NewDirent(ctx, root, "/")

	mnts := map[*Dirent]*Mount{
		d: newRootMount(1, d),
	}

	return &MountNamespace{
		userns:  creds.UserNamespace,
		root:    d,
		mounts:  mnts,
		mountID: 2,
	}, nil
}

// UserNamespace returns the user namespace associated with this mount manager.
func (mns *MountNamespace) UserNamespace() *auth.UserNamespace {
	return mns.userns
}

// Root returns the MountNamespace's root Dirent and increments its reference
// count.  The caller must call DecRef when finished.
func (mns *MountNamespace) Root() *Dirent {
	mns.root.IncRef()
	return mns.root
}

// FlushMountSourceRefs flushes extra references held by MountSources for all active mount points;
// see fs/mount.go:MountSource.FlushDirentRefs.
func (mns *MountNamespace) FlushMountSourceRefs() {
	mns.mu.Lock()
	defer mns.mu.Unlock()
	mns.flushMountSourceRefsLocked()
}

func (mns *MountNamespace) flushMountSourceRefsLocked() {
	// Flush mounts' MountSource references.
	for _, mp := range mns.mounts {
		for ; mp != nil; mp = mp.previous {
			mp.root.Inode.MountSource.FlushDirentRefs()
		}
	}

	// Flush root's MountSource references.
	mns.root.Inode.MountSource.FlushDirentRefs()
}

// destroy drops root and mounts dirent references and closes any original nodes.
//
// After destroy is called, the MountNamespace may continue to be referenced (for
// example via /proc/mounts), but should free all resources and shouldn't have
// Find* methods called.
func (mns *MountNamespace) destroy() {
	mns.mu.Lock()
	defer mns.mu.Unlock()

	// Flush all mounts' MountSource references to Dirents. This allows for mount
	// points to be torn down since there should be no remaining references after
	// this and DecRef below.
	mns.flushMountSourceRefsLocked()

	// Teardown mounts.
	for _, mp := range mns.mounts {
		// Drop the mount reference on all mounted dirents.
		for ; mp != nil; mp = mp.previous {
			mp.root.DecRef()
		}
	}
	mns.mounts = nil

	// Drop reference on the root.
	mns.root.DecRef()

	// Wait for asynchronous work (queued by dropping Dirent references
	// above) to complete before destroying this MountNamespace.
	AsyncBarrier()
}

// DecRef implements RefCounter.DecRef with destructor mns.destroy.
func (mns *MountNamespace) DecRef() {
	mns.DecRefWithDestructor(mns.destroy)
}

// Freeze freezes the entire mount tree.
func (mns *MountNamespace) Freeze() {
	mns.mu.Lock()
	defer mns.mu.Unlock()

	// We only want to freeze Dirents with active references, not Dirents referenced
	// by a mount's MountSource.
	mns.flushMountSourceRefsLocked()

	// Freeze the entire shebang.
	mns.root.Freeze()
}

// withMountLocked prevents further walks to `node`, because `node` is about to
// be a mount point.
func (mns *MountNamespace) withMountLocked(node *Dirent, fn func() error) error {
	mns.mu.Lock()
	defer mns.mu.Unlock()

	renameMu.Lock()
	defer renameMu.Unlock()

	// Linux allows mounting over the root (?). It comes with a strange set
	// of semantics. We'll just not do this for now.
	if node.parent == nil {
		return syserror.EBUSY
	}

	// For both mount and unmount, we take this lock so we can swap out the
	// appropriate child in parent.children.
	//
	// For unmount, this also ensures that if `node` is a mount point, the
	// underlying mount's MountSource.direntRefs cannot increase by preventing
	// walks to node.
	node.parent.dirMu.Lock()
	defer node.parent.dirMu.Unlock()

	node.parent.mu.Lock()
	defer node.parent.mu.Unlock()

	// We need not take node.dirMu since we have parent.dirMu.

	// We need to take node.mu, so that we can check for deletion.
	node.mu.Lock()
	defer node.mu.Unlock()

	return fn()
}

// Mount mounts a `inode` over the subtree at `node`.
func (mns *MountNamespace) Mount(ctx context.Context, mountPoint *Dirent, inode *Inode) error {
	return mns.withMountLocked(mountPoint, func() error {
		replacement, err := mountPoint.mount(ctx, inode)
		if err != nil {
			return err
		}
		defer replacement.DecRef()

		// Set the mount's root dirent and id.
		parentMnt := mns.findMountLocked(mountPoint)
		childMnt := newMount(mns.mountID, parentMnt.ID, replacement)
		mns.mountID++

		// Drop mountPoint from its dirent cache.
		mountPoint.dropExtendedReference()

		// If mountPoint is already a mount, push mountPoint on the stack so it can
		// be recovered on unmount.
		if prev := mns.mounts[mountPoint]; prev != nil {
			childMnt.previous = prev
			mns.mounts[replacement] = childMnt
			delete(mns.mounts, mountPoint)
			return nil
		}

		// Was not already mounted, just add another mount point.
		childMnt.previous = newUndoMount(mountPoint)
		mns.mounts[replacement] = childMnt
		return nil
	})
}

// Unmount ensures no references to the MountSource remain and removes `node` from
// this subtree. The subtree formerly mounted in `node`'s place will be
// restored. node's MountSource will be destroyed as soon as the last reference to
// `node` is dropped, as no references to Dirents within will remain.
//
// If detachOnly is set, Unmount merely removes `node` from the subtree, but
// allows existing references to the MountSource remain. E.g. if an open file still
// refers to Dirents in MountSource, the Unmount will succeed anyway and MountSource will
// be destroyed at a later time when all references to Dirents within are
// dropped.
//
// The caller must hold a reference to node from walking to it.
func (mns *MountNamespace) Unmount(ctx context.Context, node *Dirent, detachOnly bool) error {
	// This takes locks to prevent further walks to Dirents in this mount
	// under the assumption that `node` is the root of the mount.
	return mns.withMountLocked(node, func() error {
		orig, ok := mns.mounts[node]
		if !ok {
			// node is not a mount point.
			return syserror.EINVAL
		}

		if orig.previous == nil {
			panic("cannot unmount initial dirent")
		}

		m := node.Inode.MountSource
		if !detachOnly {
			// Flush all references on the mounted node.
			m.FlushDirentRefs()

			// At this point, exactly two references must be held
			// to mount: one mount reference on node, and one due
			// to walking to node.
			//
			// We must also be guaranteed that no more references
			// can be taken on mount. This is why withMountLocked
			// must be held at this point to prevent any walks to
			// and from node.
			if refs := m.DirentRefs(); refs < 2 {
				panic(fmt.Sprintf("have %d refs on unmount, expect 2 or more", refs))
			} else if refs != 2 {
				return syserror.EBUSY
			}
		}

		prev := orig.previous
		if err := node.unmount(ctx, prev.root); err != nil {
			return err
		}

		if prev.previous == nil {
			if !prev.IsUndo() {
				panic(fmt.Sprintf("Last mount in the chain must be a undo mount: %+v", prev))
			}
			// Drop mount reference taken at the end of MountNamespace.Mount.
			prev.root.DecRef()
		} else {
			mns.mounts[prev.root] = prev
		}
		delete(mns.mounts, node)

		return nil
	})
}

// FindMount returns the mount that 'd' belongs to. It walks the dirent back
// until a mount is found. It may return nil if no mount was found.
func (mns *MountNamespace) FindMount(d *Dirent) *Mount {
	mns.mu.Lock()
	defer mns.mu.Unlock()
	renameMu.Lock()
	defer renameMu.Unlock()

	return mns.findMountLocked(d)
}

func (mns *MountNamespace) findMountLocked(d *Dirent) *Mount {
	for {
		if mnt := mns.mounts[d]; mnt != nil {
			return mnt
		}
		if d.parent == nil {
			return nil
		}
		d = d.parent
	}
}

// AllMountsUnder returns a slice of all mounts under the parent, including
// itself.
func (mns *MountNamespace) AllMountsUnder(parent *Mount) []*Mount {
	mns.mu.Lock()
	defer mns.mu.Unlock()

	var rv []*Mount
	for _, mp := range mns.mounts {
		if !mp.IsUndo() && mp.root.descendantOf(parent.root) {
			rv = append(rv, mp)
		}
	}
	return rv
}

// FindLink returns an Dirent from a given node, which may be a symlink.
//
// The root argument is treated as the root directory, and FindLink will not
// return anything above that. The wd dirent provides the starting directory,
// and may be nil which indicates the root should be used. You must call DecRef
// on the resulting Dirent when you are no longer using the object.
//
// If wd is nil, then the root will be used as the working directory. If the
// path is absolute, this has no functional impact.
//
// Precondition: root must be non-nil.
// Precondition: the path must be non-empty.
func (mns *MountNamespace) FindLink(ctx context.Context, root, wd *Dirent, path string, remainingTraversals *uint) (*Dirent, error) {
	if root == nil {
		panic("MountNamespace.FindLink: root must not be nil")
	}
	if len(path) == 0 {
		panic("MountNamespace.FindLink: path is empty")
	}

	// Split the path.
	first, remainder := SplitFirst(path)

	// Where does this walk originate?
	current := wd
	if current == nil {
		current = root
	}
	for first == "/" {
		// Special case: it's possible that we have nothing to walk at
		// all. This is necessary since we're resplitting the path.
		if remainder == "" {
			root.IncRef()
			return root, nil
		}

		// Start at the root and advance the path component so that the
		// walk below can proceed. Note at this point, it handles the
		// no-op walk case perfectly fine.
		current = root
		first, remainder = SplitFirst(remainder)
	}

	current.IncRef() // Transferred during walk.

	for {
		// Check that the file is a directory and that we have
		// permissions to walk.
		//
		// Note that we elide this check for the root directory as an
		// optimization; a non-executable root may still be walked.  A
		// non-directory root is hopeless.
		if current != root {
			if !IsDir(current.Inode.StableAttr) {
				current.DecRef() // Drop reference from above.
				return nil, syserror.ENOTDIR
			}
			if err := current.Inode.CheckPermission(ctx, PermMask{Execute: true}); err != nil {
				current.DecRef() // Drop reference from above.
				return nil, err
			}
		}

		// Move to the next level.
		next, err := current.Walk(ctx, root, first)
		if err != nil {
			// Allow failed walks to cache the dirent, because no
			// children will acquire a reference at the end.
			current.maybeExtendReference()
			current.DecRef()
			return nil, err
		}

		// Drop old reference.
		current.DecRef()

		if remainder != "" {
			// Ensure it's resolved, unless it's the last level.
			//
			// See resolve for reference semantics; on err next
			// will have one dropped.
			current, err = mns.resolve(ctx, root, next, remainingTraversals)
			if err != nil {
				return nil, err
			}
		} else {
			// Allow the file system to take an extra reference on the
			// found child. This will hold a reference on the containing
			// directory, so the whole tree will be implicitly cached.
			next.maybeExtendReference()
			return next, nil
		}

		// Move to the next element.
		first, remainder = SplitFirst(remainder)
	}
}

// FindInode is identical to FindLink except the return value is resolved.
//
//go:nosplit
func (mns *MountNamespace) FindInode(ctx context.Context, root, wd *Dirent, path string, remainingTraversals *uint) (*Dirent, error) {
	d, err := mns.FindLink(ctx, root, wd, path, remainingTraversals)
	if err != nil {
		return nil, err
	}

	// See resolve for reference semantics; on err d will have the
	// reference dropped.
	return mns.resolve(ctx, root, d, remainingTraversals)
}

// resolve resolves the given link.
//
// If successful, a reference is dropped on node and one is acquired on the
// caller's behalf for the returned dirent.
//
// If not successful, a reference is _also_ dropped on the node and an error
// returned. This is for convenience in using resolve directly as a return
// value.
func (mns *MountNamespace) resolve(ctx context.Context, root, node *Dirent, remainingTraversals *uint) (*Dirent, error) {
	// Resolve the path.
	target, err := node.Inode.Getlink(ctx)

	switch err {
	case nil:
		// Make sure we didn't exhaust the traversal budget.
		if *remainingTraversals == 0 {
			target.DecRef()
			return nil, syscall.ELOOP
		}

		node.DecRef() // Drop the original reference.
		return target, nil

	case syscall.ENOLINK:
		// Not a symlink.
		return node, nil

	case ErrResolveViaReadlink:
		defer node.DecRef() // See above.

		// First, check if we should traverse.
		if *remainingTraversals == 0 {
			return nil, syscall.ELOOP
		}

		// Read the target path.
		targetPath, err := node.Inode.Readlink(ctx)
		if err != nil {
			return nil, err
		}

		// Find the node; we resolve relative to the current symlink's parent.
		*remainingTraversals--
		d, err := mns.FindInode(ctx, root, node.parent, targetPath, remainingTraversals)
		if err != nil {
			return nil, err
		}

		return d, err

	default:
		node.DecRef() // Drop for err; see above.

		// Propagate the error.
		return nil, err
	}
}

// SyncAll calls Dirent.SyncAll on the root.
func (mns *MountNamespace) SyncAll(ctx context.Context) {
	mns.mu.Lock()
	defer mns.mu.Unlock()
	mns.root.SyncAll(ctx)
}

// ResolveExecutablePath resolves the given executable name given a set of
// paths that might contain it.
func (mns *MountNamespace) ResolveExecutablePath(ctx context.Context, wd, name string, paths []string) (string, error) {
	// Absolute paths can be used directly.
	if path.IsAbs(name) {
		return name, nil
	}

	// Paths with '/' in them should be joined to the working directory, or
	// to the root if working directory is not set.
	if strings.IndexByte(name, '/') > 0 {
		if wd == "" {
			wd = "/"
		}
		if !path.IsAbs(wd) {
			return "", fmt.Errorf("working directory %q must be absolute", wd)
		}
		return path.Join(wd, name), nil
	}

	// Otherwise, We must lookup the name in the paths, starting from the
	// calling context's root directory.
	root := RootFromContext(ctx)
	if root == nil {
		// Caller has no root. Don't bother traversing anything.
		return "", syserror.ENOENT
	}
	defer root.DecRef()
	for _, p := range paths {
		binPath := path.Join(p, name)
		traversals := uint(linux.MaxSymlinkTraversals)
		d, err := mns.FindInode(ctx, root, nil, binPath, &traversals)
		if err == syserror.ENOENT || err == syserror.EACCES {
			// Didn't find it here.
			continue
		}
		if err != nil {
			return "", err
		}
		defer d.DecRef()

		// Check whether we can read and execute the found file.
		if err := d.Inode.CheckPermission(ctx, PermMask{Read: true, Execute: true}); err != nil {
			log.Infof("Found executable at %q, but user cannot execute it: %v", binPath, err)
			continue
		}
		return path.Join("/", p, name), nil
	}
	return "", syserror.ENOENT
}

// GetPath returns the PATH as a slice of strings given the environemnt
// variables.
func GetPath(env []string) []string {
	const prefix = "PATH="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.Split(strings.TrimPrefix(e, prefix), ":")
		}
	}
	return nil
}
