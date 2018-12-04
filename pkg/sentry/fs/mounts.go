// Copyright 2018 Google LLC
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
	"path"
	"strings"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// DefaultTraversalLimit provides a sensible default traversal limit that may
// be passed to FindInode and FindLink. You may want to provide other options in
// individual syscall implementations, but for internal functions this will be
// sane.
const DefaultTraversalLimit = 10

// MountNamespace defines a collection of mounts.
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

	// mounts is a map of the last mounted Dirent -> stack of old Dirents
	// that were mounted over, with the oldest mounted Dirent first and
	// more recent mounted Dirents at the end of the slice.
	//
	// A reference to all Dirents in mounts (keys and values) must be held
	// to ensure the Dirents are recoverable when unmounting.
	mounts map[*Dirent][]*Dirent

	// mountID is the next mount id to assign.
	mountID uint64
}

// NewMountNamespace returns a new MountNamespace, with the provided node at the
// root, and the given cache size. A root must always be provided.
func NewMountNamespace(ctx context.Context, root *Inode) (*MountNamespace, error) {
	creds := auth.CredentialsFromContext(ctx)

	root.MountSource.mu.Lock()
	defer root.MountSource.mu.Unlock()

	// Set the root dirent and id on the root mount.
	d := NewDirent(root, "/")
	root.MountSource.root = d
	root.MountSource.id = 1

	return &MountNamespace{
		userns:  creds.UserNamespace,
		root:    d,
		mounts:  make(map[*Dirent][]*Dirent),
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
	for current, stack := range mns.mounts {
		current.Inode.MountSource.FlushDirentRefs()
		for _, prev := range stack {
			prev.Inode.MountSource.FlushDirentRefs()
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
	for current, mp := range mns.mounts {
		// Drop the mount reference on all mounted dirents.
		for _, d := range mp {
			d.DecRef()
		}
		current.DecRef()
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
func (mns *MountNamespace) Mount(ctx context.Context, node *Dirent, inode *Inode) error {
	return mns.withMountLocked(node, func() error {
		// replacement already has one reference taken; this is the mount
		// reference.
		replacement, err := node.mount(ctx, inode)
		if err != nil {
			return err
		}

		// Set child/parent dirent relationship.
		parentMountSource := node.Inode.MountSource
		childMountSource := inode.MountSource
		parentMountSource.mu.Lock()
		defer parentMountSource.mu.Unlock()
		childMountSource.mu.Lock()
		defer childMountSource.mu.Unlock()

		parentMountSource.children[childMountSource] = struct{}{}
		childMountSource.parent = parentMountSource

		// Set the mount's root dirent and id.
		childMountSource.root = replacement
		childMountSource.id = mns.mountID
		mns.mountID++

		// Drop node from its dirent cache.
		node.dropExtendedReference()

		// If node is already a mount point, push node on the stack so it can
		// be recovered on unmount.
		if stack, ok := mns.mounts[node]; ok {
			mns.mounts[replacement] = append(stack, node)
			delete(mns.mounts, node)
			return nil
		}

		// Was not already mounted, just add another mount point.
		// Take a reference on node so it can be recovered on unmount.
		node.IncRef()
		mns.mounts[replacement] = []*Dirent{node}
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
		origs, ok := mns.mounts[node]
		if !ok {
			// node is not a mount point.
			return syserror.EINVAL
		}

		if len(origs) == 0 {
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

		// Lock the parent MountSource first, if it exists. We are
		// holding mns.Lock, so the parent can not change out
		// from under us.
		parent := m.Parent()
		if parent != nil {
			parent.mu.Lock()
			defer parent.mu.Unlock()
		}

		// Lock the mount that is being unmounted.
		m.mu.Lock()
		defer m.mu.Unlock()

		if m.parent != nil {
			// Sanity check.
			if _, ok := m.parent.children[m]; !ok {
				panic(fmt.Sprintf("mount %+v is not a child of parent %+v", m, m.parent))
			}
			delete(m.parent.children, m)
		}

		original := origs[len(origs)-1]
		if err := node.unmount(ctx, original); err != nil {
			return err
		}

		switch {
		case len(origs) > 1:
			mns.mounts[original] = origs[:len(origs)-1]
		case len(origs) == 1:
			// Drop mount reference taken at the end of
			// MountNamespace.Mount.
			original.DecRef()
		}

		delete(mns.mounts, node)
		return nil
	})
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
