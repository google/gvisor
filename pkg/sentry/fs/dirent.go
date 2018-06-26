// Copyright 2018 Google Inc.
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
	"sort"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
)

type globalDirentMap struct {
	mu      sync.Mutex
	dirents map[*Dirent]struct{}
}

func (g *globalDirentMap) add(d *Dirent) {
	g.mu.Lock()
	g.dirents[d] = struct{}{}
	g.mu.Unlock()
}

func (g *globalDirentMap) remove(d *Dirent) {
	g.mu.Lock()
	delete(g.dirents, d)
	g.mu.Unlock()
}

// allDirents keeps track of all Dirents that need to be considered in
// Save/Restore for inode mappings.
//
// Because inodes do not hold paths, but inodes for external file systems map
// to an external path, every user-visible Dirent is stored in this map and
// iterated through upon save to keep inode ID -> restore path mappings.
var allDirents = globalDirentMap{
	dirents: map[*Dirent]struct{}{},
}

// renameMu protects the parent of *all* Dirents. (See explanation in
// lockForRename.)
//
// See fs.go for lock ordering.
var renameMu sync.RWMutex

// Dirent holds an Inode in memory.
//
// A Dirent may be negative or positive:
//
// A negative Dirent contains a nil Inode and indicates that a path does not exist. This
// is a convention taken from the Linux dcache, see fs/dcache.c. A negative Dirent remains
// cached until a create operation replaces it with a positive Dirent. A negative Dirent
// always has one reference owned by its parent and takes _no_ reference on its parent. This
// ensures that its parent can be unhashed regardless of negative children.
//
// A positive Dirent contains a non-nil Inode. It remains cached for as long as there remain
// references to it. A positive Dirent always takes a reference on its parent.
//
// A Dirent may be a root Dirent (parent is nil) or be parented (non-nil parent).
//
// Dirents currently do not attempt to free entries that lack application references under
// memory pressure.
type Dirent struct {
	// AtomicRefCount is our reference count.
	refs.AtomicRefCount

	// userVisible indicates whether the Dirent is visible to the user or
	// not.  Only user-visible Dirents should save inode mappings in
	// save/restore, as only they hold the real path to the underlying
	// inode.
	//
	// See newDirent and Dirent.afterLoad.
	userVisible bool

	// Inode is the underlying file object.
	//
	// Inode is exported currently to assist in implementing overlay Inodes (where a
	// Inode.InodeOperations.Lookup may need to merge the Inode contained in a positive Dirent with
	// another Inode). This is normally done before the Dirent is parented (there are
	// no external references to it).
	//
	// Other objects in the VFS may take a reference to this Inode but only while holding
	// a reference to this Dirent.
	Inode *Inode

	// name is the name (i.e. basename) of this entry.
	//
	// N.B. name is protected by parent.mu, not this node's mu!
	name string

	// parent is the parent directory.
	//
	// We hold a hard reference to the parent.
	//
	// parent is protected by renameMu.
	parent *Dirent

	// deleted may be set atomically when removed.
	deleted int32 `state:"nosave"`

	// frozen indicates this entry can't walk to unknown nodes.
	frozen bool

	// mounted is true if Dirent is a mount point, similar to include/linux/dcache.h:DCACHE_MOUNTED.
	mounted bool

	// direntEntry identifies this Dirent as an element in a DirentCache. DirentCaches
	// and their contents are not saved.
	direntEntry `state:"nosave"`

	// dirMu is a read-write mutex that protects caching decisions made by directory operations.
	// Lock ordering: dirMu must be taken before mu (see below). Details:
	//
	// dirMu does not participate in Rename; instead mu and renameMu are used, see lockForRename.
	//
	// Creation and Removal operations must be synchronized with Walk to prevent stale negative
	// caching. Note that this requirement is not specific to a _Dirent_ doing negative caching.
	// The following race exists at any level of the VFS:
	//
	// For an object D that represents a directory, containing a cache of non-existent paths,
	// protected by D.cacheMu:
	//
	// T1:                       T2:
	//                           D.lookup(name)
	//                           --> ENOENT
	// D.create(name)
	// --> success
	// D.cacheMu.Lock
	//   delete(D.cache, name)
	// D.cacheMu.Unlock
	//                           D.cacheMu.Lock
	//                             D.cache[name] = true
	//                           D.cacheMu.Unlock
	//
	// D.lookup(name)
	// D.cacheMu.Lock
	//   if D.cache[name] {
	//   --> ENOENT (wrong)
	//   }
	// D.cacheMu.Lock
	//
	// Correct:
	//
	// T1:                       T2:
	//                           D.cacheMu.Lock
	//                             D.lookup(name)
	//                             --> ENOENT
	//                             D.cache[name] = true
	//                           D.cacheMu.Unlock
	// D.cacheMu.Lock
	//   D.create(name)
	//   --> success
	//   delete(D.cache, name)
	// D.cacheMu.Unlock
	//
	// D.cacheMu.Lock
	//   D.lookup(name)
	//   --> EXISTS (right)
	// D.cacheMu.Unlock
	//
	// Note that the above "correct" solution causes too much lock contention: all lookups are
	// synchronized with each other. This is a problem because lookups are involved in any VFS
	// path operation.
	//
	// A Dirent diverges from the single D.cacheMu and instead uses two locks: dirMu to protect
	// concurrent creation/removal/lookup caching, and mu to protect the Dirent's children map
	// in general.
	//
	// This allows for concurrent Walks to be executed in order to pipeline lookups. For instance
	// for a hot directory /a/b, threads T1, T2, T3 will only block on each other update the
	// children map of /a/b when their individual lookups complete.
	//
	// T1:           T2:           T3:
	// stat(/a/b/c)  stat(/a/b/d)  stat(/a/b/e)
	dirMu sync.RWMutex `state:"nosave"`

	// mu protects the below fields. Lock ordering: mu must be taken after dirMu.
	mu sync.Mutex `state:"nosave"`

	// children are cached via weak references.
	children map[string]*refs.WeakRef
}

// NewDirent returns a new root Dirent, taking the caller's reference on inode. The caller
// holds the only reference to the Dirent. Parents may call hashChild to parent this Dirent.
func NewDirent(inode *Inode, name string) *Dirent {
	d := newDirent(inode, name)
	allDirents.add(d)
	d.userVisible = true
	return d
}

// NewTransientDirent creates a transient Dirent that shouldn't actually be
// visible to users.
//
// An Inode is required.
func NewTransientDirent(inode *Inode) *Dirent {
	if inode == nil {
		panic("an inode is required")
	}
	return newDirent(inode, "transient")
}

func newDirent(inode *Inode, name string) *Dirent {
	// The Dirent needs to maintain one reference to MountSource.
	if inode != nil {
		inode.MountSource.IncDirentRefs()
	}
	return &Dirent{
		Inode:    inode,
		name:     name,
		children: make(map[string]*refs.WeakRef),
	}
}

// NewNegativeDirent returns a new root negative Dirent. Otherwise same as NewDirent.
func NewNegativeDirent(name string) *Dirent {
	return newDirent(nil, name)
}

// IsRoot returns true if d is a root Dirent.
func (d *Dirent) IsRoot() bool {
	return d.parent == nil
}

// IsNegative returns true if d represents a path that does not exist.
func (d *Dirent) IsNegative() bool {
	return d.Inode == nil
}

// hashChild will hash child into the children list of its new parent d, carrying over
// any "frozen" state from d.
//
// Returns (*WeakRef, true) if hashing child caused a Dirent to be unhashed. The caller must
// validate the returned unhashed weak reference. Common cases:
//
// * Remove: hashing a negative Dirent unhashes a positive Dirent (unimplemented).
// * Create: hashing a positive Dirent unhashes a negative Dirent.
// * Lookup: hashing any Dirent should not unhash any other Dirent.
//
// Preconditions:
// * d.mu must be held.
// * child must be a root Dirent.
func (d *Dirent) hashChild(child *Dirent) (*refs.WeakRef, bool) {
	if !child.IsRoot() {
		panic("hashChild must be a root Dirent")
	}

	// Assign parentage.
	child.parent = d

	// Avoid letting negative Dirents take a reference on their parent; these Dirents
	// don't have a role outside of the Dirent cache and should not keep their parent
	// indefinitely pinned.
	if !child.IsNegative() {
		// Positive dirents must take a reference on their parent.
		d.IncRef()
	}

	// Carry over parent's frozen state.
	child.frozen = d.frozen

	return d.hashChildParentSet(child)
}

// hashChildParentSet will rehash child into the children list of its parent d.
//
// Assumes that child.parent = d already.
func (d *Dirent) hashChildParentSet(child *Dirent) (*refs.WeakRef, bool) {
	if child.parent != d {
		panic("hashChildParentSet assumes the child already belongs to the parent")
	}

	// Save any replaced child so our caller can validate it.
	old, ok := d.children[child.name]

	// Hash the child.
	d.children[child.name] = refs.NewWeakRef(child, nil)

	// Return any replaced child.
	return old, ok
}

// SyncAll iterates through mount points under d and writes back their buffered
// modifications to filesystems.
func (d *Dirent) SyncAll(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// For negative Dirents there is nothing to sync. By definition these are
	// leaves (there is nothing left to traverse).
	if d.IsNegative() {
		return
	}

	// There is nothing to sync for a read-only filesystem.
	if !d.Inode.MountSource.Flags.ReadOnly {
		// FIXME: This should be a mount traversal, not a
		// Dirent traversal, because some Inodes that need to be synced
		// may no longer be reachable by name (after sys_unlink).
		//
		// Write out metadata, dirty page cached pages, and sync disk/remote
		// caches.
		d.Inode.WriteOut(ctx)
	}

	// Continue iterating through other mounted filesystems.
	for _, w := range d.children {
		if child := w.Get(); child != nil {
			child.(*Dirent).SyncAll(ctx)
			child.DecRef()
		}
	}
}

// FullName returns the fully-qualified name and a boolean value representing
// whether this Dirent was a descendant of root.
// If the root argument is nil it is assumed to be the root of the Dirent tree.
func (d *Dirent) FullName(root *Dirent) (string, bool) {
	renameMu.RLock()
	defer renameMu.RUnlock()
	return d.fullName(root)
}

// fullName returns the fully-qualified name and a boolean value representing
// if the root node was reachable from this Dirent.
func (d *Dirent) fullName(root *Dirent) (string, bool) {
	if d == root {
		return "/", true
	}

	if d.IsRoot() {
		if root != nil {
			// We reached the top of the Dirent tree but did not encounter
			// the given root. Return false for reachable so the caller
			// can handle this situation accordingly.
			return d.name, false
		}
		return d.name, true
	}

	// Traverse up to parent.
	d.parent.mu.Lock()
	name := d.name
	d.parent.mu.Unlock()
	parentName, reachable := d.parent.fullName(root)
	s := path.Join(parentName, name)
	if atomic.LoadInt32(&d.deleted) != 0 {
		return s + " (deleted)", reachable
	}
	return s, reachable
}

func (d *Dirent) freeze() {
	if d.frozen {
		// Already frozen.
		return
	}
	d.frozen = true

	// Take a reference when freezing.
	for _, w := range d.children {
		if child := w.Get(); child != nil {
			// NOTE: We would normally drop the reference here. But
			// instead we're hanging on to it.
			ch := child.(*Dirent)
			ch.Freeze()
		}
	}

	// Drop all expired weak references.
	d.flush()
}

// Freeze prevents this dirent from walking to more nodes. Freeze is applied
// recursively to all children.
//
// If this particular Dirent represents a Virtual node, then Walks and Creates
// may proceed as before.
//
// Freeze can only be called before the application starts running, otherwise
// the root it might be out of sync with the application root if modified by
// sys_chroot.
func (d *Dirent) Freeze() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.freeze()
}

// descendantOf returns true if the receiver dirent is equal to, or a
// descendant of, the argument dirent.
//
// d.mu must be held.
func (d *Dirent) descendantOf(p *Dirent) bool {
	if d == p {
		return true
	}
	if d.IsRoot() {
		return false
	}
	return d.parent.descendantOf(p)
}

// walk walks to path name starting at the dirent, and will not traverse above
// root Dirent.
//
// If walkMayUnlock is true then walk can unlock d.mu to execute a slow
// Inode.Lookup, otherwise walk will keep d.mu locked.
//
// Preconditions:
// - d.mu must be held.
// - name must must not contain "/"s.
func (d *Dirent) walk(ctx context.Context, root *Dirent, name string, walkMayUnlock bool) (*Dirent, error) {
	if !IsDir(d.Inode.StableAttr) {
		return nil, syscall.ENOTDIR
	}
	if name == "" || name == "." {
		d.IncRef()
		return d, nil
	} else if name == ".." {
		renameMu.RLock()
		// Respect the chroot. Note that in Linux there is no check to enforce
		// that d is a descendant of root.
		if d == root {
			d.IncRef()
			renameMu.RUnlock()
			return d, nil
		}
		// Are we already at the root? Then ".." is ".".
		if d.IsRoot() {
			d.IncRef()
			renameMu.RUnlock()
			return d, nil
		}
		d.parent.IncRef()
		renameMu.RUnlock()
		return d.parent, nil
	}

	if w, ok := d.children[name]; ok {
		// Try to resolve the weak reference to a hard reference.
		if child := w.Get(); child != nil {
			cd := child.(*Dirent)

			// Is this a negative Dirent?
			if cd.IsNegative() {
				// Don't leak a reference; this doesn't matter as much for negative Dirents,
				// which don't hold a hard reference on their parent (their parent holds a
				// hard reference on them, and they contain virtually no state). But this is
				// good house-keeping.
				child.DecRef()
				return nil, syscall.ENOENT
			}

			// Do we need to revalidate this child?
			//
			// We never allow the file system to revalidate mounts, that could cause them
			// to unexpectedly drop out before umount.
			if cd.mounted || !cd.Inode.MountSource.Revalidate(cd) {
				// Good to go. This is the fast-path.
				return cd, nil
			}

			// If we're revalidating a child, we must ensure all inotify watches release
			// their pins on the child. Inotify doesn't properly support filesystems that
			// revalidate dirents (since watches are lost on revalidation), but if we fail
			// to unpin the watches child will never be GCed.
			cd.Inode.Watches.Unpin(cd)

			// This child needs to be revalidated, fallthrough to unhash it. Make sure
			// to not leak a reference from Get().
			//
			// Note that previous lookups may still have a reference to this stale child;
			// this can't be helped, but we can ensure that *new* lookups are up-to-date.
			child.DecRef()
		}

		// Either our weak reference expired or we need to revalidate it. Unhash child first, we're
		// about to replace it.
		delete(d.children, name)
		w.Drop()
	}

	// Are we allowed to do the lookup?
	if d.frozen && !d.Inode.IsVirtual() {
		return nil, syscall.ENOENT
	}

	// Slow path: load the InodeOperations into memory. Since this is a hot path and the lookup may be expensive,
	// if possible release the lock and re-acquire it.
	if walkMayUnlock {
		d.mu.Unlock()
	}
	c, err := d.Inode.Lookup(ctx, name)
	if walkMayUnlock {
		d.mu.Lock()
	}
	// No dice.
	if err != nil {
		return nil, err
	}

	// Sanity check c, its name must be consistent.
	if c.name != name {
		panic(fmt.Sprintf("lookup from %q to %q returned unexpected name %q", d.name, name, c.name))
	}

	// Now that we have the lock again, check if we raced.
	if w, ok := d.children[name]; ok {
		// Someone else looked up or created a child at name before us.
		if child := w.Get(); child != nil {
			cd := child.(*Dirent)

			// There are active references to the existing child, prefer it to the one we
			// retrieved from Lookup. Likely the Lookup happened very close to the insertion
			// of child, so considering one stale over the other is fairly arbitrary.
			c.DecRef()

			// The child that was installed could be negative.
			if cd.IsNegative() {
				// If so, don't leak a reference and short circuit.
				child.DecRef()
				return nil, syscall.ENOENT
			}

			// We make the judgement call that if c raced with cd they are close enough to have
			// the same staleness, so we don't attempt to revalidate cd. In Linux revalidations
			// can continue indefinitely (see fs/namei.c, retry_estale); we try to avoid this.
			return cd, nil
		}

		// Weak reference expired. We went through a full cycle of create/destroy in the time
		// we did the Inode.Lookup. Fully drop the weak reference and fallback to using the child
		// we looked up.
		delete(d.children, name)
		w.Drop()
	}

	// Give the looked up child a parent. We cannot kick out entries, since we just checked above
	// that there is nothing at name in d's children list.
	if _, kicked := d.hashChild(c); kicked {
		// Yell loudly.
		panic(fmt.Sprintf("hashed child %q over existing child", c.name))
	}

	// Is this a negative Dirent?
	if c.IsNegative() {
		// Don't drop a reference on the negative Dirent, it was just installed and this is the
		// only reference we'll ever get. d owns the reference.
		return nil, syscall.ENOENT
	}

	// Return the positive Dirent.
	return c, nil
}

// Walk walks to a new dirent, and will not walk higher than the given root
// Dirent, which must not be nil.
func (d *Dirent) Walk(ctx context.Context, root *Dirent, name string) (*Dirent, error) {
	if root == nil {
		panic("Dirent.Walk: root must not be nil")
	}

	d.dirMu.RLock()
	d.mu.Lock()
	child, err := d.walk(ctx, root, name, true /* may unlock */)
	d.mu.Unlock()
	d.dirMu.RUnlock()

	return child, err
}

// exists returns true if name exists in relation to d.
//
// Preconditions: d.mu must be held.
func (d *Dirent) exists(ctx context.Context, root *Dirent, name string) bool {
	child, err := d.walk(ctx, root, name, true /* may unlock */)
	if err != nil {
		// Child may not exist.
		return false
	}
	// Child exists.
	child.DecRef()
	return true
}

// lockDirectory should be called for any operation that changes this `d`s
// children (creating or removing them).
func (d *Dirent) lockDirectory() func() {
	if d.Inode.overlay != nil {
		// overlay copyUp may need to look at Dirent parents, and hence
		// may need renameMu.
		renameMu.RLock()
		d.dirMu.Lock()
		d.mu.Lock()
		return func() {
			d.mu.Unlock()
			d.dirMu.Unlock()
			renameMu.RUnlock()
		}
	}

	d.dirMu.Lock()
	d.mu.Lock()
	return func() {
		d.mu.Unlock()
		d.dirMu.Unlock()
	}
}

// Create creates a new regular file in this directory.
func (d *Dirent) Create(ctx context.Context, root *Dirent, name string, flags FileFlags, perms FilePermissions) (*File, error) {
	unlock := d.lockDirectory()
	defer unlock()

	// Does something already exist?
	if d.exists(ctx, root, name) {
		return nil, syscall.EEXIST
	}

	// Are we frozen?
	if d.frozen && !d.Inode.IsVirtual() {
		return nil, syscall.ENOENT
	}

	// Try the create. We need to trust the file system to return EEXIST (or something
	// that will translate to EEXIST) if name already exists.
	file, err := d.Inode.Create(ctx, d, name, flags, perms)
	if err != nil {
		return nil, err
	}
	child := file.Dirent

	// Sanity check c, its name must be consistent.
	if child.name != name {
		panic(fmt.Sprintf("create from %q to %q returned unexpected name %q", d.name, name, child.name))
	}

	// File systems cannot return a negative Dirent on Create, that makes no sense.
	if child.IsNegative() {
		panic(fmt.Sprintf("create from %q to %q returned negative Dirent", d.name, name))
	}

	// Hash the child into its parent. We can only kick out a Dirent if it is negative
	// (we are replacing something that does not exist with something that now does).
	if w, kicked := d.hashChild(child); kicked {
		if old := w.Get(); old != nil {
			if !old.(*Dirent).IsNegative() {
				panic(fmt.Sprintf("hashed child %q over a positive child", child.name))
			}
			// Don't leak a reference.
			old.DecRef()

			// Drop d's reference.
			old.DecRef()
		}

		// Finally drop the useless weak reference on the floor.
		w.Drop()
	}

	d.Inode.Watches.Notify(name, linux.IN_CREATE, 0)

	// Allow the file system to take extra references on c.
	child.maybeExtendReference()

	// Return the reference and the new file. When the last reference to
	// the file is dropped, file.Dirent may no longer be cached.
	return file, nil
}

// genericCreate executes create if name does not exist. Removes a negative Dirent at name if
// create succeeds.
//
// Preconditions: d.mu must be held.
func (d *Dirent) genericCreate(ctx context.Context, root *Dirent, name string, create func() error) error {
	// Does something already exist?
	if d.exists(ctx, root, name) {
		return syscall.EEXIST
	}

	// Are we frozen?
	if d.frozen && !d.Inode.IsVirtual() {
		return syscall.ENOENT
	}

	// Execute the create operation.
	if err := create(); err != nil {
		return err
	}

	// Remove any negative Dirent. We've already asserted above with d.exists
	// that the only thing remaining here can be a negative Dirent.
	if w, ok := d.children[name]; ok {
		// Same as Create.
		if old := w.Get(); old != nil {
			if !old.(*Dirent).IsNegative() {
				panic(fmt.Sprintf("hashed over a positive child %q", old.(*Dirent).name))
			}
			// Don't leak a reference.
			old.DecRef()

			// Drop d's reference.
			old.DecRef()
		}

		// Unhash the negative Dirent, name needs to exist now.
		delete(d.children, name)

		// Finally drop the useless weak reference on the floor.
		w.Drop()
	}

	return nil
}

// CreateLink creates a new link in this directory.
func (d *Dirent) CreateLink(ctx context.Context, root *Dirent, oldname, newname string) error {
	unlock := d.lockDirectory()
	defer unlock()

	return d.genericCreate(ctx, root, newname, func() error {
		if err := d.Inode.CreateLink(ctx, d, oldname, newname); err != nil {
			return err
		}
		d.Inode.Watches.Notify(newname, linux.IN_CREATE, 0)
		return nil
	})
}

// CreateHardLink creates a new hard link in this directory.
func (d *Dirent) CreateHardLink(ctx context.Context, root *Dirent, target *Dirent, name string) error {
	unlock := d.lockDirectory()
	defer unlock()

	// Make sure that target does not span filesystems.
	if d.Inode.MountSource != target.Inode.MountSource {
		return syscall.EXDEV
	}

	return d.genericCreate(ctx, root, name, func() error {
		if err := d.Inode.CreateHardLink(ctx, d, target, name); err != nil {
			return err
		}
		target.Inode.Watches.Notify("", linux.IN_ATTRIB, 0) // Link count change.
		d.Inode.Watches.Notify(name, linux.IN_CREATE, 0)
		return nil
	})
}

// CreateDirectory creates a new directory under this dirent.
func (d *Dirent) CreateDirectory(ctx context.Context, root *Dirent, name string, perms FilePermissions) error {
	unlock := d.lockDirectory()
	defer unlock()

	return d.genericCreate(ctx, root, name, func() error {
		if err := d.Inode.CreateDirectory(ctx, d, name, perms); err != nil {
			return err
		}
		d.Inode.Watches.Notify(name, linux.IN_ISDIR|linux.IN_CREATE, 0)
		return nil
	})
}

// Bind satisfies the InodeOperations interface; otherwise same as GetFile.
func (d *Dirent) Bind(ctx context.Context, root *Dirent, name string, socket unix.BoundEndpoint, perms FilePermissions) error {
	d.dirMu.Lock()
	defer d.dirMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.genericCreate(ctx, root, name, func() error {
		if err := d.Inode.Bind(ctx, name, socket, perms); err != nil {
			return err
		}
		d.Inode.Watches.Notify(name, linux.IN_CREATE, 0)
		return nil
	})
	if err == syscall.EEXIST {
		return syscall.EADDRINUSE
	}
	return err
}

// CreateFifo creates a new named pipe under this dirent.
func (d *Dirent) CreateFifo(ctx context.Context, root *Dirent, name string, perms FilePermissions) error {
	unlock := d.lockDirectory()
	defer unlock()

	return d.genericCreate(ctx, root, name, func() error {
		if err := d.Inode.CreateFifo(ctx, d, name, perms); err != nil {
			return err
		}
		d.Inode.Watches.Notify(name, linux.IN_CREATE, 0)
		return nil
	})
}

// getDotAttrs returns the DentAttrs corresponding to "." and ".." directories.
func (d *Dirent) getDotAttrs(root *Dirent) (DentAttr, DentAttr) {
	// Get '.'.
	sattr := d.Inode.StableAttr
	dot := DentAttr{
		Type:    sattr.Type,
		InodeID: sattr.InodeID,
	}

	// Get '..'.
	if !d.IsRoot() && d.descendantOf(root) {
		// Dirent is a descendant of the root.  Get its parent's attrs.
		psattr := d.parent.Inode.StableAttr
		dotdot := DentAttr{
			Type:    psattr.Type,
			InodeID: psattr.InodeID,
		}
		return dot, dotdot
	}
	// Dirent is either root or not a descendant of the root.  ".." is the
	// same as ".".
	return dot, dot
}

// readdirFrozen returns readdir results based solely on the frozen children.
func (d *Dirent) readdirFrozen(root *Dirent, offset int64, dirCtx *DirCtx) (int64, error) {
	// Collect attrs for "." and  "..".
	attrs := make(map[string]DentAttr)
	names := []string{".", ".."}
	attrs["."], attrs[".."] = d.getDotAttrs(root)

	// Get info from all children.
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, w := range d.children {
		if child := w.Get(); child != nil {
			defer child.DecRef()

			// Skip negative children.
			if child.(*Dirent).IsNegative() {
				continue
			}

			sattr := child.(*Dirent).Inode.StableAttr
			attrs[name] = DentAttr{
				Type:    sattr.Type,
				InodeID: sattr.InodeID,
			}
			names = append(names, name)
		}
	}

	sort.Strings(names)

	if int(offset) >= len(names) {
		return offset, nil
	}
	names = names[int(offset):]
	for _, name := range names {
		if err := dirCtx.DirEmit(name, attrs[name]); err != nil {
			return offset, err
		}
		offset++
	}
	return offset, nil
}

// DirIterator is an open directory containing directory entries that can be read.
type DirIterator interface {
	// IterateDir emits directory entries by calling dirCtx.EmitDir, beginning
	// with the entry at offset and returning the next directory offset.
	//
	// Entries for "." and ".." must *not* be included.
	//
	// If the offset returned is the same as the argument offset, then
	// nothing has been serialized.  This is equivalent to reaching EOF.
	// In this case serializer.Written() should return 0.
	//
	// The order of entries to emit must be consistent between Readdir
	// calls, and must start with the given offset.
	//
	// The caller must ensure that this operation is permitted.
	IterateDir(ctx context.Context, dirCtx *DirCtx, offset int) (int, error)
}

// DirentReaddir serializes the directory entries of d including "." and "..".
//
// Arguments:
//
// * d:		the Dirent of the directory being read; required to provide "." and "..".
// * it:	the directory iterator; which represents an open directory handle.
// * root: 	fs root; if d is equal to the root, then '..' will refer to d.
// * ctx: 	context provided to file systems in order to select and serialize entries.
// * offset:	the current directory offset.
//
// Returns the offset of the *next* element which was not serialized.
func DirentReaddir(ctx context.Context, d *Dirent, it DirIterator, root *Dirent, dirCtx *DirCtx, offset int64) (int64, error) {
	offset, err := direntReaddir(ctx, d, it, root, dirCtx, offset)
	// Serializing any directory entries at all means success.
	if dirCtx.Serializer.Written() > 0 {
		return offset, nil
	}
	return offset, err
}

func direntReaddir(ctx context.Context, d *Dirent, it DirIterator, root *Dirent, dirCtx *DirCtx, offset int64) (int64, error) {
	if root == nil {
		panic("Dirent.Readdir: root must not be nil")
	}
	if dirCtx.Serializer == nil {
		panic("Dirent.Readdir: serializer must not be nil")
	}
	if d.frozen {
		return d.readdirFrozen(root, offset, dirCtx)
	}

	// Check that this is actually a directory before emitting anything.
	// Once we have written entries for "." and "..", future errors from
	// IterateDir will be hidden.
	if !IsDir(d.Inode.StableAttr) {
		return 0, syserror.ENOTDIR
	}

	// Collect attrs for "." and "..".
	dot, dotdot := d.getDotAttrs(root)

	// Emit "." and ".." if the offset is low enough.
	if offset == 0 {
		// Serialize ".".
		if err := dirCtx.DirEmit(".", dot); err != nil {
			return offset, err
		}
		offset++
	}
	if offset == 1 {
		// Serialize "..".
		if err := dirCtx.DirEmit("..", dotdot); err != nil {
			return offset, err
		}
		offset++
	}

	// it.IterateDir should be passed an offset that does not include the
	// initial dot elements.  We will add them back later.
	offset -= 2
	newOffset, err := it.IterateDir(ctx, dirCtx, int(offset))
	if int64(newOffset) < offset {
		panic(fmt.Sprintf("node.Readdir returned offset %v less than input offset %v", newOffset, offset))
	}
	// Add the initial nodes back to the offset count.
	newOffset += 2
	return int64(newOffset), err
}

// flush flushes all weak references recursively, and removes any cached
// references to children.
//
// Preconditions: d.mu must be held.
func (d *Dirent) flush() {
	expired := make(map[string]*refs.WeakRef)
	for n, w := range d.children {
		// Call flush recursively on each child before removing our
		// reference on it, and removing the cache's reference.
		if child := w.Get(); child != nil {
			cd := child.(*Dirent)

			if !cd.IsNegative() {
				// Flush the child.
				cd.mu.Lock()
				cd.flush()
				cd.mu.Unlock()

				// Allow the file system to drop extra references on child.
				cd.dropExtendedReference()
			}

			// Don't leak a reference.
			child.DecRef()
		}
		// Check if the child dirent is closed, and mark it as expired if it is.
		// We must call w.Get() again here, since the child could have been closed
		// by the calls to flush() and cache.Remove() in the above if-block.
		if child := w.Get(); child != nil {
			child.DecRef()
		} else {
			expired[n] = w
		}
	}

	// Remove expired entries.
	for n, w := range expired {
		delete(d.children, n)
		w.Drop()
	}
}

// Busy indicates whether this Dirent is a mount point or root dirent, or has
// active positive children.
//
// This is expensive, since it flushes the children cache.
//
// TODO: Fix this busy-ness check.
func (d *Dirent) Busy() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.mounted || d.parent == nil {
		return true
	}

	// Flush any cached references to children that are doomed.
	d.flush()

	// Count positive children.
	var nonNegative int
	for _, w := range d.children {
		if child := w.Get(); child != nil {
			if !child.(*Dirent).IsNegative() {
				nonNegative++
			}
			child.DecRef()
		}
	}
	return nonNegative > 0
}

// mount mounts a new dirent with the given inode over d.
//
// Precondition: must be called with mm.withMountLocked held on `d`.
func (d *Dirent) mount(ctx context.Context, inode *Inode) (newChild *Dirent, err error) {
	// Did we race with deletion?
	if atomic.LoadInt32(&d.deleted) != 0 {
		return nil, syserror.ENOENT
	}

	// Refuse to mount a symlink.
	//
	// See Linux equivalent in fs/namespace.c:do_add_mount.
	if IsSymlink(inode.StableAttr) {
		return nil, syserror.EINVAL
	}

	// Are we frozen?
	if d.parent.frozen && !d.parent.Inode.IsVirtual() {
		return nil, syserror.ENOENT
	}

	// Dirent that'll replace d.
	//
	// Note that NewDirent returns with one reference taken; the reference
	// is donated to the caller as the mount reference.
	replacement := NewDirent(inode, d.name)
	replacement.mounted = true

	weakRef, ok := d.parent.hashChild(replacement)
	if !ok {
		panic("mount must mount over an existing dirent")
	}
	weakRef.Drop()

	// Note that even though `d` is now hidden, it still holds a reference
	// to its parent.
	return replacement, nil
}

// unmount unmounts `d` and replaces it with the last Dirent that was in its
// place, supplied by the MountNamespace as `replacement`.
//
// Precondition: must be called with mm.withMountLocked held on `d`.
func (d *Dirent) unmount(ctx context.Context, replacement *Dirent) error {
	// Did we race with deletion?
	if atomic.LoadInt32(&d.deleted) != 0 {
		return syserror.ENOENT
	}

	// Are we frozen?
	if d.parent.frozen && !d.parent.Inode.IsVirtual() {
		return syserror.ENOENT
	}

	// Remount our former child in its place.
	//
	// As replacement used to be our child, it must already have the right
	// parent.
	weakRef, ok := d.parent.hashChildParentSet(replacement)
	if !ok {
		panic("mount must mount over an existing dirent")
	}
	weakRef.Drop()

	// d is not reachable anymore, and hence not mounted anymore.
	d.mounted = false

	// Drop mount reference.
	d.DecRef()
	return nil
}

// Remove removes the given file or symlink.  The root dirent is used to
// resolve name, and must not be nil.
func (d *Dirent) Remove(ctx context.Context, root *Dirent, name string) error {
	// Check the root.
	if root == nil {
		panic("Dirent.Remove: root must not be nil")
	}

	unlock := d.lockDirectory()
	defer unlock()

	// Are we frozen?
	if d.frozen && !d.Inode.IsVirtual() {
		return syscall.ENOENT
	}

	// Try to walk to the node.
	child, err := d.walk(ctx, root, name, false /* may unlock */)
	if err != nil {
		// Child does not exist.
		return err
	}
	defer child.DecRef()

	// Remove cannot remove directories.
	if IsDir(child.Inode.StableAttr) {
		return syscall.EISDIR
	}

	// Remove cannot remove a mount point.
	if child.Busy() {
		return syscall.EBUSY
	}

	// Try to remove name on the file system.
	if err := d.Inode.Remove(ctx, d, child); err != nil {
		return err
	}

	// Link count changed, this only applies to non-directory nodes.
	child.Inode.Watches.Notify("", linux.IN_ATTRIB, 0)

	// Mark name as deleted and remove from children.
	atomic.StoreInt32(&child.deleted, 1)
	if w, ok := d.children[name]; ok {
		delete(d.children, name)
		w.Drop()
	}

	// Allow the file system to drop extra references on child.
	child.dropExtendedReference()

	// Finally, let inotify know the child is being unlinked. Drop any extra
	// refs from inotify to this child dirent. This doesn't necessarily mean the
	// watches on the underlying inode will be destroyed, since the underlying
	// inode may have other links. If this was the last link, the events for the
	// watch removal will be queued by the inode destructor.
	child.Inode.Watches.MarkUnlinked()
	child.Inode.Watches.Unpin(child)
	d.Inode.Watches.Notify(name, linux.IN_DELETE, 0)

	return nil
}

// RemoveDirectory removes the given directory.  The root dirent is used to
// resolve name, and must not be nil.
func (d *Dirent) RemoveDirectory(ctx context.Context, root *Dirent, name string) error {
	// Check the root.
	if root == nil {
		panic("Dirent.Remove: root must not be nil")
	}

	unlock := d.lockDirectory()
	defer unlock()

	// Are we frozen?
	if d.frozen && !d.Inode.IsVirtual() {
		return syscall.ENOENT
	}

	// Check for dots.
	if name == "." {
		// Rejected as the last component by rmdir(2).
		return syscall.EINVAL
	}
	if name == ".." {
		// If d was found, then its parent is not empty.
		return syscall.ENOTEMPTY
	}

	// Try to walk to the node.
	child, err := d.walk(ctx, root, name, false /* may unlock */)
	if err != nil {
		// Child does not exist.
		return err
	}
	defer child.DecRef()

	// RemoveDirectory can only remove directories.
	if !IsDir(child.Inode.StableAttr) {
		return syscall.ENOTDIR
	}

	// Remove cannot remove a mount point.
	if child.Busy() {
		return syscall.EBUSY
	}

	// Try to remove name on the file system.
	if err := d.Inode.Remove(ctx, d, child); err != nil {
		return err
	}

	// Mark name as deleted and remove from children.
	atomic.StoreInt32(&child.deleted, 1)
	if w, ok := d.children[name]; ok {
		delete(d.children, name)
		w.Drop()
	}

	// Allow the file system to drop extra references on child.
	child.dropExtendedReference()

	// Finally, let inotify know the child is being unlinked. Drop any extra
	// refs from inotify to this child dirent.
	child.Inode.Watches.MarkUnlinked()
	child.Inode.Watches.Unpin(child)
	d.Inode.Watches.Notify(name, linux.IN_ISDIR|linux.IN_DELETE, 0)

	return nil
}

// destroy closes this node and all children.
func (d *Dirent) destroy() {
	if d.IsNegative() {
		// Nothing to tear-down and no parent references to drop, since a negative
		// Dirent does not take a references on its parent, has no Inode and no children.
		return
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()

	// Drop all weak references.
	for _, w := range d.children {
		if c := w.Get(); c != nil {
			if c.(*Dirent).IsNegative() {
				// The parent holds both weak and strong refs in the case of
				// negative dirents.
				c.DecRef()
			}
			// Drop the reference we just acquired in WeakRef.Get.
			c.DecRef()
		}
		w.Drop()
	}
	d.children = nil

	allDirents.remove(d)

	// Drop our reference to the Inode.
	d.Inode.DecRef()

	// Allow the Dirent to be GC'ed after this point, since the Inode may still
	// be referenced after the Dirent is destroyed (for instance by filesystem
	// internal caches or hard links).
	d.Inode = nil

	// Drop the reference we have on our parent if we took one. renameMu doesn't need to be
	// held because d can't be reparented without any references to it left.
	if d.parent != nil {
		d.parent.DecRef()
	}
}

// IncRef increases the Dirent's refcount as well as its mount's refcount.
//
// IncRef implements RefCounter.IncRef.
func (d *Dirent) IncRef() {
	if d.Inode != nil {
		d.Inode.MountSource.IncDirentRefs()
	}
	d.AtomicRefCount.IncRef()
}

// TryIncRef implements RefCounter.TryIncRef.
func (d *Dirent) TryIncRef() bool {
	ok := d.AtomicRefCount.TryIncRef()
	if ok && d.Inode != nil {
		d.Inode.MountSource.IncDirentRefs()
	}
	return ok
}

// DecRef decreases the Dirent's refcount and drops its reference on its mount.
//
// DecRef implements RefCounter.DecRef with destructor d.destroy.
func (d *Dirent) DecRef() {
	if d.Inode != nil {
		// Keep mount around, since DecRef may destroy d.Inode.
		msrc := d.Inode.MountSource
		d.DecRefWithDestructor(d.destroy)
		msrc.DecDirentRefs()
	} else {
		d.DecRefWithDestructor(d.destroy)
	}
}

// InotifyEvent notifies all watches on the inode for this dirent and its parent
// of potential events. The events may not actually propagate up to the user,
// depending on the event masks. InotifyEvent automatically provides the name of
// the current dirent as the subject of the event as required, and adds the
// IN_ISDIR flag for dirents that refer to directories.
func (d *Dirent) InotifyEvent(events, cookie uint32) {
	// N.B. We don't defer the unlocks because InotifyEvent is in the hot
	// path of all IO operations, and the defers cost too much for small IO
	// operations.
	renameMu.RLock()

	if IsDir(d.Inode.StableAttr) {
		events |= linux.IN_ISDIR
	}

	// The ordering below is important, Linux always notifies the parent first.
	if d.parent != nil {
		d.parent.Inode.Watches.Notify(d.name, events, cookie)
	}
	d.Inode.Watches.Notify("", events, cookie)

	renameMu.RUnlock()
}

// maybeExtendReference caches a reference on this Dirent if
// MountSourceOperations.Keep returns true.
func (d *Dirent) maybeExtendReference() {
	if msrc := d.Inode.MountSource; msrc.Keep(d) {
		msrc.fscache.Add(d)
	}
}

// dropExtendedReference drops any cached reference held by the
// MountSource on the dirent.
func (d *Dirent) dropExtendedReference() {
	d.Inode.MountSource.fscache.Remove(d)
}

// lockForRename takes locks on oldParent and newParent as required by Rename
// and returns a function that will unlock the locks taken. The returned
// function must be called even if a non-nil error is returned.
func lockForRename(oldParent *Dirent, oldName string, newParent *Dirent, newName string) (func(), error) {
	if oldParent == newParent {
		oldParent.mu.Lock()
		return oldParent.mu.Unlock, nil
	}

	// Renaming between directories is a bit subtle:
	//
	// - A concurrent cross-directory Rename may try to lock in the opposite
	// order; take renameMu to prevent this from happening.
	//
	// - If either directory is an ancestor of the other, then a concurrent
	// Remove may lock the descendant (in DecRef -> closeAll) while holding a
	// lock on the ancestor; to avoid this, ensure we take locks in the same
	// ancestor-to-descendant order. (Holding renameMu prevents this
	// relationship from changing.)
	renameMu.Lock()

	// First check if newParent is a descendant of oldParent.
	child := newParent
	for p := newParent.parent; p != nil; p = p.parent {
		if p == oldParent {
			oldParent.mu.Lock()
			newParent.mu.Lock()
			var err error
			if child.name == oldName {
				// newParent is not just a descendant of oldParent, but
				// more specifically of oldParent/oldName. That is, we're
				// trying to rename something into a subdirectory of
				// itself.
				err = syscall.EINVAL
			}
			return func() {
				newParent.mu.Unlock()
				oldParent.mu.Unlock()
				renameMu.Unlock()
			}, err
		}
		child = p
	}

	// Otherwise, either oldParent is a descendant of newParent or the two
	// have no relationship; in either case we can do this:
	newParent.mu.Lock()
	oldParent.mu.Lock()
	return func() {
		oldParent.mu.Unlock()
		newParent.mu.Unlock()
		renameMu.Unlock()
	}, nil
}

func checkSticky(ctx context.Context, dir *Dirent, victim *Dirent) error {
	uattr, err := dir.Inode.UnstableAttr(ctx)
	if err != nil {
		return syserror.EPERM
	}
	if !uattr.Perms.Sticky {
		return nil
	}

	creds := auth.CredentialsFromContext(ctx)
	if uattr.Owner.UID == creds.EffectiveKUID {
		return nil
	}

	vuattr, err := victim.Inode.UnstableAttr(ctx)
	if err != nil {
		return syserror.EPERM
	}
	if vuattr.Owner.UID == creds.EffectiveKUID {
		return nil
	}
	if victim.Inode.CheckCapability(ctx, linux.CAP_FOWNER) {
		return nil
	}
	return syserror.EPERM
}

// MayDelete determines whether `name`, a child of `dir`, can be deleted or
// renamed by `ctx`.
//
// Compare Linux kernel fs/namei.c:may_delete.
func MayDelete(ctx context.Context, root, dir *Dirent, name string) error {
	victim, err := dir.Walk(ctx, root, name)
	if err != nil {
		return err
	}
	defer victim.DecRef()

	return mayDelete(ctx, dir, victim)
}

func mayDelete(ctx context.Context, dir *Dirent, victim *Dirent) error {
	if err := dir.Inode.CheckPermission(ctx, PermMask{Write: true, Execute: true}); err != nil {
		return err
	}

	return checkSticky(ctx, dir, victim)
}

// Rename atomically converts the child of oldParent named oldName to a
// child of newParent named newName.
func Rename(ctx context.Context, root *Dirent, oldParent *Dirent, oldName string, newParent *Dirent, newName string) error {
	if root == nil {
		panic("Rename: root must not be nil")
	}
	if oldParent == newParent && oldName == newName {
		return nil
	}

	// Acquire global renameMu lock, and mu locks on oldParent/newParent.
	unlock, err := lockForRename(oldParent, oldName, newParent, newName)
	defer unlock()
	if err != nil {
		return err
	}

	// Are we frozen?
	// TODO: Is this the right errno?
	if oldParent.frozen && !oldParent.Inode.IsVirtual() {
		return syscall.ENOENT
	}
	if newParent.frozen && !newParent.Inode.IsVirtual() {
		return syscall.ENOENT
	}

	// Check constraints on the object being renamed.
	renamed, err := oldParent.walk(ctx, root, oldName, false /* may unlock */)
	if err != nil {
		return err
	}
	defer renamed.DecRef()

	// Make sure we have write permissions on old and new parent.
	if err := mayDelete(ctx, oldParent, renamed); err != nil {
		return err
	}
	if newParent != oldParent {
		if err := newParent.Inode.CheckPermission(ctx, PermMask{Write: true, Execute: true}); err != nil {
			return err
		}
	}

	// Source should not be an ancestor of the target.
	if renamed == newParent {
		return syscall.EINVAL
	}

	// Is the thing we're trying to rename busy?
	if renamed.Busy() {
		return syscall.EBUSY
	}

	// Per rename(2): "... EACCES: ... or oldpath is a directory and does not
	// allow write permission (needed to update the .. entry)."
	if IsDir(renamed.Inode.StableAttr) {
		if err := renamed.Inode.CheckPermission(ctx, PermMask{Write: true}); err != nil {
			return err
		}
	}

	// Check constraints on the object being replaced, if any.
	replaced, err := newParent.walk(ctx, root, newName, false /* may unlock */)
	if err == nil {
		defer replaced.DecRef()

		// Target should not be an ancestor of source.
		if replaced == oldParent {
			// Why is this not EINVAL? See fs/namei.c.
			return syscall.ENOTEMPTY
		}

		// Is the thing we're trying to replace busy?
		if replaced.Busy() {
			return syscall.EBUSY
		}

		// Require that a directory is replaced by a directory.
		oldIsDir := IsDir(renamed.Inode.StableAttr)
		newIsDir := IsDir(replaced.Inode.StableAttr)
		if !newIsDir && oldIsDir {
			return syscall.ENOTDIR
		}
		if !oldIsDir && newIsDir {
			return syscall.EISDIR
		}

		// Allow the file system to drop extra references on replaced.
		replaced.dropExtendedReference()

		// NOTE: Keeping a dirent
		// open across renames is currently broken for multiple
		// reasons, so we flush all references on the replaced node and
		// its children.
		replaced.Inode.Watches.Unpin(replaced)
		replaced.flush()
	}

	if err := renamed.Inode.Rename(ctx, oldParent, renamed, newParent, newName); err != nil {
		return err
	}

	renamed.name = newName
	renamed.parent = newParent
	if oldParent != newParent {
		// Reparent the reference held by renamed.parent. oldParent.DecRef
		// can't destroy oldParent (and try to retake its lock) because
		// Rename's caller must be holding a reference.
		newParent.IncRef()
		oldParent.DecRef()
	}
	if w, ok := newParent.children[newName]; ok {
		w.Drop()
		delete(newParent.children, newName)
	}
	if w, ok := oldParent.children[oldName]; ok {
		w.Drop()
		delete(oldParent.children, oldName)
	}

	// Add a weak reference from the new parent.  This ensures that the child
	// can still be found from the new parent if a prior hard reference is
	// held on renamed.
	//
	// This is required for file lock correctness because file locks are per-Dirent
	// and without maintaining the a cached child (via a weak reference) for renamed,
	// multiple Dirents can correspond to the same resource (by virtue of the renamed
	// Dirent being unreachable by its parent and it being looked up).
	newParent.children[newName] = refs.NewWeakRef(renamed, nil)

	// Queue inotify events for the rename.
	var ev uint32
	if IsDir(renamed.Inode.StableAttr) {
		ev |= linux.IN_ISDIR
	}

	cookie := uniqueid.InotifyCookie(ctx)
	oldParent.Inode.Watches.Notify(oldName, ev|linux.IN_MOVED_FROM, cookie)
	newParent.Inode.Watches.Notify(newName, ev|linux.IN_MOVED_TO, cookie)
	// Somewhat surprisingly, self move events do not have a cookie.
	renamed.Inode.Watches.Notify("", linux.IN_MOVE_SELF, 0)

	// Allow the file system to drop extra references on renamed.
	renamed.dropExtendedReference()

	// Same as replaced.flush above.
	renamed.flush()

	return nil
}
