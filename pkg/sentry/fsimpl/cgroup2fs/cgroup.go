// Copyright 2026 The gVisor Authors.
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

package cgroup2fs

// Lock order:
//
// kernfs.filesystem.mu
//   cgroup2fs.filesystem.treeMu
//     kernfs.OrderedChildren.mu
//     kernel.TaskSet.mu
//       cgroup2fs.filesystem.tasksMu
//         kernel.SignalHandlers.mu
//         kernel.Task.cgroup2Mu
//
// The treeMu is an analogue to the kernel's cgroup_mutex, whereas
// tasksMu is an analogue to the kernel's css_set_lock. The former
// governs matters of topology: the basic structure of the tree and
// the controllers enabled in each node. The latter governs membership:
// the tasks associated with each cgroup.

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs/memxattr"
	"gvisor.dev/gvisor/pkg/usermem"
)

// limitMax is the value for max.descendants and max.depth that indicates no limit.
const limitMax = -1

// cgroup is a cgroup2 directory inode.
//
// +stateify savable
type cgroup struct {
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren // But we override NewDir() and RmDir().
	kernfs.InodeNoopRefCount
	kernfs.InodeNotAnonymous
	kernfs.InodeNotSymlink
	kernfs.InodeWatches
	kernfs.OrderedChildren
	kernfs.InodeFSOwned
	implStatFS
	locks vfs.FileLocks

	// Back pointer to the filesystem. Immutable.
	fs *filesystem
	// parent is the parent cgroup. Immutable.
	parent *cgroup // nil for the root cgroup.
	// Used to publish to cgroup.events. Immutable.
	eventsFile *eventFile
	// path relative to the root cgroup. Immutable.
	path string
	// Makes searching for common ancestors faster. Immutable.
	level int

	// Used to make operations on FDs pointing to deleted cgroups fail.
	// +checklocks:fs.treeMu
	// +checkatomic
	deleted atomicbitops.Bool

	// children contains all sub-cgroups in this directory.
	// +checklocks:fs.treeMu
	children map[*cgroup]struct{}
	// subtreeCtrls tracks the controller types that this cgroup has enabled for its children.
	// +checklocks:fs.treeMu
	subtreeCtrls [kernel.Cgroup2NumControllers]bool

	// Task membership.
	// +checklocks:fs.tasksMu
	tasks map[*kernel.Task]struct{}
	// +checkatomic
	tasksCount atomicbitops.Int64

	// ctrls stores pointers to active controllers attached to this cgroup.
	// +checklocks:fs.treeMu
	ctrls ctrlSet
	// closestCtrls stores an array of deepest ancestor controllers that are enabled.
	// It is an atomic pointer so that when we do implement hotpath charging, it can be
	// achieved locklessly.
	// If ctrls[i] is non-nil, that is, there is a controller
	// attached to this cgroup, then closestCtrls[i] == ctrls[i].
	closestCtrls atomic.Pointer[ctrlSet] `state:".(*ctrlSet)"`

	// The field below counts the number of immediate children considered populated.
	// It helps answer quickly if the subtree beneath a cgroup is considered populated.
	// +checklocks:fs.tasksMu
	// +checkatomic
	nrPopulatedChildren atomicbitops.Int64

	// Backing field for cgroup.max.descendants.
	// +checklocks:fs.treeMu
	// +checkatomic
	maxDescendants atomicbitops.Int64
	// Backing field for cgroup.max.depth.
	// +checklocks:fs.treeMu
	// +checkatomic
	maxDepth atomicbitops.Int64
	// The total number of cgroups nested inside this cgroup at all depths.
	// Backs the nr_descendants field in cgroup.stat.
	// +checklocks:fs.treeMu
	// +checkatomic
	nrDescendants atomicbitops.Int64

	// killSeq tracks cgroup.kill invocations.
	// +checklocks:fs.tasksMu
	killSeq uint64

	// xattrs stores extended attributes on this cgroup directory.
	xattrs memxattr.SimpleExtendedAttributes
}

// +checklocks:c.fs.treeMu
func (c *cgroup) initRoot(ctx context.Context) {
	arr := new(ctrlSet)
	for i := firstController; i < numControllers; i++ {
		// Root cgroup must have all controllers active.
		ctrl := c.newController(i)
		c.ctrls[i] = ctrl
		c.populateInterfaceFiles(ctx, ctrl)
		arr[i] = c.ctrls[i]
	}
	c.closestCtrls.Store(arr)
}

// +checklocks:c.fs.treeMu
func (c *cgroup) init(ctx context.Context) {
	var parentSet *ctrlSet
	if c.parent != nil {
		parentSet = c.parent.closestCtrls.Load()
		if parentSet == nil {
			panic("cgroup tree inconsistency: parent closestCtrls is nil")
		}
	} else {
		panic("cgroup tree inconsistency: init called on root cgroup")
	}

	arr := new(ctrlSet)
	for i := firstController; i < numControllers; i++ {
		if c.parent.subtreeCtrls[i] { // +checklocksforce: c.fs.treeMu is locked
			ctrl := c.newController(i)
			c.ctrls[i] = ctrl
			c.populateInterfaceFiles(ctx, ctrl)
		}

		if c.ctrls[i] != nil {
			arr[i] = c.ctrls[i]
		} else {
			arr[i] = parentSet[i]
		}
	}
	c.closestCtrls.Store(arr)
}

// Keep implements kernfs.Inode.Keep.
func (*cgroup) Keep() bool {
	return true
}

// SetStat implements kernfs.Inode.SetStat.
func (c *cgroup) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return c.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// Open implements kernfs.Inode.Open.
func (c *cgroup) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), kd, rp.Credentials(), &c.OrderedChildren, &c.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndStaticEntries,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// Valid implements kernfs.Inode.Valid.
func (c *cgroup) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	return !c.deleted.Load()
}

// Lookup implements kernfs.Inode.Lookup.
func (c *cgroup) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	if c.deleted.Load() {
		return nil, linuxerr.ENOENT
	}
	return c.OrderedChildren.Lookup(ctx, name)
}

// IterDirents implements kernfs.Inode.IterDirents.
func (c *cgroup) IterDirents(ctx context.Context, mnt *vfs.Mount, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	return c.OrderedChildren.IterDirents(ctx, mnt, cb, offset, relOffset)
}

// NewDir implements kernfs.Inode.NewDir.
func (c *cgroup) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	if strings.Contains(name, "\n") {
		return nil, linuxerr.EINVAL
	}
	c.fs.treeMu.Lock()
	defer c.fs.treeMu.Unlock()

	if c.deleted.Load() {
		return nil, linuxerr.ENOENT
	}
	if err := c.checkLimitsLocked(); err != nil {
		return nil, err
	}

	mode := opts.Mode.Permissions() | linux.ModeDirectory
	return c.OrderedChildren.Inserter(name, func() kernfs.Inode {
		c.IncLinks(1)
		childPath := c.path
		if childPath != "/" {
			childPath += "/"
		}
		childPath += name
		return c.fs.newCgroupLocked(ctx, auth.CredentialsFromContext(ctx), mode, childPath, c) // +checklocksforce: c.fs.treeMu is locked
	})
}

// Unlink implements kernfs.Inode.Unlink.
func (c *cgroup) Unlink(ctx context.Context, name string, child kernfs.Inode) error {
	return linuxerr.EPERM
}

// HasChildren implements kernfs.Inode.HasChildren.
// We return false to bypass kernfs yielding ENOTEMPTY instead doing it in RmDir manually to yield EBUSY.
func (c *cgroup) HasChildren() bool {
	return false
}

// RmDir implements kernfs.Inode.RmDir.
func (c *cgroup) RmDir(ctx context.Context, name string, child kernfs.Inode) error {
	childCgroup, ok := child.(*cgroup)
	if !ok {
		return linuxerr.ENOTDIR
	}

	c.fs.treeMu.Lock()
	defer c.fs.treeMu.Unlock()

	if childCgroup.InodeAttrs.Links()-2 > 0 || childCgroup.populated() {
		return linuxerr.EBUSY
	}

	err := c.OrderedChildren.RmDir(ctx, name, child)
	if err != nil {
		return err
	}
	c.InodeAttrs.DecLinks()

	delete(c.children, childCgroup)
	childCgroup.deleted.Store(true) // +checklocksforce: c.fs.treeMu is locked

	// Walk up the ancestry to keep nrDescendants up to date.
	for curr := c; curr != nil; curr = curr.parent {
		curr.nrDescendants.Add(-1) // +checklocksforce: c.fs.treeMu is locked
	}
	return nil
}

// Rename implements kernfs.Inode.Rename.
func (c *cgroup) Rename(ctx context.Context, oldname, newname string, child, dstDir kernfs.Inode) error {
	return linuxerr.EPERM
}

// populated returns true if this cgroup, or any of its descendants contain tasks.
// nrPopulatedChildren keeps this O(1).
func (c *cgroup) populated() bool {
	if c.tasksCount.Load() > 0 {
		return true
	}
	if c.nrPopulatedChildren.Load() > 0 {
		return true
	}
	return false
}

// updatePopulated propagates task population changes up the ancestry.
// When an ancestor transitions between empty and populated, it updates
// its parent's populated child counters and triggers cgroup.events notifications.
// +checklocks:c.fs.tasksMu
func (c *cgroup) updatePopulated(ctx context.Context, populated bool) {
	diff := int64(-1)
	if populated {
		diff = 1
	}

	child := (*cgroup)(nil)
	curr := c
	for curr != nil {
		wasPopulated := curr.populated()

		if child != nil {
			curr.nrPopulatedChildren.Add(diff) // +checklocksforce: c.fs.tasksMu is locked
		}

		if child != nil && wasPopulated == curr.populated() {
			break
		}
		if curr.eventsFile != nil {
			curr.eventsFile.Notify(ctx)
		}
		child = curr
		curr = curr.parent
	}
}

// setControllersLocked modifies the set of enabled controllers for the children of the
// given cgroup and updates impacted descendants.
// +checklocks:c.fs.treeMu
func (c *cgroup) setControllersLocked(ctx context.Context, enable []kernel.Cgroup2Ctrl, disable []kernel.Cgroup2Ctrl) {
	var cTypes []kernel.Cgroup2Ctrl

	for _, cType := range enable {
		if !c.subtreeCtrls[cType] {
			c.subtreeCtrls[cType] = true
			cTypes = append(cTypes, cType)
		}
	}
	for _, cType := range disable {
		if c.subtreeCtrls[cType] {
			c.subtreeCtrls[cType] = false
			cTypes = append(cTypes, cType)
		}
	}

	if len(cTypes) > 0 {
		for child := range c.children {
			child.rebuildCtrlsLocked(ctx, cTypes) // +checklocksforce: c.fs.treeMu is locked
		}
	}
}

// rebuildCtrls reconciles the child's active controllers with the parent's subtree_control.
// +checklocks:c.fs.treeMu
func (c *cgroup) rebuildCtrlsLocked(ctx context.Context, cTypes []kernel.Cgroup2Ctrl) {
	if c.parent == nil {
		panic("cgroup tree inconsistency: rebuildCtrlsLocked called on root")
	}

	for _, cType := range cTypes {
		if c.parent.subtreeCtrls[cType] && c.ctrls[cType] == nil { // +checklocksforce: c.fs.treeMu is locked
			ctrl := c.newController(cType)
			c.ctrls[cType] = ctrl
			c.populateInterfaceFiles(ctx, ctrl)
		} else if !c.parent.subtreeCtrls[cType] && c.ctrls[cType] != nil { // +checklocksforce: c.fs.treeMu is locked
			ctrl := c.ctrls[cType]
			c.ctrls[cType] = nil
			c.removeInterfaceFiles(ctx, ctrl)
			ctrl.detach()
		}
	}

	if !c.updateClosestCtrlsLocked(cTypes) {
		return
	}
	c.walkSubtreeLocked(func(child *cgroup) bool {
		return child.updateClosestCtrlsLocked(cTypes) // +checklocksforce: c.fs.treeMu is locked
	})

	for _, cType := range cTypes {
		if cType == kernel.Cgroup2Memory {
			// Update the memory cgroup IDs of existing tasks in this subtree
			// because the memory controller has been enabled/disabled.
			c.fs.tasksMu.Lock()
			c.updateTaskMemoryCgIDsLocked()
			c.walkSubtreeLocked(func(child *cgroup) bool {
				child.updateTaskMemoryCgIDsLocked() // +checklocksforce: child.fs.treeMu and child.fs.tasksMu are locked.
				return true
			})
			c.fs.tasksMu.Unlock()
		}
	}
}

// updateClosestCtrls updates the cached nearest active controller for the given types.
// Returns true if the cache was actually modified.
// +checklocks:c.fs.treeMu
func (c *cgroup) updateClosestCtrlsLocked(cTypes []kernel.Cgroup2Ctrl) bool {
	curSet := c.closestCtrls.Load()
	if curSet == nil {
		panic("cgroup tree inconsistency: closestCtrls is nil")
	}
	curSet = curSet.fork()

	var parentSet *ctrlSet
	if c.parent != nil {
		parentSet = c.parent.closestCtrls.Load()
		if parentSet == nil {
			panic("cgroup tree inconsistency: parent closestCtrls is nil")
		}
	}

	changed := false
	for _, cType := range cTypes {
		var ctrl controller
		if c.ctrls[cType] != nil {
			ctrl = c.ctrls[cType]
		} else if c.parent != nil {
			ctrl = parentSet[cType]
		}
		if curSet[cType] != ctrl {
			curSet[cType] = ctrl
			changed = true
		}
	}

	if changed {
		c.closestCtrls.Store(curSet)
	}
	return changed
}

// CanEnter checks if a task can enter the cgroup.
func (c *cgroup) CanEnter(ctx context.Context, t *kernel.Task) (func(), func(), error) {
	curSet := c.closestCtrls.Load()
	if curSet == nil {
		return func() {}, func() {}, nil
	}

	for i, ctrl := range curSet {
		if ctrl == nil {
			continue
		}
		if !ctrl.canEnter(ctx, t) {
			for _, prev := range curSet[:i] {
				if prev != nil {
					prev.cancelEnter(ctx, t)
				}
			}
			return nil, nil, linuxerr.EAGAIN
		}
	}

	// rollback and commit should be bound to the cached curSet, so that a concurrent
	// update to c.closestCtrls is safe.
	rollback := func() {
		for _, ctrl := range curSet {
			if ctrl != nil {
				ctrl.cancelEnter(ctx, t)
			}
		}
	}
	commit := func() {
		c.fs.tasksMu.Lock()
		c.tasks[t] = struct{}{}
		if c.tasksCount.Add(1) == 1 {
			c.updatePopulated(ctx, true)
		}
		c.fs.tasksMu.Unlock()

		for _, ctrl := range curSet {
			if ctrl != nil {
				ctrl.enter(ctx, t)
			}
		}
	}

	return rollback, commit, nil
}

// Exit is called when a task dies.
func (c *cgroup) Exit(ctx context.Context, t *kernel.Task) {
	c.fs.tasksMu.Lock()
	delete(c.tasks, t)
	if c.tasksCount.Add(-1) == 0 {
		c.updatePopulated(ctx, false)
	}
	c.fs.tasksMu.Unlock()

	curSet := c.closestCtrls.Load()
	if curSet == nil {
		return
	}
	for _, ctrl := range curSet {
		if ctrl == nil {
			continue
		}
		ctrl.exit(ctx, t)
	}
}

// CanCloneInto implements kernel.Cgroup2.CanCloneInto.
// It is used to check permissions for CLONE_CGROUP_INTO. ns is the forking
// task's cgroup namespace.
// +checklocksread:c.fs.treeMu
func (c *cgroup) CanCloneInto(ctx context.Context, creds *auth.Credentials, ns *kernel.CgroupNamespace) error {
	if c.deleted.Load() {
		return linuxerr.ENOENT
	}

	if c.parent != nil && c.hasControllersEnabledLocked() {
		return linuxerr.EBUSY
	}

	inode, err := c.OrderedChildren.Lookup(ctx, "cgroup.procs")
	if err != nil {
		return err
	}
	if err := inode.CheckPermissions(ctx, creds, vfs.MayWrite); err != nil {
		return err
	}

	t := kernel.TaskFromContext(ctx)
	if t != nil {
		if parentCg, ok := t.Cgroup2().(*cgroup); ok {
			var nsRoot *cgroup
			if ns != nil {
				nsRoot, _ = ns.Root().(*cgroup)
			}
			return c.checkMigrationPermsLocked(ctx, creds, parentCg, nsRoot)
		}
	}
	return nil
}

func (c *cgroup) canAttach(ctx context.Context, actx *attachCtx) bool {
	curSet := c.closestCtrls.Load()
	if curSet == nil {
		return true
	}

	for i, ctrl := range curSet {
		if ctrl == nil {
			continue
		}
		if !ctrl.canAttach(ctx, actx) {
			for _, prev := range curSet[:i] {
				if prev != nil {
					prev.cancelAttach(ctx, actx)
				}
			}
			return false
		}
	}
	return true
}

// cancelAttach cancels an attach().
func (c *cgroup) cancelAttach(ctx context.Context, actx *attachCtx) {
	curSet := c.closestCtrls.Load()
	if curSet == nil {
		return
	}

	for _, ctrl := range curSet {
		if ctrl == nil {
			continue
		}
		ctrl.cancelAttach(ctx, actx)
	}
}

// attach() helps achieve administrative migration (cgroup.procs or cgroup.threads)
func (c *cgroup) attach(ctx context.Context, actx *attachCtx) {
	c.fs.tasksMu.Lock()
	defer c.fs.tasksMu.Unlock()

	for t := range actx.tasks {
		t.SetCgroup2(c)

		oldNode := actx.oldNodes[t]
		if oldNode == nil {
			panic("cgroup tree inconsistency: task has no cgroup2 node")
		}

		delete(oldNode.tasks, t)             // +checklocksforce: c.fs.tasksMu is locked
		if oldNode.tasksCount.Add(-1) == 0 { // +checklocksforce: c.fs.tasksMu is locked
			oldNode.updatePopulated(ctx, false) // +checklocksforce: c.fs.tasksMu is locked
		}

		c.tasks[t] = struct{}{}
		if c.tasksCount.Add(1) == 1 {
			c.updatePopulated(ctx, true)
		}
	}

	curSet := c.closestCtrls.Load()
	if curSet == nil {
		return
	}
	for _, ctrl := range curSet {
		if ctrl == nil {
			continue
		}
		ctrl.attach(ctx, actx)
	}
}

func (c *cgroup) populateInterfaceFiles(ctx context.Context, ctrl controller) {
	if ctrl == nil {
		return
	}
	uid := c.UID()
	gid := c.GID()

	for _, def := range ctrl.interfaceFiles() {
		def.ctrl = ctrl
		if c.parent == nil && !def.showAtRoot {
			continue
		}
		inode := c.fs.newInode(ctx, uid, gid, c, def)

		// Insert() can only return EEXIST. Short of cgroup2fs inconsistency, this should never happen.
		if err := c.OrderedChildren.Insert(def.name, inode); err != nil {
			ctx.Warningf("cgroup2fs: failed to insert interface file %q: %v", def.name, err)
		}
	}
}

func (c *cgroup) removeInterfaceFiles(ctx context.Context, ctrl controller) {
	if ctrl == nil {
		return
	}
	for _, name := range ctrl.interfaceFileNames() {
		if inode, err := c.OrderedChildren.Lookup(ctx, name); err == nil {
			c.OrderedChildren.Unlink(ctx, name, inode)
		}
	}
}

// Path returns the path of the cgroup (`without " (deleted)"`).
func (c *cgroup) Path() string {
	return c.path
}

// PathFrom implements kernel.Cgroup2.PathFrom.
//
// It mirrors Linux's cgroup_path_ns(): the returned path is relative
// to nsRoot, always starts with '/', and contains one leading "/.." component
// per level separating nsRoot from the lowest common ancestor of the two
// cgroups.
//
// It relies only on immutable fields (parent, level, path), so it
// needs no locks.
func (c *cgroup) PathFrom(nsRoot kernel.Cgroup2) string {
	root, ok := nsRoot.(*cgroup)
	if !ok || root.fs != c.fs || root.parent == nil {
		// Namespace rooted at the real root (or a foreign node, which
		// shouldn't happen): the path is absolute.
		return c.Path()
	}

	lca := lowestCommonAncestor(c, root)
	var b strings.Builder
	for i := 0; i < root.level-lca.level; i++ {
		b.WriteString("/..")
	}
	if c != lca {
		if lca.parent == nil {
			b.WriteString(c.path)
		} else {
			b.WriteString(c.path[len(lca.path):])
		}
	}
	if b.Len() == 0 {
		b.WriteString("/")
	}
	return b.String()
}

// Deleted implements kernel.Cgroup2.Deleted.
func (c *cgroup) Deleted() bool {
	return c.deleted.Load()
}

// KillSeq implements kernel.Cgroup2.KillSeq.
func (c *cgroup) KillSeq() uint64 {
	c.fs.tasksMu.RLock()
	defer c.fs.tasksMu.RUnlock()
	return c.killSeq
}

// +checklocksread:c.fs.treeMu
func (c *cgroup) isControllerAvailableLocked(i kernel.Cgroup2Ctrl) bool {
	if c.parent != nil {
		return c.parent.subtreeCtrls[i] // +checklocksforce: c.fs.treeMu is locked
	}
	return c.ctrls[i] != nil
}

// walkSubtree walks the subtree rooted at c, calling f on each descendant.
// If f returns false, the subtree walk stops descending down that branch.
// +checklocksread:c.fs.treeMu
func (c *cgroup) walkSubtreeLocked(f func(n *cgroup) bool) {
	for child := range c.children {
		if f(child) {
			child.walkSubtreeLocked(f) // +checklocksforce: c.fs.treeMu is locked
		}
	}
}

// checkMigrationPermsLocked checks whether the caller may migrate a process
// from oldNode to c. nsRoot is the root cgroup of the calling task's cgroup
// namespace.
// +checklocksread:c.fs.treeMu
func (c *cgroup) checkMigrationPermsLocked(ctx context.Context, creds *auth.Credentials, oldNode, nsRoot *cgroup) error {
	lca := lowestCommonAncestor(oldNode, c)
	if lca == nil {
		return nil
	}
	lcaProcs, err := lca.OrderedChildren.Lookup(ctx, "cgroup.procs")
	if err != nil {
		return err
	}
	if err := lcaProcs.CheckPermissions(ctx, creds, vfs.MayWrite); err != nil {
		return err
	}

	// If cgroup namespaces are delegation boundaries, both the source and
	// destination cgroups must be reachable from the migrating task's cgroup
	// namespace.
	if c.fs.nsDelegate.Load() && nsRoot != nil {
		if !oldNode.isDescendantOf(nsRoot) || !c.isDescendantOf(nsRoot) {
			return linuxerr.ENOENT
		}
	}
	return nil
}

// isDescendantOf returns true if c is a descendant of (or the same as) a.
// It relies only on immutable fields and needs no locks.
func (c *cgroup) isDescendantOf(a *cgroup) bool {
	for c != nil && c.level > a.level {
		c = c.parent
	}
	return c == a
}

// checkNSDelegateWrite enforces the "nsdelegate" mount option: cgroup
// namespace roots are delegation boundaries, so writes from inside a
// non-init namespace to non-delegatable interface files of the namespace
// root cgroup are rejected.
func (c *cgroup) checkNSDelegateWrite(ctx context.Context, fd *vfs.FileDescription) error {
	if !c.fs.nsDelegate.Load() {
		return nil
	}
	ifd, ok := fd.Impl().(*interfaceFD)
	if !ok || ifd.ns == nil {
		return nil
	}
	cgns := ifd.ns
	if k := kernel.KernelFromContext(ctx); k == nil || cgns == k.RootCgroupNamespace() {
		return nil
	}
	if nsRoot, ok := cgns.Root().(*cgroup); ok && nsRoot == c {
		return linuxerr.EPERM
	}
	return nil
}

func lowestCommonAncestor(a, b *cgroup) *cgroup {
	da := a.level
	db := b.level
	for da > db {
		a = a.parent
		da--
	}
	for db > da {
		b = b.parent
		db--
	}
	for a != b && a != nil && b != nil {
		a = a.parent
		b = b.parent
	}
	return a
}

// checkLimitsLocked checks if we are hitting cgroup dir limits.
// +checklocksread:c.fs.treeMu
func (c *cgroup) checkLimitsLocked() error {
	for curr := c; curr != nil; curr = curr.parent {
		maxDepth := curr.maxDepth.Load()
		maxDesc := curr.maxDescendants.Load()

		if maxDepth != limitMax {
			diff := int64(c.level - curr.level)
			if diff >= maxDepth {
				return linuxerr.EAGAIN
			}
		}
		if maxDesc != limitMax {
			if curr.nrDescendants.Load() >= maxDesc {
				return linuxerr.EAGAIN
			}
		}
	}
	return nil
}

// +checklocksread:c.fs.treeMu
func (c *cgroup) hasControllersEnabledLocked() bool {
	for _, enabled := range c.subtreeCtrls {
		if enabled {
			return true
		}
	}
	return false
}

// attachProcess handles writes to cgroup.procs.
// nsRoot is the root cgroup of the cgroupns of the task at the time of the
// opening of the cgroup.procs fd.
func (c *cgroup) attachProcess(ctx context.Context, creds *auth.Credentials, nsRoot *cgroup, pid int64) error {
	c.fs.treeMu.Lock()
	defer c.fs.treeMu.Unlock()
	if c.deleted.Load() {
		return linuxerr.ENODEV
	}

	// No internal processes.
	// cgroup-v2.rst: "Only cgroups which don't contain any processes can have
	// controllers enabled in their "cgroup.subtree_control" files."
	if c.parent != nil && c.hasControllersEnabledLocked() {
		return linuxerr.EBUSY
	}

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return nil
	}
	var targetTask *kernel.Task
	if pid != 0 {
		targetTask = t.PIDNamespace().TaskWithID(kernel.ThreadID(pid))
	} else {
		targetTask = t
	}
	if targetTask == nil {
		return linuxerr.ESRCH
	}
	oldNode := targetTask.Cgroup2().(*cgroup)
	if err := c.checkMigrationPermsLocked(ctx, creds, oldNode, nsRoot); err != nil {
		return err
	}

	// Locking the TaskSet mutex helps prevent the threadgroup
	// membership from changing during the migration.
	var errRet error
	targetTask.ThreadGroup().WithTaskSetRLock(func() {
		actx := &attachCtx{
			tasks:    make(map[*kernel.Task]struct{}),
			oldNodes: make(map[*kernel.Task]*cgroup),
		}
		targetTask.ThreadGroup().ForEachTaskLocked(func(t *kernel.Task) bool {
			if t.ExitState() < kernel.TaskExitInitiated {
				if tn, _ := t.Cgroup2().(*cgroup); tn != c {
					actx.tasks[t] = struct{}{}
					actx.oldNodes[t] = tn
				}
			}
			return true
		})

		if len(actx.tasks) > 0 {
			if !c.canAttach(ctx, actx) {
				errRet = linuxerr.EAGAIN
				return
			}
			c.attach(ctx, actx)
		}
	})
	if errRet != nil {
		return errRet
	}

	return nil
}

// getPIDs handles reads from cgroup.procs.
func (c *cgroup) getPIDs(t *kernel.Task) []int {
	if t == nil {
		return nil
	}
	return c.getPIDsInNamespace(t.PIDNamespace())
}

// getPIDsInNamespace returns task IDs in currPidns for all tasks in c.
func (c *cgroup) getPIDsInNamespace(currPidns *kernel.PIDNamespace) []int {
	if currPidns == nil {
		return nil
	}
	var tasks []*kernel.Task

	c.fs.tasksMu.RLock()
	for task := range c.tasks {
		tasks = append(tasks, task)
	}
	c.fs.tasksMu.RUnlock()

	var pids []int
	for tgid := range currPidns.IDsOfTasks(tasks, true /* threadGroupIDs */) {
		pids = append(pids, int(tgid))
	}
	sort.Ints(pids)
	return pids
}

// setSubtreeControl() handles writes to cgroup.subtree_control.
func (c *cgroup) setSubtreeControl(ctx context.Context, enable []kernel.Cgroup2Ctrl, disable []kernel.Cgroup2Ctrl) error {
	c.fs.treeMu.Lock()
	defer c.fs.treeMu.Unlock()

	if c.deleted.Load() {
		return linuxerr.ENODEV
	}

	for _, cType := range enable {
		if !c.isControllerAvailableLocked(cType) {
			return linuxerr.ENOENT
		}
		// No internal processes.
		// cgroup-v2.rst: "Only cgroups which don't contain any processes can have
		// controllers enabled in their "cgroup.subtree_control" files."
		hasTasks := c.tasksCount.Load() > 0
		if c.parent != nil && hasTasks { // Although the root cgroup is exempt.
			return linuxerr.EBUSY
		}
	}

	for _, cType := range disable {
		// Cannot disable if a child cgroup has this controller enabled.
		inUse := false
		for child := range c.children {
			if child.subtreeCtrls[cType] { // +checklocksforce: c.fs.treeMu is locked
				inUse = true
				break
			}
		}
		if inUse {
			return linuxerr.EBUSY
		}
	}

	c.setControllersLocked(ctx, enable, disable)
	return nil
}

// kill() handles writes to cgroup.kill.
func (c *cgroup) kill() error {
	// cgroup-v2.rst says: "Killing a cgroup tree will deal with concurrent forks appropriately and
	// is protected against migrations."
	c.fs.treeMu.Lock()
	defer c.fs.treeMu.Unlock()
	if c.deleted.Load() {
		return linuxerr.ENODEV
	}

	c.fs.tasksMu.Lock()
	defer c.fs.tasksMu.Unlock()

	// Mark the kill intention across the subtree.
	c.killSeq++
	c.walkSubtreeLocked(func(child *cgroup) bool {
		child.killSeq++ // +checklocksforce: c.fs.tasksMu is locked
		return true
	})

	// Collect tasks to kill. Racing fork()s will check the sequence number we just updated.
	var toKill []*kernel.Task
	for t := range c.tasks {
		toKill = append(toKill, t)
	}
	c.walkSubtreeLocked(func(child *cgroup) bool {
		for t := range child.tasks { // +checklocksforce: c.fs.tasksMu is locked
			toKill = append(toKill, t)
		}
		return true
	})

	for _, t := range toKill {
		t.SendSignal(kernel.SignalInfoPriv(linux.SIGKILL))
	}
	return nil
}

// stealController detaches a controller from the root cgroup V2 tree.
// +checklocks:c.fs.treeMu
func (c *cgroup) stealController(ctx context.Context, cType kernel.Cgroup2Ctrl) error {
	if c.parent != nil {
		panic("Unified cgroups inconsistency: stealController called on non-root")
	}
	if c.subtreeCtrls[cType] {
		return linuxerr.EBUSY
	}

	if ctrl := c.ctrls[cType]; ctrl != nil {
		c.removeInterfaceFiles(ctx, ctrl)
		ctrl.detach()
	}
	c.ctrls[cType] = nil

	cTypes := []kernel.Cgroup2Ctrl{cType}
	c.updateClosestCtrlsLocked(cTypes)
	for child := range c.children {
		child.rebuildCtrlsLocked(ctx, cTypes) // +checklocksforce: c.fs.treeMu is locked
	}
	if cType == kernel.Cgroup2Memory {
		// Update tasks residing in the root cgroup itself to charge to system ID 0
		// since the root memory controller has been stolen.
		c.fs.tasksMu.Lock()
		c.updateTaskMemoryCgIDsLocked()
		c.fs.tasksMu.Unlock()
	}
	return nil
}

// returnController attaches a controller back to the root cgroup V2 tree.
// +checklocks:c.fs.treeMu
func (c *cgroup) returnController(ctx context.Context, cType kernel.Cgroup2Ctrl) {
	if c.parent != nil {
		panic("Unified cgroups inconsistency: returnController called on non-root")
	}

	ctrl := c.newController(cType)
	c.ctrls[cType] = ctrl
	c.populateInterfaceFiles(ctx, ctrl)

	cTypes := []kernel.Cgroup2Ctrl{cType}
	c.updateClosestCtrlsLocked(cTypes)
	for child := range c.children {
		child.rebuildCtrlsLocked(ctx, cTypes) // +checklocksforce: c.fs.treeMu is locked
	}
	if cType == kernel.Cgroup2Memory {
		// Update tasks residing in the root cgroup itself to charge to the root
		// memory controller ID now that it has been returned.
		c.fs.tasksMu.Lock()
		c.updateTaskMemoryCgIDsLocked()
		c.fs.tasksMu.Unlock()
	}
}

// +checklocks:c.fs.treeMu
// +checklocks:c.fs.tasksMu
func (c *cgroup) updateTaskMemoryCgIDsLocked() {
	var memCgID uint32
	if mem := c.closestCtrls.Load()[kernel.Cgroup2Memory]; mem != nil {
		memCgID = mem.(*memory).id
	}
	for t := range c.tasks {
		t.SetMemCgID(memCgID)
	}
}

// ReadControl implements kernel.Cgroup2.ReadControl.
// It allows reading from control files from outside the sandbox.
func (c *cgroup) ReadControl(ctx context.Context, name string) (string, error) {
	cfi, err := c.Lookup(ctx, name)
	if err != nil {
		return "", fmt.Errorf("no such control file")
	}
	dbf, ok := cfi.(*cgroupInterfaceFile)
	var data vfs.DynamicBytesSource
	if ok {
		data, err = dbf.Data(ctx)
		if err != nil {
			return "", err
		}
	} else if ef, ok := cfi.(*eventFile); ok {
		data, err = ef.Data(ctx)
		if err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("no such control file")
	}

	var buf bytes.Buffer
	if err := data.Generate(ctx, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// WriteControl implements kernel.Cgroup2.WriteControl.
// It allows writing to control files from outside the sandbox.
func (c *cgroup) WriteControl(ctx context.Context, name string, val string) error {
	cfi, err := c.Lookup(ctx, name)
	if err != nil {
		return fmt.Errorf("no such control file")
	}
	dbf, ok := cfi.(*cgroupInterfaceFile)
	if !ok {
		return fmt.Errorf("control file not writable")
	}
	data, err := dbf.Data(ctx)
	if err != nil {
		return err
	}
	wdata, ok := data.(vfs.WritableDynamicBytesSource)
	if !ok {
		return fmt.Errorf("control file not writable")
	}
	ioSeq := usermem.BytesIOSequence([]byte(val))
	n, err := wdata.Write(ctx, nil, ioSeq, 0)
	if err != nil {
		return err
	}
	if n != int64(len(val)) {
		return fmt.Errorf("short write")
	}
	return nil
}
