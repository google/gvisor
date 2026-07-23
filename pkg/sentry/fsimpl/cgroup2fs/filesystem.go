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

// Package cgroup2fs provides the cgroupv2 filesystem implementation.
package cgroup2fs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Name is the default filesystem name.
const Name = "cgroup2"

// FilesystemType implements vfs.FilesystemType for cgroup2 (cgroup v2).
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (ft FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	nsDelegate := false
	mopts := vfs.GenericParseMountOptions(opts.Data)
	for k := range mopts {
		switch k {
		case "nsdelegate":
			nsDelegate = true
		default:
			ctx.Debugf("cgroup2fs.FilesystemType.GetFilesystem: unknown option: %s", k)
			return nil, nil, linuxerr.EINVAL
		}
	}

	k := kernel.KernelFromContext(ctx)
	fs := k.Cgroup2FS().(*filesystem)
	cgns := mountingCgroupNS(ctx)
	if cgns != nil {
		defer cgns.DecRef(ctx)
	}
	rootD, err := fs.mountRoot(ctx, vfsObj, cgns)
	if err != nil {
		return nil, nil, err
	}

	// "nsdelegate" is system wide: every mount from the init cgroup namespace
	// sets or clears it, and it is ignored on non-init namespace mounts.
	// A failed mount must not change the flag, hence the store is ordered after mountRoot().
	if cgns == nil || cgns == k.RootCgroupNamespace() {
		fs.nsDelegate.Store(nsDelegate)
	}

	fs.mounted.Store(1)
	vfsfs := fs.VFSFilesystem()
	vfsfs.IncRef()
	return vfsfs, rootD.VFSDentry(), nil
}

// mountingCgroupNS returns the cgroup namespace a mount originates from.
// A reference is taken on the namespace if it is not nil.
func mountingCgroupNS(ctx context.Context) *kernel.CgroupNamespace {
	if t := kernel.TaskFromContext(ctx); t != nil {
		return t.GetCgroupNamespace()
	}
	return kernel.CgroupNamespaceFromContext(ctx)
}

// mountRoot returns the dentry a new cgroup2 mount should be rooted at, with
// a reference taken on it. Mounts created from within a non-init cgroup
// namespace are rooted at the namespace's root cgroup, per cgroup-v2.rst
// "Interaction with Other Namespaces". Otherwise, the mount is rooted at the
// real root of the hierarchy.
func (fs *filesystem) mountRoot(ctx context.Context, vfsObj *vfs.VirtualFilesystem, cgns *kernel.CgroupNamespace) (*kernfs.Dentry, error) {
	if cgns == nil {
		fs.root.IncRef()
		return fs.root, nil
	}
	nsRoot, ok := cgns.Root().(*cgroup)
	if !ok || nsRoot.fs != fs || nsRoot.parent == nil {
		fs.root.IncRef()
		return fs.root, nil
	}
	if nsRoot.deleted.Load() {
		return nil, linuxerr.ENOENT
	}
	// Cgroups can't be renamed and nsRoot.path is immutable, so walking the
	// path from the real root reliably finds nsRoot's dentry unless it has
	// been removed.
	d, err := fs.root.WalkDentryTree(ctx, vfsObj, fspath.Parse(nsRoot.path))
	if err != nil {
		return nil, err
	}
	if d.Inode() != nsRoot {
		d.DecRef(ctx)
		return nil, linuxerr.ENOENT
	}
	return d, nil
}

// MountRootPath implements vfs.MountRootPathProvider.MountRootPath.
func (fs *filesystem) MountRootPath(ctx context.Context, vd vfs.VirtualDentry) string {
	d, ok := vd.Dentry().Impl().(*kernfs.Dentry)
	if !ok {
		return ""
	}
	c, ok := d.Inode().(*cgroup)
	if !ok {
		return ""
	}
	var path string
	if t := kernel.TaskFromContext(ctx); t != nil {
		if cgns := t.CgroupNamespace(); cgns != nil {
			path = c.PathFrom(cgns.Root())
		}
	}
	if path == "" {
		path = c.Path()
	}
	return path
}

// NewInternalMount returns a disconnected mount of the cgroup2fs singleton,
// rooted at the true root of the hierarchy, for use by the sentry control
// plane (e.g. to create per-container cgroups). The caller owns the returned
// mount reference.
func NewInternalMount(k *kernel.Kernel, vfsObj *vfs.VirtualFilesystem) *vfs.Mount {
	fs := k.Cgroup2FS().(*filesystem)
	fs.mounted.Store(1)
	return vfsObj.NewDisconnectedMount(fs.VFSFilesystem(), fs.root.VFSDentry(), &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{InternalMount: true},
	})
}

// SetNSDelegate sets the system-wide nsdelegate flag, which makes cgroup
// namespace roots delegation boundaries. Calling this at sandbox boot is the
// analog of the host's init mounting cgroup2 with the "nsdelegate" option
// from the init cgroup namespace.
func SetNSDelegate(k *kernel.Kernel, v bool) {
	k.Cgroup2FS().(*filesystem).nsDelegate.Store(v)
}

// CgroupFromDentry returns the cgroup2 node backing d, if any.
func CgroupFromDentry(d *vfs.Dentry) (kernel.Cgroup2, bool) {
	kd, ok := d.Impl().(*kernfs.Dentry)
	if !ok {
		return nil, false
	}
	c, ok := kd.Inode().(*cgroup)
	return c, ok
}

// NewFilesystem creates and registers the cgroup2fs singleton. It should be called early
// during boot before the first task is created.
func NewFilesystem(ctx context.Context, k *kernel.Kernel, vfsObj *vfs.VirtualFilesystem) (*vfs.Filesystem, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, err
	}

	fs := &filesystem{
		rootCreds: auth.NewRootCredentials(k.RootUserNamespace()),
		devMinor:  devMinor,
	}
	fs.VFSFilesystem().Init(vfsObj, &FilesystemType{}, fs)

	rootMode := linux.FileMode(0755) | linux.ModeDirectory
	rootInode := fs.newRootInode(ctx, rootMode)

	rootD := &kernfs.Dentry{}
	rootD.InitRoot(&fs.Filesystem, rootInode)
	fs.root = rootD

	return fs.VFSFilesystem(), nil
}

// filesystem implements vfs.FilesystemImpl for cgroup2.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem
	rootCreds *auth.Credentials
	devMinor  uint32

	root *kernfs.Dentry

	// mounted tracks whether the filesystem has been mounted/initialized.
	mounted atomicbitops.Uint32

	// nsDelegate tracks whether cgroup namespaces are delegation boundaries.
	// It is system wide, and may only be changed by mounts from the init
	// cgroup namespace.
	nsDelegate atomicbitops.Bool

	// nextMemCgroupID is used to allocate unique IDs to memory controllers.
	nextMemCgroupID atomicbitops.Uint32

	// treeMu protects controller hierarchy enablement traversals, and tracking of owned controllers.
	treeMu treeRWMutex `state:"nosave"`

	// tasksMu protects the task-to-cgroup mapping (the c.tasks map across all cgroups)
	// and population bubbling.
	tasksMu tasksRWMutex `state:"nosave"`
}

// EverMounted implements EverMounted.
func (fs *filesystem) EverMounted() bool {
	return fs.mounted.Load() != 0
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	if fs.root != nil {
		fs.root.DecRef(ctx)
		fs.root = nil
	}

	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	if fs.nsDelegate.Load() {
		return "nsdelegate"
	}
	return ""
}

// LockTree implements kernel.Cgroup2FS.LockTree.
func (fs *filesystem) LockTree() {
	fs.treeMu.Lock()
}

// UnlockTree implements kernel.Cgroup2FS.UnlockTree.
func (fs *filesystem) UnlockTree() {
	fs.treeMu.Unlock()
}

// RLockTree implements kernel.Cgroup2FS.RLockTree.
func (fs *filesystem) RLockTree() {
	fs.treeMu.RLock()
}

// RUnlockTree implements kernel.Cgroup2FS.RUnlockTree.
func (fs *filesystem) RUnlockTree() {
	fs.treeMu.RUnlock()
}

// StealControllerLocked implements kernel.Cgroup2FS.StealControllerLocked.
// +checklocks:fs.treeMu
func (fs *filesystem) StealControllerLocked(ctx context.Context, cType kernel.Cgroup2Ctrl) error {
	rootCG := fs.root.Inode().(*cgroup)
	return rootCG.stealController(ctx, cType) // +checklocksforce: fs.treeMu is locked
}

// ReturnControllerLocked implements kernel.Cgroup2FS.ReturnControllerLocked.
// +checklocks:fs.treeMu
func (fs *filesystem) ReturnControllerLocked(ctx context.Context, cType kernel.Cgroup2Ctrl) {
	rootCG := fs.root.Inode().(*cgroup)
	rootCG.returnController(ctx, cType) // +checklocksforce: fs.treeMu is locked
}

// RootCgroup implements kernel.Cgroup2FS.RootCgroup.
func (fs *filesystem) RootCgroup() kernel.Cgroup2 {
	return fs.root.Inode().(*cgroup)
}

// FindCgroup implements kernel.Cgroup2FS.FindCgroup.
// It allows reading and writing to a cgroup from outside the sandbox.
func (fs *filesystem) FindCgroup(ctx context.Context, path string) (kernel.Cgroup2, error) {
	p := fspath.Parse(path)
	if !p.Absolute {
		return nil, fmt.Errorf("path must be absolute")
	}
	vfsObj := fs.VFSFilesystem().VirtualFilesystem()
	d, err := fs.root.WalkDentryTree(ctx, vfsObj, p)
	if err != nil {
		return nil, err
	}
	cg, ok := d.Inode().(*cgroup)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return cg, nil
}

func (fs *filesystem) newRootInode(ctx context.Context, mode linux.FileMode) kernfs.Inode {
	c := &cgroup{
		fs:       fs,
		tasks:    make(map[*kernel.Task]struct{}),
		path:     "/",
		parent:   nil,
		children: make(map[*cgroup]struct{}),
	}
	c.InodeAttrs.Init(ctx, fs.rootCreds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), mode)
	c.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})

	c.IncLinks(c.OrderedChildren.Populate(fs.rootInodes(ctx, fs.rootCreds.EffectiveKUID, fs.rootCreds.EffectiveKGID, c)))

	c.fs.treeMu.Lock()
	defer c.fs.treeMu.Unlock()
	c.initRoot(ctx)
	c.maxDescendants.Store(limitMax)
	c.maxDepth.Store(limitMax)

	return c
}

// +checklocks:fs.treeMu
func (fs *filesystem) newCgroupLocked(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, path string, parent *cgroup) kernfs.Inode {
	c := &cgroup{
		fs:       fs,
		tasks:    make(map[*kernel.Task]struct{}),
		path:     path,
		parent:   parent,
		children: make(map[*cgroup]struct{}),
		level:    parent.level + 1,
	}
	c.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), mode)
	c.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})

	c.IncLinks(c.OrderedChildren.Populate(fs.cgroupInodes(ctx, creds.EffectiveKUID, creds.EffectiveKGID, c)))

	c.init(ctx) // +checklocksforce: c.fs.treeMu is locked
	c.maxDescendants.Store(limitMax)
	c.maxDepth.Store(limitMax)
	parent.children[c] = struct{}{} // +checklocksforce: c.fs.treeMu is locked
	for curr := parent; curr != nil; curr = curr.parent {
		curr.nrDescendants.Add(1) // +checklocksforce: c.fs.treeMu is locked
	}

	return c
}

// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.CGROUP2_SUPER_MAGIC), nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.CGROUP2_SUPER_MAGIC), nil
}

func (fs *filesystem) nextMemoryID() uint32 {
	id := fs.nextMemCgroupID.Add(1)
	if id == 0 {
		id = fs.nextMemCgroupID.Add(1)
	}
	return id
}
