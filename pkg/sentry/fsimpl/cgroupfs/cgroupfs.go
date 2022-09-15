// Copyright 2021 The gVisor Authors.
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

// Package cgroupfs implements cgroupfs.
//
// A cgroup is a collection of tasks on the system, organized into a tree-like
// structure similar to a filesystem directory tree. In fact, each cgroup is
// represented by a directory on cgroupfs, and is manipulated through control
// files in the directory.
//
// All cgroups on a system are organized into hierarchies. Hierarchies are a
// distinct tree of cgroups, with a common set of controllers. One or more
// cgroupfs mounts may point to each hierarchy. These mounts provide a common
// view into the same tree of cgroups.
//
// A controller (also known as a "resource controller", or a cgroup "subsystem")
// determines the behaviour of each cgroup.
//
// In addition to cgroupfs, the kernel has a cgroup registry that tracks
// system-wide state related to cgroups such as active hierarchies and the
// controllers associated with them.
//
// Since cgroupfs doesn't allow hardlinks, there is a unique mapping between
// cgroupfs dentries and inodes. Thus, cgroupfs inodes don't need to be ref
// counted and exist until they're unlinked once or the FS is destroyed.
//
// # Synchronization
//
// Cgroup hierarchy creation and destruction is protected by the
// kernel.CgroupRegistry.mu. Once created, a hierarchy's set of controllers, the
// filesystem associated with it, and the root cgroup for the hierarchy are
// immutable.
//
// Membership of tasks within cgroups is protected by
// cgroupfs.filesystem.tasksMu. Tasks also maintain a set of all cgroups they're
// in, and this list is protected by Task.mu.
//
// Lock order:
//
//	kernel.CgroupRegistry.mu
//		kernfs.filesystem.mu
//		kernel.TaskSet.mu
//	  	kernel.Task.mu
//	    	cgroupfs.filesystem.tasksMu.
//	      	cgroupfs.dir.OrderedChildren.mu
package cgroupfs

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// Name is the default filesystem name.
	Name             = "cgroup"
	readonlyFileMode = linux.FileMode(0444)
	writableFileMode = linux.FileMode(0644)
	defaultDirMode   = linux.FileMode(0555) | linux.ModeDirectory

	defaultMaxCachedDentries = uint64(1000)
)

var allControllers = []kernel.CgroupControllerType{
	kernel.CgroupControllerCPU,
	kernel.CgroupControllerCPUAcct,
	kernel.CgroupControllerCPUSet,
	kernel.CgroupControllerJob,
	kernel.CgroupControllerMemory,
	kernel.CgroupControllerPIDs,
}

// SupportedMountOptions is the set of supported mount options for cgroupfs.
var SupportedMountOptions = []string{"all", "cpu", "cpuacct", "cpuset", "job", "memory", "pids"}

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// InitialCgroup specifies properties of the cgroup for the init task.
//
// +stateify savable
type InitialCgroup struct {
	// Path is an absolute path relative to the root of a cgroupfs filesystem
	// that indicates where to place the init task. An empty string indicates
	// the root of the filesystem.
	Path string

	// SetOwner indicates the UID and GID fields contain valid values. If true,
	// Both UID and GID must be provided.
	SetOwner bool
	// UID of the initial cgroup path components, excluding the root cgroup.
	UID auth.KUID
	// GID of the initial cgroup path components, excluding the root cgroup.
	GID auth.KGID

	// SetMode indicates the Mode field contains a valid value.
	SetMode bool
	// Mode of the initial cgroup path components, excluding the root cgroup.
	Mode linux.FileMode
}

// InternalData contains internal data passed in to the cgroupfs mount via
// vfs.GetFilesystemOptions.InternalData.
//
// +stateify savable
type InternalData struct {
	DefaultControlValues map[string]int64
	InitialCgroup        InitialCgroup
}

// filesystem implements vfs.FilesystemImpl and kernel.cgroupFS.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem
	devMinor uint32

	// hierarchyID is the id the cgroup registry assigns to this hierarchy. Has
	// the value kernel.InvalidCgroupHierarchyID until the FS is fully
	// initialized.
	//
	// hierarchyID is immutable after initialization.
	hierarchyID uint32

	// hierarchyName is the name for a named hierarchy. May be empty if the
	// 'name=' mount option was not used when the hierarchy was created.
	//
	// Immutable after initialization.
	hierarchyName string

	// controllers and kcontrollers are both the list of controllers attached to
	// this cgroupfs. Both lists are the same set of controllers, but typecast
	// to different interfaces for convenience. Both must stay in sync, and are
	// immutable.
	controllers  []controller
	kcontrollers []kernel.CgroupController

	numCgroups atomicbitops.Uint64 // Protected by atomic ops.

	root *kernfs.Dentry
	// effectiveRoot is the initial cgroup new tasks are created in. Unless
	// overwritten by internal mount options, root == effectiveRoot. If
	// effectiveRoot != root, an extra reference is held on effectiveRoot for
	// the lifetime of the filesystem.
	effectiveRoot *kernfs.Dentry

	// tasksMu serializes task membership changes across all cgroups within a
	// filesystem.
	tasksMu taskRWMutex `state:"nosave"`
}

// InitializeHierarchyID implements kernel.cgroupFS.InitializeHierarchyID.
func (fs *filesystem) InitializeHierarchyID(hid uint32) {
	fs.hierarchyID = hid
}

// RootCgroup implements kernel.cgroupFS.RootCgroup.
func (fs *filesystem) RootCgroup() kernel.Cgroup {
	return kernel.Cgroup{
		Dentry:     fs.root,
		CgroupImpl: fs.root.Inode().(kernel.CgroupImpl),
	}
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	mopts := vfs.GenericParseMountOptions(opts.Data)
	maxCachedDentries := defaultMaxCachedDentries
	if str, ok := mopts["dentry_cache_limit"]; ok {
		delete(mopts, "dentry_cache_limit")
		maxCachedDentries, err = strconv.ParseUint(str, 10, 64)
		if err != nil {
			ctx.Warningf("sys.FilesystemType.GetFilesystem: invalid dentry cache limit: dentry_cache_limit=%s", str)
			return nil, nil, linuxerr.EINVAL
		}
	}

	var wantControllers []kernel.CgroupControllerType
	if _, ok := mopts["cpu"]; ok {
		delete(mopts, "cpu")
		wantControllers = append(wantControllers, kernel.CgroupControllerCPU)
	}
	if _, ok := mopts["cpuacct"]; ok {
		delete(mopts, "cpuacct")
		wantControllers = append(wantControllers, kernel.CgroupControllerCPUAcct)
	}
	if _, ok := mopts["cpuset"]; ok {
		delete(mopts, "cpuset")
		wantControllers = append(wantControllers, kernel.CgroupControllerCPUSet)
	}
	if _, ok := mopts["job"]; ok {
		delete(mopts, "job")
		wantControllers = append(wantControllers, kernel.CgroupControllerJob)
	}
	if _, ok := mopts["memory"]; ok {
		delete(mopts, "memory")
		wantControllers = append(wantControllers, kernel.CgroupControllerMemory)
	}
	if _, ok := mopts["pids"]; ok {
		delete(mopts, "pids")
		wantControllers = append(wantControllers, kernel.CgroupControllerPIDs)
	}
	if _, ok := mopts["all"]; ok {
		if len(wantControllers) > 0 {
			ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: other controllers specified with all: %v", wantControllers)
			return nil, nil, linuxerr.EINVAL
		}

		delete(mopts, "all")
		wantControllers = allControllers
	}

	var name string
	var ok bool
	if name, ok = mopts["name"]; ok {
		delete(mopts, "name")
	}

	var none bool
	if _, ok = mopts["none"]; ok {
		none = true
		delete(mopts, "none")
	}

	if !none && len(wantControllers) == 0 {
		// Specifying no controllers implies all controllers, unless "none" was
		// explicitly requested.
		wantControllers = allControllers
	}

	// Some combinations of "none", "all", "name=" and explicit controllers are
	// not allowed. See Linux, kernel/cgroup.c:parse_cgroupfs_options().

	// All empty hierarchies must have a name.
	if len(wantControllers) == 0 && name == "" {
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: empty hierarchy with no name")
		return nil, nil, linuxerr.EINVAL
	}

	// Can't have "none" and some controllers.
	if none && len(wantControllers) != 0 {
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: 'none' specified with controllers: %v", wantControllers)
		return nil, nil, linuxerr.EINVAL
	}

	if len(mopts) != 0 {
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, linuxerr.EINVAL
	}

	k := kernel.KernelFromContext(ctx)
	r := k.CgroupRegistry()

	// "It is not possible to mount the same controller against multiple
	// cgroup hierarchies. For example, it is not possible to mount both
	// the cpu and cpuacct controllers against one hierarchy, and to mount
	// the cpu controller alone against another hierarchy." - man cgroups(7)
	//
	// Is there a hierarchy available with all the controllers we want? If so,
	// this mount is a view into the same hierarchy.
	//
	// Note: we're guaranteed to have at least one requested controller, since
	// no explicit controller name implies all controllers.
	vfsfs, err := r.FindHierarchy(name, wantControllers)
	if err != nil {
		return nil, nil, err
	}
	if vfsfs != nil {
		fs := vfsfs.Impl().(*filesystem)
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: mounting new view to hierarchy %v", fs.hierarchyID)
		fs.root.IncRef()
		if fs.effectiveRoot != fs.root {
			fs.effectiveRoot.IncRef()
		}
		return vfsfs, fs.root.VFSDentry(), nil
	}

	// No existing hierarchy with the exactly controllers found. Make a new
	// one. Note that it's possible this mount creation is unsatisfiable, if one
	// or more of the requested controllers are already on existing
	// hierarchies. We'll find out about such collisions when we try to register
	// the new hierarchy later.
	fs := &filesystem{
		devMinor:      devMinor,
		hierarchyName: name,
	}
	fs.MaxCachedDentries = maxCachedDentries
	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)

	var defaults map[string]int64
	if opts.InternalData != nil {
		defaults = opts.InternalData.(*InternalData).DefaultControlValues
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: default control values: %v", defaults)
	}

	for _, ty := range wantControllers {
		var c controller
		switch ty {
		case kernel.CgroupControllerCPU:
			c = newCPUController(fs, defaults)
		case kernel.CgroupControllerCPUAcct:
			c = newCPUAcctController(fs)
		case kernel.CgroupControllerCPUSet:
			c = newCPUSetController(k, fs)
		case kernel.CgroupControllerJob:
			c = newJobController(fs)
		case kernel.CgroupControllerMemory:
			c = newMemoryController(fs, defaults)
		case kernel.CgroupControllerPIDs:
			c = newRootPIDsController(fs)
		default:
			panic(fmt.Sprintf("Unreachable: unknown cgroup controller %q", ty))
		}
		fs.controllers = append(fs.controllers, c)
	}

	if len(defaults) != 0 {
		// Internal data is always provided at sentry startup and unused values
		// indicate a problem with the sandbox config. Fail fast.
		panic(fmt.Sprintf("cgroupfs.FilesystemType.GetFilesystem: unknown internal mount data: %v", defaults))
	}

	// Controllers usually appear in alphabetical order when displayed. Sort it
	// here now, so it never needs to be sorted elsewhere.
	sort.Slice(fs.controllers, func(i, j int) bool { return fs.controllers[i].Type() < fs.controllers[j].Type() })
	fs.kcontrollers = make([]kernel.CgroupController, 0, len(fs.controllers))
	for _, c := range fs.controllers {
		fs.kcontrollers = append(fs.kcontrollers, c)
	}

	root := fs.newCgroupInode(ctx, creds, nil, defaultDirMode)
	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)
	fs.root = &rootD
	fs.effectiveRoot = fs.root

	if err := fs.prepareInitialCgroup(ctx, vfsObj, opts); err != nil {
		ctx.Warningf("cgroupfs.FilesystemType.GetFilesystem: failed to prepare initial cgroup: %v", err)
		rootD.DecRef(ctx)
		fs.VFSFilesystem().DecRef(ctx)
		return nil, nil, err
	}

	// Register controllers. The registry may be modified concurrently, so if we
	// get an error, we raced with someone else who registered the same
	// controllers first.
	if err := r.Register(name, fs.kcontrollers, fs); err != nil {
		ctx.Infof("cgroupfs.FilesystemType.GetFilesystem: failed to register new hierarchy with controllers %v: %v", wantControllers, err)
		rootD.DecRef(ctx)
		fs.VFSFilesystem().DecRef(ctx)
		return nil, nil, linuxerr.EBUSY
	}

	// Move all existing tasks to the root of the new hierarchy.
	k.PopulateNewCgroupHierarchy(fs.effectiveRootCgroup())

	return fs.VFSFilesystem(), rootD.VFSDentry(), nil
}

// prepareInitialCgroup creates the initial cgroup according to opts. An initial
// cgroup is optional, and if not specified, this function is a no-op.
func (fs *filesystem) prepareInitialCgroup(ctx context.Context, vfsObj *vfs.VirtualFilesystem, opts vfs.GetFilesystemOptions) error {
	if opts.InternalData == nil {
		return nil
	}
	idata := opts.InternalData.(*InternalData)

	initPathStr := idata.InitialCgroup.Path
	if initPathStr == "" {
		return nil
	}
	ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: initial cgroup path: %v", initPathStr)
	initPath := fspath.Parse(initPathStr)
	if !initPath.Absolute {
		ctx.Warningf("cgroupfs.FilesystemType.GetFilesystem: initial cgroup path invalid: %+v", initPath)
		return linuxerr.EINVAL
	}
	if !initPath.HasComponents() {
		// Explicit "/" as initial cgroup, nothing to do.
		return nil
	}

	ownerCreds := auth.CredentialsFromContext(ctx).Fork()
	if idata.InitialCgroup.SetOwner {
		ownerCreds.EffectiveKUID = idata.InitialCgroup.UID
		ownerCreds.EffectiveKGID = idata.InitialCgroup.GID
	}
	mode := defaultDirMode
	if idata.InitialCgroup.SetMode {
		mode = idata.InitialCgroup.Mode
	}

	// Have initial cgroup target, create the tree.
	cgDir := fs.root.Inode().(*cgroupInode)
	for pit := initPath.Begin; pit.Ok(); pit = pit.Next() {
		cgDirI, err := cgDir.newDirWithOwner(ctx, ownerCreds, pit.String(), vfs.MkdirOptions{Mode: mode})
		if err != nil {
			return err
		}
		cgDir = cgDirI.(*cgroupInode)
	}

	// Walk to target dentry.
	initDentry, err := fs.root.WalkDentryTree(ctx, vfsObj, initPath)
	if err != nil {
		ctx.Warningf("cgroupfs.FilesystemType.GetFilesystem: initial cgroup dentry not found: %v", err)
		return linuxerr.ENOENT
	}
	fs.effectiveRoot = initDentry // Reference from WalkDentryTree transferred here.
	return nil
}

func (fs *filesystem) effectiveRootCgroup() kernel.Cgroup {
	return kernel.Cgroup{
		Dentry:     fs.effectiveRoot,
		CgroupImpl: fs.effectiveRoot.Inode().(kernel.CgroupImpl),
	}
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	k := kernel.KernelFromContext(ctx)
	r := k.CgroupRegistry()

	if fs.hierarchyID != kernel.InvalidCgroupHierarchyID {
		k.ReleaseCgroupHierarchy(fs.hierarchyID)
		r.Unregister(fs.hierarchyID)
	}

	if fs.root != fs.effectiveRoot {
		fs.effectiveRoot.DecRef(ctx)
	}

	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	var cnames []string
	for _, c := range fs.controllers {
		cnames = append(cnames, string(c.Type()))
	}
	return strings.Join(cnames, ",")
}

// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.CGROUP_SUPER_MAGIC), nil
}

// dir implements kernfs.Inode for a generic cgroup resource controller
// directory. Specific controllers extend this to add their own functionality.
//
// +stateify savable
type dir struct {
	kernfs.InodeNoopRefCount
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeWatches
	kernfs.OrderedChildren
	implStatFS

	locks vfs.FileLocks

	fs  *filesystem  // Immutable.
	cgi *cgroupInode // Immutable.
}

// Keep implements kernfs.Inode.Keep.
func (*dir) Keep() bool {
	return true
}

// SetStat implements kernfs.Inode.SetStat.
func (d *dir) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return d.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// Open implements kernfs.Inode.Open.
func (d *dir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), kd, &d.OrderedChildren, &d.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndStaticEntries,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// NewDir implements kernfs.Inode.NewDir.
func (d *dir) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	return d.newDirWithOwner(ctx, auth.CredentialsFromContext(ctx), name, opts)
}

func (d *dir) newDirWithOwner(ctx context.Context, ownerCreds *auth.Credentials, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	// "Do not accept '\n' to prevent making /proc/<pid>/cgroup unparsable."
	//   -- Linux, kernel/cgroup.c:cgroup_mkdir().
	if strings.Contains(name, "\n") {
		return nil, linuxerr.EINVAL
	}
	mode := opts.Mode.Permissions() | linux.ModeDirectory
	return d.OrderedChildren.Inserter(name, func() kernfs.Inode {
		d.IncLinks(1)
		return d.fs.newCgroupInode(ctx, ownerCreds, d.cgi, mode)
	})
}

// Rename implements kernfs.Inode.Rename. Cgroupfs only allows renaming of
// cgroup directories, and the rename may only change the name within the same
// parent. See linux, kernel/cgroup.c:cgroup_rename().
func (d *dir) Rename(ctx context.Context, oldname, newname string, child, dst kernfs.Inode) error {
	if _, ok := child.(*cgroupInode); !ok {
		// Not a cgroup directory. Control files are backed by different types.
		return linuxerr.ENOTDIR
	}

	dstCGInode, ok := dst.(*cgroupInode)
	if !ok {
		// Not a cgroup inode, so definitely can't be *this* inode.
		return linuxerr.EIO
	}
	// Note: We're intentionally comparing addresses, since two different dirs
	// could plausibly be identical in memory, but would occupy different
	// locations in memory.
	if d != &dstCGInode.dir {
		// Destination dir is a different cgroup inode. Cross directory renames
		// aren't allowed.
		return linuxerr.EIO
	}

	// Rename moves oldname to newname within d. Proceed.
	return d.OrderedChildren.Rename(ctx, oldname, newname, child, dst)
}

// Unlink implements kernfs.Inode.Unlink. Cgroupfs disallows unlink, as the only
// files in the filesystem are control files, which can't be deleted.
func (d *dir) Unlink(ctx context.Context, name string, child kernfs.Inode) error {
	return linuxerr.EPERM
}

// hasChildrenLocked returns whether the cgroup dir contains any objects that
// prevent it from being deleted.
func (d *dir) hasChildrenLocked() bool {
	// Subdirs take a link on the parent, so checks if there are any direct
	// children cgroups. Exclude the dir's self link and the link from ".".
	if d.InodeAttrs.Links()-2 > 0 {
		return true
	}
	return len(d.cgi.ts) > 0
}

// HasChildren implements kernfs.Inode.HasChildren.
//
// The empty check for a cgroupfs directory is unlike a regular directory since
// a cgroupfs directory will always have control files. A cgroupfs directory can
// be deleted if cgroup contains no tasks and has no sub-cgroups.
func (d *dir) HasChildren() bool {
	d.fs.tasksMu.RLock()
	defer d.fs.tasksMu.RUnlock()
	return d.hasChildrenLocked()
}

// RmDir implements kernfs.Inode.RmDir.
func (d *dir) RmDir(ctx context.Context, name string, child kernfs.Inode) error {
	// Unlike a normal directory, we need to recheck if d is empty again, since
	// vfs/kernfs can't stop tasks from entering or leaving the cgroup.
	d.fs.tasksMu.RLock()
	defer d.fs.tasksMu.RUnlock()

	cgi, ok := child.(*cgroupInode)
	if !ok {
		return linuxerr.ENOTDIR
	}
	if cgi.dir.hasChildrenLocked() {
		return linuxerr.ENOTEMPTY
	}

	// Disallow deletion of the effective root cgroup.
	if cgi == d.fs.effectiveRoot.Inode().(*cgroupInode) {
		ctx.Warningf("Cannot delete initial cgroup for new tasks %q", d.fs.effectiveRoot.FSLocalPath())
		return linuxerr.EBUSY
	}

	err := d.OrderedChildren.RmDir(ctx, name, child)
	if err == nil {
		d.InodeAttrs.DecLinks()
	}
	return err
}

func (d *dir) forEachChildDir(fn func(*dir)) {
	d.OrderedChildren.ForEachChild(func(_ string, i kernfs.Inode) {
		if childI, ok := i.(*cgroupInode); ok {
			fn(&childI.dir)
		}
	})
}

// controllerFileImpl represents common cgroupfs-specific operations for control
// files.
type controllerFileImpl interface {
	// Source extracts the underlying DynamicBytesFile for a control file.
	Source() *kernfs.DynamicBytesFile
	// AllowBackgroundAccess indicates whether a control file can be accessed
	// from a background (i.e. non-task) context. Some control files cannot be
	// meaningfully accessed from a non-task context because accessing them
	// either have side effects on the calling context (ex: task migration
	// across cgroups), or they refer to data which must be interpreted within
	// the calling context (ex: when referring to a pid, in which pid
	// namespace?).
	//
	// Currently, all writable control files that allow access from a background
	// process can handle a nil FD, since a background write doesn't explicitly
	// open the control file. This is enforced through the
	// writableControllerFileImpl.
	AllowBackgroundAccess() bool
}

// writableControllerFileImpl represents common cgroupfs-specific operations for
// a writable control file.
type writableControllerFileImpl interface {
	controllerFileImpl
	// WriteBackground writes data to a control file from a background
	// context. This means the write isn't performed through and FD may be
	// performed from a background context.
	//
	// Control files that support this should also return true for
	// controllerFileImpl.AllowBackgroundAccess().
	WriteBackground(ctx context.Context, src usermem.IOSequence) (int64, error)
}

// controllerFile represents a generic control file that appears within a cgroup
// directory.
//
// +stateify savable
type controllerFile struct {
	kernfs.DynamicBytesFile
	allowBackgroundAccess bool
}

var _ controllerFileImpl = (*controllerFile)(nil)

// Source implements controllerFileImpl.Source.
func (f *controllerFile) Source() *kernfs.DynamicBytesFile {
	return &f.DynamicBytesFile
}

// AllowBackgroundAccess implements controllerFileImpl.AllowBackgroundAccess.
func (f *controllerFile) AllowBackgroundAccess() bool {
	return f.allowBackgroundAccess
}

// SetStat implements kernfs.Inode.SetStat.
func (f *controllerFile) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return f.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

func (fs *filesystem) newControllerFile(ctx context.Context, creds *auth.Credentials, data vfs.DynamicBytesSource, allowBackgroundAccess bool) kernfs.Inode {
	f := &controllerFile{
		allowBackgroundAccess: allowBackgroundAccess,
	}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), data, readonlyFileMode)
	return f
}

func (fs *filesystem) newControllerWritableFile(ctx context.Context, creds *auth.Credentials, data vfs.WritableDynamicBytesSource, allowBackgroundAccess bool) kernfs.Inode {
	f := &controllerFile{
		allowBackgroundAccess: allowBackgroundAccess,
	}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), data, writableFileMode)
	return f
}

// staticControllerFile represents a generic control file that appears within a
// cgroup directory which always returns the same data when read.
// staticControllerFiles are not writable.
//
// +stateify savable
type staticControllerFile struct {
	kernfs.DynamicBytesFile
	vfs.StaticData
}

var _ controllerFileImpl = (*staticControllerFile)(nil)

// Source implements controllerFileImpl.Source.
func (f *staticControllerFile) Source() *kernfs.DynamicBytesFile {
	return &f.DynamicBytesFile
}

// AllowBackgroundAccess implements controllerFileImpl.AllowBackgroundAccess.
func (f *staticControllerFile) AllowBackgroundAccess() bool {
	return true
}

// SetStat implements kernfs.Inode.SetStat.
func (f *staticControllerFile) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return f.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// Note: We let the caller provide the mode so that static files may be used to
// fake both readable and writable control files. However, static files are
// effectively readonly, as attempting to write to them will return EIO
// regardless of the mode.
func (fs *filesystem) newStaticControllerFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, data string) kernfs.Inode {
	f := &staticControllerFile{StaticData: vfs.StaticData{Data: data}}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), f, mode)
	return f
}

// stubControllerFile is a writable control file that remembers the control
// value written to it.
//
// +stateify savable
type stubControllerFile struct {
	controllerFile

	// data is accessed through atomic ops.
	data *atomicbitops.Int64
}

var _ controllerFileImpl = (*stubControllerFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *stubControllerFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", f.data.Load())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *stubControllerFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return f.WriteBackground(ctx, src)
}

// WriteBackground implements writableControllerFileImpl.WriteBackground.
func (f *stubControllerFile) WriteBackground(ctx context.Context, src usermem.IOSequence) (int64, error) {
	val, n, err := parseInt64FromString(ctx, src)
	if err != nil {
		return 0, err
	}
	f.data.Store(val)
	return n, nil
}

// newStubControllerFile creates a new stub controller file that loads and
// stores a control value from data.
func (fs *filesystem) newStubControllerFile(ctx context.Context, creds *auth.Credentials, data *atomicbitops.Int64, allowBackgroundAccess bool) kernfs.Inode {
	f := &stubControllerFile{
		controllerFile: controllerFile{
			allowBackgroundAccess: allowBackgroundAccess,
		},
		data: data,
	}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), f, writableFileMode)
	return f
}
