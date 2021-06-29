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
// cgroupfs dentries and inodes.
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
// kernel.CgroupRegistry.mu
//   cgroupfs.filesystem.mu
//     kernel.TaskSet.mu
//       kernel.Task.mu
//         cgroupfs.filesystem.tasksMu.
package cgroupfs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

const (
	// Name is the default filesystem name.
	Name                     = "cgroup"
	readonlyFileMode         = linux.FileMode(0444)
	writableFileMode         = linux.FileMode(0644)
	defaultMaxCachedDentries = uint64(1000)
)

const (
	controllerCPU     = kernel.CgroupControllerType("cpu")
	controllerCPUAcct = kernel.CgroupControllerType("cpuacct")
	controllerCPUSet  = kernel.CgroupControllerType("cpuset")
	controllerJob     = kernel.CgroupControllerType("job")
	controllerMemory  = kernel.CgroupControllerType("memory")
)

var allControllers = []kernel.CgroupControllerType{
	controllerCPU,
	controllerCPUAcct,
	controllerCPUSet,
	controllerJob,
	controllerMemory,
}

// SupportedMountOptions is the set of supported mount options for cgroupfs.
var SupportedMountOptions = []string{"all", "cpu", "cpuacct", "cpuset", "job", "memory"}

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// InternalData contains internal data passed in to the cgroupfs mount via
// vfs.GetFilesystemOptions.InternalData.
//
// +stateify savable
type InternalData struct {
	DefaultControlValues map[string]int64
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

	// controllers and kcontrollers are both the list of controllers attached to
	// this cgroupfs. Both lists are the same set of controllers, but typecast
	// to different interfaces for convenience. Both must stay in sync, and are
	// immutable.
	controllers  []controller
	kcontrollers []kernel.CgroupController

	numCgroups uint64 // Protected by atomic ops.

	root *kernfs.Dentry

	// tasksMu serializes task membership changes across all cgroups within a
	// filesystem.
	tasksMu sync.RWMutex `state:"nosave"`
}

// InitializeHierarchyID implements kernel.cgroupFS.InitializeHierarchyID.
func (fs *filesystem) InitializeHierarchyID(hid uint32) {
	fs.hierarchyID = hid
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
		wantControllers = append(wantControllers, controllerCPU)
	}
	if _, ok := mopts["cpuacct"]; ok {
		delete(mopts, "cpuacct")
		wantControllers = append(wantControllers, controllerCPUAcct)
	}
	if _, ok := mopts["cpuset"]; ok {
		delete(mopts, "cpuset")
		wantControllers = append(wantControllers, controllerCPUSet)
	}
	if _, ok := mopts["job"]; ok {
		delete(mopts, "job")
		wantControllers = append(wantControllers, controllerJob)
	}
	if _, ok := mopts["memory"]; ok {
		delete(mopts, "memory")
		wantControllers = append(wantControllers, controllerMemory)
	}
	if _, ok := mopts["all"]; ok {
		if len(wantControllers) > 0 {
			ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: other controllers specified with all: %v", wantControllers)
			return nil, nil, linuxerr.EINVAL
		}

		delete(mopts, "all")
		wantControllers = allControllers
	}

	if len(wantControllers) == 0 {
		// Specifying no controllers implies all controllers.
		wantControllers = allControllers
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
	if vfsfs := r.FindHierarchy(wantControllers); vfsfs != nil {
		fs := vfsfs.Impl().(*filesystem)
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: mounting new view to hierarchy %v", fs.hierarchyID)
		fs.root.IncRef()
		return vfsfs, fs.root.VFSDentry(), nil
	}

	// No existing hierarchy with the exactly controllers found. Make a new
	// one. Note that it's possible this mount creation is unsatisfiable, if one
	// or more of the requested controllers are already on existing
	// hierarchies. We'll find out about such collisions when we try to register
	// the new hierarchy later.
	fs := &filesystem{
		devMinor: devMinor,
	}
	fs.MaxCachedDentries = maxCachedDentries
	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)

	var defaults map[string]int64
	if opts.InternalData != nil {
		ctx.Debugf("cgroupfs.FilesystemType.GetFilesystem: default control values: %v", defaults)
		defaults = opts.InternalData.(*InternalData).DefaultControlValues
	}

	for _, ty := range wantControllers {
		var c controller
		switch ty {
		case controllerCPU:
			c = newCPUController(fs, defaults)
		case controllerCPUAcct:
			c = newCPUAcctController(fs)
		case controllerCPUSet:
			c = newCPUSetController(fs)
		case controllerJob:
			c = newJobController(fs)
		case controllerMemory:
			c = newMemoryController(fs, defaults)
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

	root := fs.newCgroupInode(ctx, creds)
	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)
	fs.root = &rootD

	// Register controllers. The registry may be modified concurrently, so if we
	// get an error, we raced with someone else who registered the same
	// controllers first.
	if err := r.Register(fs.kcontrollers, fs); err != nil {
		ctx.Infof("cgroupfs.FilesystemType.GetFilesystem: failed to register new hierarchy with controllers %v: %v", wantControllers, err)
		rootD.DecRef(ctx)
		fs.VFSFilesystem().DecRef(ctx)
		return nil, nil, syserror.EBUSY
	}

	// Move all existing tasks to the root of the new hierarchy.
	k.PopulateNewCgroupHierarchy(fs.rootCgroup())

	return fs.VFSFilesystem(), rootD.VFSDentry(), nil
}

func (fs *filesystem) rootCgroup() kernel.Cgroup {
	return kernel.Cgroup{
		Dentry:     fs.root,
		CgroupImpl: fs.root.Inode().(kernel.CgroupImpl),
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
	dirRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren // TODO(b/183137098): Implement mkdir.
	kernfs.OrderedChildren
	implStatFS

	locks vfs.FileLocks
}

// Keep implements kernfs.Inode.Keep.
func (*dir) Keep() bool {
	return true
}

// SetStat implements kernfs.Inode.SetStat not allowing inode attributes to be changed.
func (*dir) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return syserror.EPERM
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

// DecRef implements kernfs.Inode.DecRef.
func (d *dir) DecRef(ctx context.Context) {
	d.dirRefs.DecRef(func() { d.Destroy(ctx) })
}

// StatFS implements kernfs.Inode.StatFS.
func (d *dir) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.CGROUP_SUPER_MAGIC), nil
}

// controllerFile represents a generic control file that appears within a cgroup
// directory.
//
// +stateify savable
type controllerFile struct {
	kernfs.DynamicBytesFile
}

func (fs *filesystem) newControllerFile(ctx context.Context, creds *auth.Credentials, data vfs.DynamicBytesSource) kernfs.Inode {
	f := &controllerFile{}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), data, readonlyFileMode)
	return f
}

func (fs *filesystem) newControllerWritableFile(ctx context.Context, creds *auth.Credentials, data vfs.WritableDynamicBytesSource) kernfs.Inode {
	f := &controllerFile{}
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

// Note: We let the caller provide the mode so that static files may be used to
// fake both readable and writable control files. However, static files are
// effectively readonly, as attempting to write to them will return EIO
// regardless of the mode.
func (fs *filesystem) newStaticControllerFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, data string) kernfs.Inode {
	f := &staticControllerFile{StaticData: vfs.StaticData{Data: data}}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), f, mode)
	return f
}
