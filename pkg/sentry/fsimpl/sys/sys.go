// Copyright 2019 The gVisor Authors.
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

// Package sys implements sysfs.
package sys

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/rdma"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// Name is the default filesystem name.
	Name                     = "sysfs"
	defaultSysMode           = linux.FileMode(0444)
	defaultSysDirMode        = linux.FileMode(0755)
	defaultMaxCachedDentries = uint64(1000)
	iommuGroupSysPath        = "/sys/kernel/iommu_groups/"
)

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// InternalData contains internal data passed in via
// vfs.GetFilesystemOptions.InternalData.
//
// +stateify savable
type InternalData struct {
	// ProductName is the value to be set to devices/virtual/dmi/id/product_name.
	ProductName string
	// EnableTPUProxyPaths is whether to populate sysfs paths used by hardware
	// accelerators.
	EnableTPUProxyPaths bool
	// RDMASysfs, when non-nil, is the host sysfs snapshot from which the
	// RDMA device topology (/sys/devices/pci..., /sys/class/infiniband*,
	// /sys/class/net, /sys/class/pci_bus, /sys/bus/pci/devices,
	// /sys/devices/system/node) is constructed.
	RDMASysfs *rdma.Snapshot
	// TestSysfsPathPrefix is a prefix for the sysfs paths. It is useful for
	// unit testing.
	TestSysfsPathPrefix string
}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor            uint32
	enableTPUProxyPaths bool
	testSysfsPathPrefix string
	// productName is the value of devices/virtual/dmi/id/product_name. If
	// empty, the DMI directories are not created.
	productName string
	root        *dir
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

	fs := &filesystem{
		devMinor: devMinor,
	}
	fs.MaxCachedDentries = maxCachedDentries
	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)

	k := kernel.KernelFromContext(ctx)
	fsDirChildren := make(map[string]kernfs.Inode)
	// Create an empty directory to serve as the mount point for cgroupfs when
	// cgroups are available. This emulates Linux behaviour, see
	// kernel/cgroup.c:cgroup_init(). Note that in Linux, userspace (typically
	// the init process) is ultimately responsible for actually mounting
	// cgroupfs, but the kernel creates the mountpoint. For the sentry, the
	// launcher mounts cgroupfs.
	if k.CgroupRegistry() != nil {
		fsDirChildren["cgroup"] = fs.newCgroupDir(ctx, creds, defaultSysDirMode, nil)
	}

	classSub := map[string]kernfs.Inode{ // /sys/class
		"power_supply": fs.newDir(ctx, creds, defaultSysDirMode, nil),
	}
	devicesSub := map[string]kernfs.Inode{} // /sys/devices
	systemSub := map[string]kernfs.Inode{   // /sys/devices/system
		"cpu": cpuDir(ctx, fs, creds),
	}

	busSub := make(map[string]kernfs.Inode)     // /sys/bus
	pciDevices := make(map[string]kernfs.Inode) // /sys/bus/pci/devices
	pciDrivers := make(map[string]kernfs.Inode) // /sys/bus/pci/drivers
	kernelSub := kernelDir(ctx, fs, creds)      // /sys/kernel
	if opts.InternalData != nil {
		idata := opts.InternalData.(*InternalData)
		fs.productName = idata.ProductName
		if idata.EnableTPUProxyPaths {
			fs.enableTPUProxyPaths = true
			fs.testSysfsPathPrefix = idata.TestSysfsPathPrefix

			sysDevicesPath := path.Join(idata.TestSysfsPathPrefix, sysDevicesMainPath)
			iommuGroupsPath := path.Join(idata.TestSysfsPathPrefix, iommuGroupSysPath)
			pciInfos, err := pciDeviceInfos(sysDevicesPath, iommuGroupsPath)
			if err != nil {
				return nil, nil, err
			}

			sysDevicesSub, err := fs.mirrorSysDevicesDir(ctx, creds, sysDevicesPath, pciInfos)
			if err != nil {
				return nil, nil, err
			}
			for dir, sub := range sysDevicesSub {
				devicesSub[dir] = sub
			}

			deviceDirs, err := fs.newDeviceClassDir(ctx, creds, []string{accelDevice, vfioDevice}, sysDevicesPath, pciInfos)
			if err != nil {
				return nil, nil, err
			}
			for tpuDeviceType, symlinkDir := range deviceDirs {
				classSub[tpuDeviceType] = fs.newDir(ctx, creds, defaultSysDirMode, symlinkDir)
			}

			pciDevicesSub, err := fs.newBusPCIDevicesDir(ctx, creds, pciInfos)
			if err != nil {
				return nil, nil, err
			}
			for name, sub := range pciDevicesSub {
				pciDevices[name] = sub
			}

			iommuGroups, err := fs.mirrorIOMMUGroups(ctx, creds, iommuGroupsPath, pciInfos)
			if err != nil {
				return nil, nil, err
			}
			kernelSub["iommu_groups"] = fs.newDir(ctx, creds, defaultSysDirMode, iommuGroups)
		}
		if idata.RDMASysfs != nil {
			rdmaDirs, err := fs.newRDMASysfs(ctx, creds, idata.RDMASysfs)
			if err != nil {
				return nil, nil, err
			}
			for name, sub := range rdmaDirs.devices {
				// The TPU-proxy devices and the RDMA ConnectX devices come from
				// two different accelerator stacks and aren't exposed to the
				// same sandbox today, so a shared /sys/devices root complex
				// shouldn't occur. Deep-merging two sealed kernfs subtrees
				// isn't supported, so reject an overlap.
				if _, ok := devicesSub[name]; ok {
					return nil, nil, fmt.Errorf("TPU proxy and RDMA sysfs both populate /sys/devices/%s", name)
				}
				devicesSub[name] = sub
			}
			for name, sub := range rdmaDirs.class {
				classSub[name] = sub
			}
			for name, sub := range rdmaDirs.busPCIDevices {
				pciDevices[name] = sub
			}
			for name, sub := range rdmaDirs.busPCIDrivers {
				pciDrivers[name] = sub
			}
			if rdmaDirs.node != nil {
				systemSub["node"] = rdmaDirs.node
			}
		}
	}
	if len(pciDevices) > 0 || len(pciDrivers) > 0 {
		pciSub := map[string]kernfs.Inode{}
		if len(pciDevices) > 0 {
			pciSub["devices"] = fs.newDir(ctx, creds, defaultSysDirMode, pciDevices)
		}
		if len(pciDrivers) > 0 {
			pciSub["drivers"] = fs.newDir(ctx, creds, defaultSysDirMode, pciDrivers)
		}
		busSub["pci"] = fs.newDir(ctx, creds, defaultSysDirMode, pciSub)
	}
	devicesSub["system"] = fs.newDir(ctx, creds, defaultSysDirMode, systemSub)

	fs.addDMIDirs(ctx, creds, classSub, devicesSub)
	root := fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"block": fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"bus":   fs.newDir(ctx, creds, defaultSysDirMode, busSub),
		"class": fs.newDir(ctx, creds, defaultSysDirMode, classSub),
		"dev": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"block": fs.newDir(ctx, creds, defaultSysDirMode, nil),
			"char":  fs.newDir(ctx, creds, defaultSysDirMode, nil),
		}),
		"devices":  fs.newDir(ctx, creds, defaultSysDirMode, devicesSub),
		"firmware": fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"fs":       fs.newDir(ctx, creds, defaultSysDirMode, fsDirChildren),
		"kernel":   fs.newDir(ctx, creds, defaultSysDirMode, kernelSub),
		"module":   fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"power":    fs.newDir(ctx, creds, defaultSysDirMode, nil),
	})
	fs.root = root.(*dir)
	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)
	return fs.VFSFilesystem(), rootD.VFSDentry(), nil
}

// addDMIDirs adds the DMI entries to classSub (/sys/class) and devicesSub
// (/sys/devices) if fs.productName is set.
func (fs *filesystem) addDMIDirs(ctx context.Context, creds *auth.Credentials, classSub, devicesSub map[string]kernfs.Inode) {
	if len(fs.productName) == 0 {
		return
	}
	log.Debugf("Setting product_name: %q", fs.productName)
	classSub["dmi"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"id": kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), "../../devices/virtual/dmi/id"),
	})
	devicesSub["virtual"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"dmi": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"id": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
				"product_name": fs.newStaticFile(ctx, creds, defaultSysMode, fs.productName+"\n"),
			}),
		}),
	})
}

// cpuDir returns the inode for /sys/devices/system/cpu.
func cpuDir(ctx context.Context, fs *filesystem, creds *auth.Credentials) kernfs.Inode {
	cores := kernel.KernelFromContext(ctx).ApplicationCores()
	return fs.newLazyCPURootDir(ctx, creds, cores)
}

// fullCPUMask returns a "hex format ASCII string", consistent with Linux's
// include/linux/cpumask.h:cpumap_print_to_pagebuf(list=false) =>
// lib/bitmap.c:bitmap_print_to_pagebuf(list=false), representing a CPU bitmask
// in which all `cores` CPUs are set.
func fullCPUMask(cores uint) string {
	var (
		b   strings.Builder
		sep string
	)
	if rem := cores % 32; rem != 0 {
		cores -= rem
		fmt.Fprintf(&b, "%x", (uint32(1)<<rem)-1)
		sep = ","
	}
	for cores != 0 {
		cores -= 32
		fmt.Fprintf(&b, "%sffffffff", sep)
		sep = ","
	}
	return b.String()
}

// oneCPUMask returns a "hex format ASCII string", consistent with Linux's
// include/linux/cpumask.h:cpumap_print_to_pagebuf(list=false) =>
// lib/bitmap.c:bitmap_print_to_pagebuf(list=false), representing a CPU bitmask
// for `cores` CPUs in which only CPU `i` is set.
//
// Preconditions: i < cores.
func oneCPUMask(i, cores uint) string {
	var (
		b   strings.Builder
		sep string
	)
	word := func() (w uint32) {
		if cores <= i {
			w = uint32(1) << (i - cores)
		}
		return
	}
	if rem := cores % 32; rem != 0 {
		cores -= rem
		chars := (rem + 3) / 4 // 4 bits per hex character
		fmt.Fprintf(&b, "%0*x", chars, word())
		sep = ","
	}
	for cores != 0 {
		cores -= 32
		fmt.Fprintf(&b, "%s%08x", sep, word())
		sep = ","
	}
	return b.String()
}

func kernelDir(ctx context.Context, fs *filesystem, creds *auth.Credentials) map[string]kernfs.Inode {
	// Set up /sys/kernel/debug/kcov. Technically, debugfs should be
	// mounted at debug/, but for our purposes, it is sufficient to keep it
	// in sys.
	children := make(map[string]kernfs.Inode)
	if coverage.KcovSupported() {
		log.Debugf("Set up /sys/kernel/debug/kcov")
		children["debug"] = fs.newDir(ctx, creds, linux.FileMode(0700), map[string]kernfs.Inode{
			"kcov": fs.newKcovFile(ctx, creds),
		})
	}
	return children
}

// Recursively build out IOMMU directories from the host.
func (fs *filesystem) mirrorIOMMUGroups(ctx context.Context, creds *auth.Credentials, dir string, pciInfos map[string]*pciDeviceInfo) (map[string]kernfs.Inode, error) {
	subs := map[string]kernfs.Inode{}
	dents, err := hostDirEntries(dir)
	if err != nil {
		// TPU before v5 doesn't need IOMMU, skip the whole process for the backward compatibility when the directory can't be found.
		if err == unix.ENOENT {
			log.Debugf("Skip the path at %v which cannot be found.", dir)
			return nil, nil
		}
		return nil, err
	}
	for _, dent := range dents {
		absPath := path.Join(dir, dent)
		mode, err := hostFileMode(absPath)
		if err != nil {
			return nil, err
		}
		switch mode {
		case unix.S_IFDIR:
			contents, err := fs.mirrorIOMMUGroups(ctx, creds, absPath, pciInfos)
			if err != nil {
				return nil, err
			}
			subs[dent] = fs.newDir(ctx, creds, defaultSysMode, contents)
		case unix.S_IFREG:
			subs[dent] = fs.newHostFile(ctx, creds, defaultSysMode, absPath)
		case unix.S_IFLNK:
			if pciDeviceRegex.MatchString(dent) {
				info, ok := pciInfos[dent]
				if !ok {
					log.Infof("Skipping IOMMU group link %q: not a known PCI device", absPath)
					continue
				}
				subs[dent] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../../../devices/%s", info.path))
			}
		}
	}
	return subs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return fmt.Sprintf("dentry_cache_limit=%d", fs.MaxCachedDentries)
}

// dir implements kernfs.Inode.
//
// +stateify savable
type dir struct {
	dirRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNotAnonymous
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary
	kernfs.InodeWatches
	kernfs.InodeFSOwned
	kernfs.OrderedChildren

	locks vfs.FileLocks
}

func (fs *filesystem) newDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, contents map[string]kernfs.Inode) kernfs.Inode {
	d := &dir{}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	d.IncLinks(d.OrderedChildren.Populate(contents))
	return d
}

func (fs *filesystem) newCgroupDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, contents map[string]kernfs.Inode) kernfs.Inode {
	d := &cgroupDir{}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	d.IncLinks(d.OrderedChildren.Populate(contents))
	return d
}

// SetStat implements kernfs.Inode.SetStat not allowing inode attributes to be changed.
func (*dir) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// Open implements kernfs.Inode.Open.
func (d *dir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), kd, rp.Credentials(), &d.OrderedChildren, &d.locks, &opts, kernfs.GenericDirectoryFDOptions{
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
	return vfs.GenericStatFS(linux.SYSFS_MAGIC), nil
}

// cpuRootDir is the value of lazyDir.cpu for /sys/devices/system/cpu.
const cpuRootDir = -1

// lazyDir is a directory in /sys/devices/system/cpu whose children are created
// on first use.
//
// Most workloads never access the per-CPU directories in
// /sys/devices/system/cpu. Creating them lazily keeps unused inodes out of
// memory and out of checkpoints: directories that were never populated are
// saved empty, and are populated after restore if needed.
//
// +stateify savable
type lazyDir struct {
	dir

	fs    *filesystem
	creds *auth.Credentials
	cores uint

	// cpu is the CPU index for /sys/devices/system/cpu/cpuN, or cpuRootDir
	// for /sys/devices/system/cpu itself. Immutable.
	cpu int

	// populateMu serializes populate calls.
	populateMu sync.Mutex `state:"nosave"`

	// populated is true once the children of the directory have been
	// created.
	populated atomicbitops.Bool
}

var _ kernfs.Inode = (*lazyDir)(nil)

// newLazyCPURootDir returns the lazyDir for /sys/devices/system/cpu.
func (fs *filesystem) newLazyCPURootDir(ctx context.Context, creds *auth.Credentials, cores uint) *lazyDir {
	d := fs.newLazyDir(ctx, creds, cores, cpuRootDir)
	// Apps read these files often. Create these files now,
	// so that lookups of these files do not create the
	// cpuN directories.
	d.OrderedChildren.Populate(map[string]kernfs.Inode{
		"online":   fs.newCPUFile(ctx, creds, cores, defaultSysMode),
		"possible": fs.newCPUFile(ctx, creds, cores, defaultSysMode),
		"present":  fs.newCPUFile(ctx, creds, cores, defaultSysMode),
	})
	return d
}

// newLazyCPUDir returns the lazyDir for /sys/devices/system/cpu/cpuN.
func (fs *filesystem) newLazyCPUDir(ctx context.Context, creds *auth.Credentials, cores, cpu uint) *lazyDir {
	return fs.newLazyDir(ctx, creds, cores, int(cpu))
}

func (fs *filesystem) newLazyDir(ctx context.Context, creds *auth.Credentials, cores uint, cpu int) *lazyDir {
	d := &lazyDir{
		fs:    fs,
		creds: creds,
		cores: cores,
		cpu:   cpu,
	}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|defaultSysDirMode)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	// Set the link count of the populated directory now, so that Stat does
	// not need to populate d.
	d.IncLinks(d.subdirs())
	return d
}

// subdirs returns the number of subdirectories that populate creates. That
// is either one cpuN directory per core in /sys/devices/system/cpu, or the
// single topology directory in each cpuN directory.
func (d *lazyDir) subdirs() uint32 {
	if d.cpu == cpuRootDir {
		return uint32(d.cores)
	}
	return 1
}

// children returns the children of d that populate creates.
func (d *lazyDir) children(ctx context.Context) map[string]kernfs.Inode {
	if d.cpu == cpuRootDir {
		children := make(map[string]kernfs.Inode, d.cores)
		for i := uint(0); i < d.cores; i++ {
			children["cpu"+strconv.FormatUint(uint64(i), 10)] = d.fs.newLazyCPUDir(ctx, d.creds, d.cores, i)
		}
		return children
	}
	// For consistency with /proc/cpuinfo, pretend all CPUs are in the same
	// socket and each CPU is a distinct core.
	fullMask := fullCPUMask(d.cores) + "\n"
	oneMask := oneCPUMask(uint(d.cpu), d.cores) + "\n"
	return map[string]kernfs.Inode{
		"topology": d.fs.newDir(ctx, d.creds, defaultSysDirMode, map[string]kernfs.Inode{
			"core_cpus":       d.fs.newStaticFile(ctx, d.creds, defaultSysMode, oneMask),
			"core_siblings":   d.fs.newStaticFile(ctx, d.creds, defaultSysMode, fullMask),
			"package_cpus":    d.fs.newStaticFile(ctx, d.creds, defaultSysMode, fullMask),
			"thread_siblings": d.fs.newStaticFile(ctx, d.creds, defaultSysMode, oneMask),
		}),
	}
}

// populate creates the children of d, unless that has already been done.
func (d *lazyDir) populate(ctx context.Context) {
	if d.populated.Load() {
		return
	}
	d.populateMu.Lock()
	defer d.populateMu.Unlock()
	if d.populated.Load() {
		return
	}
	if links, want := d.OrderedChildren.Populate(d.children(ctx)), d.subdirs(); links != want {
		panic(fmt.Sprintf("lazyDir(cpu=%d) populated %d subdirectories, want %d", d.cpu, links, want))
	}
	d.populated.Store(true)
}

// Lookup implements kernfs.Inode.Lookup.
func (d *lazyDir) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	// Only populate the cpuN directories when they are accessed directly,
	// not on access of the general cpu directory.
	if d.cpu != cpuRootDir || isCPUDirName(name) {
		d.populate(ctx)
	}
	return d.dir.Lookup(ctx, name)
}

// isCPUDirName returns true if name is of the form "cpuN".
func isCPUDirName(name string) bool {
	const prefix = "cpu"
	if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
		return false
	}
	for i := len(prefix); i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// Open implements kernfs.Inode.Open.
func (d *lazyDir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Populate before GenericDirectoryFD reads d.OrderedChildren.
	d.populate(ctx)
	return d.dir.Open(ctx, rp, kd, opts)
}

// HasChildren implements kernfs.Inode.HasChildren.
func (d *lazyDir) HasChildren() bool {
	// lazyDir.children never returns an empty map.
	return !d.populated.Load() || d.dir.HasChildren()
}

// cgroupDir implements kernfs.Inode.
//
// +stateify savable
type cgroupDir struct {
	dir
}

// StatFS implements kernfs.Inode.StatFS.
func (d *cgroupDir) StatFS(ctx context.Context, fs *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.TMPFS_MAGIC), nil
}

// cpuFile implements kernfs.Inode.
//
// +stateify savable
type cpuFile struct {
	implStatFS
	kernfs.DynamicBytesFile

	maxCores uint
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "0-%d\n", c.maxCores-1)
	return nil
}

func (fs *filesystem) newCPUFile(ctx context.Context, creds *auth.Credentials, maxCores uint, mode linux.FileMode) kernfs.Inode {
	c := &cpuFile{maxCores: maxCores}
	c.DynamicBytesFile.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), c, mode)
	return c
}

// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.SYSFS_MAGIC), nil
}

// +stateify savable
type staticFile struct {
	kernfs.DynamicBytesFile
	vfs.StaticData
}

func (fs *filesystem) newStaticFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, data string) kernfs.Inode {
	s := &staticFile{StaticData: vfs.StaticData{Data: data}}
	s.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), s, mode)
	return s
}

// hostFile is an inode whose contents are generated by reading from the
// host.
//
// +stateify savable
type hostFile struct {
	kernfs.DynamicBytesFile
	hostPath string
}

func (hf *hostFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fd, err := unix.Openat(-1, hf.hostPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), hf.hostPath)
	defer file.Close()
	_, err = buf.ReadFrom(file)
	return err
}

func (fs *filesystem) newHostFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, hostPath string) kernfs.Inode {
	hf := &hostFile{hostPath: hostPath}
	hf.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), hf, mode)
	return hf
}

// errorFile is an inode whose reads fail with a fixed errno.
//
// +stateify savable
type errorFile struct {
	kernfs.DynamicBytesFile
	errno int32
}

func (ef *errorFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return unix.Errno(ef.errno)
}

func (fs *filesystem) newErrorFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, errno int32) kernfs.Inode {
	ef := &errorFile{errno: errno}
	ef.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), ef, mode)
	return ef
}
