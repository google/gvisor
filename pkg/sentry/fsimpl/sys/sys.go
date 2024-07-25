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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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
	// TestSysfsPathPrefix is a prefix for the sysfs paths. It is useful for
	// unit testing.
	TestSysfsPathPrefix string
}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
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

	classSub := map[string]kernfs.Inode{
		"power_supply": fs.newDir(ctx, creds, defaultSysDirMode, nil),
	}
	devicesSub := map[string]kernfs.Inode{
		"system": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"cpu": cpuDir(ctx, fs, creds),
		}),
	}

	productName := ""
	busSub := make(map[string]kernfs.Inode)
	kernelSub := kernelDir(ctx, fs, creds)
	if opts.InternalData != nil {
		idata := opts.InternalData.(*InternalData)
		productName = idata.ProductName
		if idata.EnableTPUProxyPaths {
			deviceToIOMMUGroup, err := pciDeviceIOMMUGroups(path.Join(idata.TestSysfsPathPrefix, iommuGroupSysPath))
			if err != nil {
				return nil, nil, err
			}
			sysDevicesPath := path.Join(idata.TestSysfsPathPrefix, sysDevicesMainPath)
			sysDevicesSub, err := fs.mirrorSysDevicesDir(ctx, creds, sysDevicesPath, deviceToIOMMUGroup)
			if err != nil {
				return nil, nil, err
			}
			for dir, sub := range sysDevicesSub {
				devicesSub[dir] = sub
			}

			deviceDirs, err := fs.newDeviceClassDir(ctx, creds, []string{accelDevice, vfioDevice}, sysDevicesPath)
			if err != nil {
				return nil, nil, err
			}

			for tpuDeviceType, symlinkDir := range deviceDirs {
				classSub[tpuDeviceType] = fs.newDir(ctx, creds, defaultSysDirMode, symlinkDir)
			}
			pciDevicesSub, err := fs.newBusPCIDevicesDir(ctx, creds, sysDevicesPath)
			if err != nil {
				return nil, nil, err
			}
			busSub["pci"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
				"devices": fs.newDir(ctx, creds, defaultSysDirMode, pciDevicesSub),
			})
			iommuPath := path.Join(idata.TestSysfsPathPrefix, iommuGroupSysPath)
			iommuGroups, err := fs.mirrorIOMMUGroups(ctx, creds, iommuPath)
			if err != nil {
				return nil, nil, err
			}
			kernelSub["iommu_groups"] = fs.newDir(ctx, creds, defaultSysDirMode, iommuGroups)
		}
	}

	if len(productName) > 0 {
		log.Debugf("Setting product_name: %q", productName)
		classSub["dmi"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"id": kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), "../../devices/virtual/dmi/id"),
		})
		devicesSub["virtual"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"dmi": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
				"id": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
					"product_name": fs.newStaticFile(ctx, creds, defaultSysMode, productName+"\n"),
				}),
			}),
		})
	}
	root := fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"block":    fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"bus":      fs.newDir(ctx, creds, defaultSysDirMode, busSub),
		"class":    fs.newDir(ctx, creds, defaultSysDirMode, classSub),
		"dev":      fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"devices":  fs.newDir(ctx, creds, defaultSysDirMode, devicesSub),
		"firmware": fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"fs":       fs.newDir(ctx, creds, defaultSysDirMode, fsDirChildren),
		"kernel":   fs.newDir(ctx, creds, defaultSysDirMode, kernelSub),
		"module":   fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"power":    fs.newDir(ctx, creds, defaultSysDirMode, nil),
	})
	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)
	return fs.VFSFilesystem(), rootD.VFSDentry(), nil
}

func cpuDir(ctx context.Context, fs *filesystem, creds *auth.Credentials) kernfs.Inode {
	k := kernel.KernelFromContext(ctx)
	maxCPUCores := k.ApplicationCores()
	children := map[string]kernfs.Inode{
		"online":   fs.newCPUFile(ctx, creds, maxCPUCores, linux.FileMode(0444)),
		"possible": fs.newCPUFile(ctx, creds, maxCPUCores, linux.FileMode(0444)),
		"present":  fs.newCPUFile(ctx, creds, maxCPUCores, linux.FileMode(0444)),
	}
	for i := uint(0); i < maxCPUCores; i++ {
		children[fmt.Sprintf("cpu%d", i)] = fs.newDir(ctx, creds, linux.FileMode(0555), nil)
	}
	return fs.newDir(ctx, creds, defaultSysDirMode, children)
}

// Returns a map from a PCI device name to its IOMMU group if available.
func pciDeviceIOMMUGroups(iommuGroupsPath string) (map[string]string, error) {
	// IOMMU groups are organized as iommu_group_path/$GROUP, where $GROUP is
	// the IOMMU group number of which the device is a member.
	iommuGroupNums, err := hostDirEntries(iommuGroupsPath)
	if err != nil {
		// When IOMMU is not enabled, skip the rest of the process.
		if err == unix.ENOENT {
			return nil, nil
		}
		return nil, err
	}
	// The returned map from PCI device name to its IOMMU group.
	iommuGroups := map[string]string{}
	for _, iommuGroupNum := range iommuGroupNums {
		groupDevicesPath := path.Join(iommuGroupsPath, iommuGroupNum, "devices")
		pciDeviceNames, err := hostDirEntries(groupDevicesPath)
		if err != nil {
			return nil, err
		}
		// An IOMMU group may include multiple devices.
		for _, pciDeviceName := range pciDeviceNames {
			iommuGroups[pciDeviceName] = iommuGroupNum
		}
	}
	return iommuGroups, nil
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
func (fs *filesystem) mirrorIOMMUGroups(ctx context.Context, creds *auth.Credentials, dir string) (map[string]kernfs.Inode, error) {
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
			contents, err := fs.mirrorIOMMUGroups(ctx, creds, absPath)
			if err != nil {
				return nil, err
			}
			subs[dent] = fs.newDir(ctx, creds, defaultSysMode, contents)
		case unix.S_IFREG:
			subs[dent] = fs.newHostFile(ctx, creds, defaultSysMode, absPath)
		case unix.S_IFLNK:
			if pciDeviceRegex.MatchString(dent) {
				pciBus := pciBusFromAddress(dent)
				subs[dent] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../../../devices/pci%s/%s", pciBus, dent))
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
	return vfs.GenericStatFS(linux.SYSFS_MAGIC), nil
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
