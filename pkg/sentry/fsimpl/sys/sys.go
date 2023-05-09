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
	"strconv"

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
		fsDirChildren["cgroup"] = fs.newDir(ctx, creds, defaultSysDirMode, nil)
	}

	classSub := map[string]kernfs.Inode{
		"power_supply": fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"net":          fs.newDir(ctx, creds, defaultSysDirMode, fs.newNetDir(ctx, creds, defaultSysDirMode)),
	}
	devicesSub := map[string]kernfs.Inode{
		"system": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"cpu": cpuDir(ctx, fs, creds),
		}),
	}

	productName := ""
	if opts.InternalData != nil {
		data := opts.InternalData.(*InternalData)
		productName = data.ProductName
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
		"bus":      fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"class":    fs.newDir(ctx, creds, defaultSysDirMode, classSub),
		"dev":      fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"devices":  fs.newDir(ctx, creds, defaultSysDirMode, devicesSub),
		"firmware": fs.newDir(ctx, creds, defaultSysDirMode, nil),
		"fs":       fs.newDir(ctx, creds, defaultSysDirMode, fsDirChildren),
		"kernel":   kernelDir(ctx, fs, creds),
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

func kernelDir(ctx context.Context, fs *filesystem, creds *auth.Credentials) kernfs.Inode {
	// Set up /sys/kernel/debug/kcov. Technically, debugfs should be
	// mounted at debug/, but for our purposes, it is sufficient to keep it
	// in sys.
	var children map[string]kernfs.Inode
	if coverage.KcovSupported() {
		log.Debugf("Set up /sys/kernel/debug/kcov")
		children = map[string]kernfs.Inode{
			"debug": fs.newDir(ctx, creds, linux.FileMode(0700), map[string]kernfs.Inode{
				"kcov": fs.newKcovFile(ctx, creds),
			}),
		}
	}
	return fs.newDir(ctx, creds, defaultSysDirMode, children)
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
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
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
