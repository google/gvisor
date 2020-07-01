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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Name is the default filesystem name.
const Name = "sysfs"

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	fs := &filesystem{
		devMinor: devMinor,
	}
	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)
	k := kernel.KernelFromContext(ctx)
	maxCPUCores := k.ApplicationCores()
	defaultSysDirMode := linux.FileMode(0755)

	root := fs.newDir(creds, defaultSysDirMode, map[string]*kernfs.Dentry{
		"block": fs.newDir(creds, defaultSysDirMode, nil),
		"bus":   fs.newDir(creds, defaultSysDirMode, nil),
		"class": fs.newDir(creds, defaultSysDirMode, map[string]*kernfs.Dentry{
			"power_supply": fs.newDir(creds, defaultSysDirMode, nil),
		}),
		"dev": fs.newDir(creds, defaultSysDirMode, nil),
		"devices": fs.newDir(creds, defaultSysDirMode, map[string]*kernfs.Dentry{
			"system": fs.newDir(creds, defaultSysDirMode, map[string]*kernfs.Dentry{
				"cpu": fs.newDir(creds, defaultSysDirMode, map[string]*kernfs.Dentry{
					"online":   fs.newCPUFile(creds, maxCPUCores, linux.FileMode(0444)),
					"possible": fs.newCPUFile(creds, maxCPUCores, linux.FileMode(0444)),
					"present":  fs.newCPUFile(creds, maxCPUCores, linux.FileMode(0444)),
				}),
			}),
		}),
		"firmware": fs.newDir(creds, defaultSysDirMode, nil),
		"fs":       fs.newDir(creds, defaultSysDirMode, nil),
		"kernel":   fs.newDir(creds, defaultSysDirMode, nil),
		"module":   fs.newDir(creds, defaultSysDirMode, nil),
		"power":    fs.newDir(creds, defaultSysDirMode, nil),
	})
	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release()
}

// dir implements kernfs.Inode.
type dir struct {
	kernfs.InodeAttrs
	kernfs.InodeNoDynamicLookup
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.OrderedChildren

	locks vfs.FileLocks

	dentry kernfs.Dentry
}

func (fs *filesystem) newDir(creds *auth.Credentials, mode linux.FileMode, contents map[string]*kernfs.Dentry) *kernfs.Dentry {
	d := &dir{}
	d.InodeAttrs.Init(creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.dentry.Init(d)

	d.IncLinks(d.OrderedChildren.Populate(&d.dentry, contents))

	return &d.dentry
}

// SetStat implements Inode.SetStat not allowing inode attributes to be changed.
func (*dir) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return syserror.EPERM
}

// Open implements kernfs.Inode.Open.
func (d *dir) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), vfsd, &d.OrderedChildren, &d.locks, &opts)
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// cpuFile implements kernfs.Inode.
type cpuFile struct {
	kernfs.DynamicBytesFile
	maxCores uint
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "0-%d\n", c.maxCores-1)
	return nil
}

func (fs *filesystem) newCPUFile(creds *auth.Credentials, maxCores uint, mode linux.FileMode) *kernfs.Dentry {
	c := &cpuFile{maxCores: maxCores}
	c.DynamicBytesFile.Init(creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), c, mode)
	d := &kernfs.Dentry{}
	d.Init(c)
	return d
}
