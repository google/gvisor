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

// Package proc implements a partial in-memory file system for procfs.
package proc

import (
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync/locking"
)

const (
	// Name is the default filesystem name.
	Name                     = "proc"
	defaultMaxCachedDentries = uint64(1000)
)

// FilesystemType is the factory class for procfs.
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

var lockClassGenerator = locking.NewLockClassGenerator("procfs")

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (ft FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, nil, fmt.Errorf("procfs requires a kernel")
	}
	pidns := kernel.PIDNamespaceFromContext(ctx)
	if pidns == nil {
		return nil, nil, fmt.Errorf("procfs requires a PID namespace")
	}
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
			ctx.Warningf("proc.FilesystemType.GetFilesystem: invalid dentry cache limit: dentry_cache_limit=%s", str)
			return nil, nil, linuxerr.EINVAL
		}
	}

	procfs := &filesystem{
		devMinor: devMinor,
	}
	procfs.Init(lockClassGenerator)
	procfs.MaxCachedDentries = maxCachedDentries
	procfs.VFSFilesystem().Init(vfsObj, &ft, procfs)

	var fakeCgroupControllers map[string]string
	if opts.InternalData != nil {
		data := opts.InternalData.(*InternalData)
		fakeCgroupControllers = data.Cgroups
	}

	inode := procfs.newTasksInode(ctx, k, pidns, fakeCgroupControllers)
	var dentry kernfs.Dentry
	dentry.InitRoot(&procfs.Filesystem, inode)
	return procfs.VFSFilesystem(), dentry.VFSDentry(), nil
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

// dynamicInode is an overfitted interface for common Inodes with
// dynamicByteSource types used in procfs.
//
// +stateify savable
type dynamicInode interface {
	kernfs.Inode
	vfs.DynamicBytesSource

	Init(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, data vfs.DynamicBytesSource, perm linux.FileMode)
}

func (fs *filesystem) newInode(ctx context.Context, creds *auth.Credentials, perm linux.FileMode, inode dynamicInode) dynamicInode {
	inode.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), inode, perm)
	return inode
}

// +stateify savable
type staticFile struct {
	kernfs.DynamicBytesFile
	vfs.StaticData
}

var _ dynamicInode = (*staticFile)(nil)

func newStaticFile(data string) *staticFile {
	return &staticFile{StaticData: vfs.StaticData{Data: data}}
}

func (fs *filesystem) newStaticDir(ctx context.Context, creds *auth.Credentials, children map[string]kernfs.Inode) kernfs.Inode {
	return kernfs.NewStaticDir(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), 0555, children, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndZero,
	})
}

// InternalData contains internal data passed in to the procfs mount via
// vfs.GetFilesystemOptions.InternalData.
//
// +stateify savable
type InternalData struct {
	Cgroups map[string]string
}

// +stateify savable
type implStatFS struct{}

// StatFS implements kernfs.Inode.StatFS.
func (*implStatFS) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.PROC_SUPER_MAGIC), nil
}
