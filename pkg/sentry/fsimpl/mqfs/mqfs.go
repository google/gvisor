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

// Package mqfs provides a filesystem implementation to back POSIX message
// queues.
package mqfs

import (
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	Name                     = "mqueue"
	defaultMaxCachedDentries = uint64(1000)
)

// FilesystemType implements vfs.FilesystemType.
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
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	maxCachedDentries, err := maxCachedDentries(ctx, vfs.GenericParseMountOptions(opts.Data))
	if err != nil {
		return nil, nil, err
	}

	fs := &filesystem{
		devMinor: devMinor,
		Filesystem: kernfs.Filesystem{
			MaxCachedDentries: maxCachedDentries,
		},
	}
	fs.VFSFilesystem().Init(vfsObj, &ft, fs)

	var dentry kernfs.Dentry
	dentry.InitRoot(&fs.Filesystem, fs.newRootInode(ctx, creds))

	return fs.VFSFilesystem(), dentry.VFSDentry(), nil
}

// maxCachedDentries checks mopts for dentry_cache_limit. If a value is
// specified, parse it into uint64 and return it. Otherwise, return the default
// value. An error is returned if a value is found but can't be parsed.
func maxCachedDentries(ctx context.Context, mopts map[string]string) (_ uint64, err error) {
	max := defaultMaxCachedDentries
	if str, ok := mopts["dentry_cache_limit"]; ok {
		delete(mopts, "dentry_cache_limit")
		max, err = strconv.ParseUint(str, 10, 64)
		if err != nil {
			ctx.Warningf("mqfs.FilesystemType.GetFilesystem: invalid dentry cache limit: dentry_cache_limit=%s", str)
			return 0, linuxerr.EINVAL
		}
	}
	return max, nil
}

// filesystem implements kernfs.Filesystem.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem
	devMinor uint32
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
