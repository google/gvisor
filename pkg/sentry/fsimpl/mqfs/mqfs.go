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
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	"gvisor.dev/gvisor/pkg/sentry/kernel/mq"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	// Name is the user-visible filesystem name.
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
	// mqfs is initialized only once per ipc namespace. Each ipc namespace has
	// a POSIX message registry with a root dentry, filesystem, and a
	// disconnected mount. We want the fs to be consistent for all processes in
	// the same ipc namespace, so instead of creating a new fs and root dentry,
	// we retreive them using IPCNamespace.PosixQueues and use them.

	i := ipcNamespaceFromContext(ctx)
	if i == nil {
		return nil, nil, fmt.Errorf("mqfs.FilesystemType.GetFilesystem: ipc namespace doesn't exist")
	}
	defer i.DecRef(ctx)

	registry := i.PosixQueues()
	if registry == nil {
		return nil, nil, fmt.Errorf("mqfs.FilesystemType.GetFilesystem: ipc namespace doesn't have a POSIX registry")
	}
	impl := registry.Impl().(*RegistryImpl)

	maxCachedDentries, err := maxCachedDentries(ctx, vfs.GenericParseMountOptions(opts.Data))
	if err != nil {
		return nil, nil, err
	}
	impl.fs.MaxCachedDentries = maxCachedDentries

	impl.fs.VFSFilesystem().IncRef()
	impl.root.IncRef()
	return impl.fs.VFSFilesystem(), impl.root.VFSDentry(), nil
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

// ipcNamespace defines functions we need from kernel.IPCNamespace. We redefine
// ipcNamespace along with ipcNamespaceFromContext to avoid circular dependency
// with package sentry/kernel.
type ipcNamespace interface {
	// PosixQueues returns a POSIX message queue registry.
	PosixQueues() *mq.Registry

	// DecRef decrements ipcNamespace's number of references.
	DecRef(ctx context.Context)
}

// ipcNamespaceFromContext returns the IPC namespace in which ctx is executing.
// Copied from package sentry/kernel.
func ipcNamespaceFromContext(ctx context.Context) ipcNamespace {
	if v := ctx.Value(ipc.CtxIPCNamespace); v != nil {
		return v.(ipcNamespace)
	}
	return nil
}
