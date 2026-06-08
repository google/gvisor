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

// Package mountfd provides a "mount object" file descriptor, as returned by fsmount(2)
// or open_tree(2) with OPEN_TREE_CLONE.
//
// A mount object fd can be used as an argument to move_mount(2) to place the mount
// on the directory tree, or it can be used as a dirfd argument to the *at() syscalls.
// If a mount object fd is closed without calling move_mount(2), the mount is unmounted.
package mountfd

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Fd represents a mount object file descriptor.
type Fd struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// anonNS is the anonymous mount namespace created for backing this mount.
	anonNS *vfs.MountNamespace
}

// New creates a new mount object file descriptor from the anonymous mount namespace anonNs
// and the mount at the root of anonNS. Consumes a reference on anonNS.
func New(ctx context.Context, anonNS *vfs.MountNamespace, fileFlags uint32) (*vfs.FileDescription, error) {
	fd := &Fd{
		anonNS: anonNS,
	}

	// The mount comes from the root of the anonymous mount namespace
	root := anonNS.Root(ctx)
	defer root.DecRef(ctx)

	err := fd.vfsfd.Init(fd, fileFlags, auth.CredentialsFromContext(ctx), root.Mount(), root.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	})
	if err != nil {
		anonNS.DecRef(ctx)
		return nil, err
	}

	return &fd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *Fd) Release(ctx context.Context) {
	// Decrement the references on the mount's anonymous namespace.
	// If move_mount(2) was not called, this will also result in the filesystem being unmounted.
	fd.anonNS.DecRef(ctx)
}
