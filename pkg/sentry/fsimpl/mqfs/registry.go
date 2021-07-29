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

package mqfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/mq"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// RegistryImpl implements mq.RegistryImpl. It implements the interface using
// the message queue filesystem, and is provided to mq.Registry at
// initialization.
//
// +stateify savable
type RegistryImpl struct {
	// mu protects all fields below.
	mu sync.Mutex

	// root is the root dentry of the mq filesystem. Its main usage is to
	// retreive the root inode, which we use to add, remove, and lookup message
	// queues.
	//
	// We hold a reference on root and release when the registry is destroyed.
	root *kernfs.Dentry

	// fs is the filesystem backing this registry, used mainly to initialize
	// new inodes.
	fs *filesystem

	// mount is the mount point used for this filesystem.
	mount *vfs.Mount
}

// NewRegistryImpl returns a new, initialized RegistryImpl, and takes a
// reference on root.
func NewRegistryImpl(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (*RegistryImpl, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, err
	}

	var dentry kernfs.Dentry
	fs := &filesystem{
		devMinor: devMinor,
		root:     &dentry,
	}
	fs.VFSFilesystem().Init(vfsObj, &FilesystemType{}, fs)

	dentry.InitRoot(&fs.Filesystem, fs.newRootInode(ctx, creds))
	dentry.IncRef()

	mount, err := vfsObj.NewDisconnectedMount(fs.VFSFilesystem(), dentry.VFSDentry(), &vfs.MountOptions{})
	if err != nil {
		return nil, err
	}

	return &RegistryImpl{
		root:  &dentry,
		fs:    fs,
		mount: mount,
	}, nil
}

// Lookup implements mq.RegistryImpl.Lookup.
func (r *RegistryImpl) Lookup(ctx context.Context, name string) *mq.Queue {
	r.mu.Lock()
	defer r.mu.Unlock()

	inode, err := r.lookup(ctx, name)
	if err != nil {
		return nil
	}
	return inode.(*queueInode).queue
}

// New implements mq.RegistryImpl.New.
func (r *RegistryImpl) New(ctx context.Context, name string, q *mq.Queue, perm linux.FileMode) (*vfs.FileDescription, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	root := r.root.Inode().(*rootInode)
	qInode := r.fs.newQueueInode(ctx, auth.CredentialsFromContext(ctx), q, perm).(*queueInode)
	err := root.Insert(name, qInode)
	if err != nil {
		return nil, err
	}

	fd := &queueFD{queue: q}
	err = fd.Init(r.mount, r.root, q, qInode.Locks(), 0 /* flags */)
	if err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Unlink implements mq.RegistryImpl.Unlink.
func (r *RegistryImpl) Unlink(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	root := r.root.Inode().(*rootInode)
	inode, err := r.lookup(ctx, name)
	if err != nil {
		return err
	}
	return root.Unlink(ctx, name, inode)
}

// lookup retreives a kernfs.Inode using a name.
//
// Precondition: r.mu must be held.
func (r *RegistryImpl) lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	inode := r.root.Inode().(*rootInode)
	lookup, err := inode.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	return lookup, nil
}

// Destroy implements mq.RegistryImpl.Destroy.
func (r *RegistryImpl) Destroy(ctx context.Context) {
	r.root.DecRef(ctx)
}
