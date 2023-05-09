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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/mq"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	maxCachedDentries = 1000
)

// RegistryImpl implements mq.RegistryImpl. It implements the interface using
// the message queue filesystem, and is provided to mq.Registry at
// initialization.
//
// RegistryImpl is not thread-safe, so it is the responsibility of the user
// (the containing mq.Registry) to protect using a lock.
//
// +stateify savable
type RegistryImpl struct {
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

	fs := &filesystem{
		devMinor:   devMinor,
		Filesystem: kernfs.Filesystem{MaxCachedDentries: maxCachedDentries},
	}
	fs.VFSFilesystem().Init(vfsObj, &FilesystemType{}, fs)
	vfsfs := fs.VFSFilesystem()
	// NewDisconnectedMount will obtain a ref on dentry and vfsfs which is
	// transferred to mount. vfsfs was initiated with 1 ref already. So get rid
	// of the extra ref.
	defer vfsfs.DecRef(ctx)

	// dentry is initialized with 1 ref which is transferred to fs.
	var dentry kernfs.Dentry
	dentry.InitRoot(&fs.Filesystem, fs.newRootInode(ctx, creds))

	mount := vfsObj.NewDisconnectedMount(vfsfs, dentry.VFSDentry(), &vfs.MountOptions{})

	return &RegistryImpl{
		root:  &dentry,
		fs:    fs,
		mount: mount,
	}, nil
}

// Get implements mq.RegistryImpl.Get.
func (r *RegistryImpl) Get(ctx context.Context, name string, access mq.AccessType, block bool, flags uint32) (*vfs.FileDescription, bool, error) {
	inode, err := r.root.Inode().(*rootInode).Lookup(ctx, name)
	if err != nil {
		return nil, false, nil
	}

	qInode := inode.(*queueInode)
	if !qInode.queue.HasPermissions(auth.CredentialsFromContext(ctx), perm(access)) {
		// "The queue exists, but the caller does not have permission to
		//  open it in the specified mode."
		return nil, false, linuxerr.EACCES
	}

	fd, err := r.newFD(qInode.queue, qInode, access, block, flags)
	if err != nil {
		return nil, false, err
	}
	return fd, true, nil
}

// New implements mq.RegistryImpl.New.
func (r *RegistryImpl) New(ctx context.Context, name string, q *mq.Queue, access mq.AccessType, block bool, perm linux.FileMode, flags uint32) (*vfs.FileDescription, error) {
	root := r.root.Inode().(*rootInode)
	qInode := r.fs.newQueueInode(ctx, auth.CredentialsFromContext(ctx), q, perm).(*queueInode)
	err := root.Insert(name, qInode)
	if err != nil {
		return nil, err
	}
	return r.newFD(q, qInode, access, block, flags)
}

// Unlink implements mq.RegistryImpl.Unlink.
func (r *RegistryImpl) Unlink(ctx context.Context, name string) error {
	creds := auth.CredentialsFromContext(ctx)
	if err := r.root.Inode().CheckPermissions(ctx, creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}

	root := r.root.Inode().(*rootInode)
	inode, err := root.Lookup(ctx, name)
	if err != nil {
		return err
	}
	return root.Unlink(ctx, name, inode)
}

// Destroy implements mq.RegistryImpl.Destroy.
func (r *RegistryImpl) Destroy(ctx context.Context) {
	r.root.DecRef(ctx)
	r.mount.DecRef(ctx)
}

// newFD returns a new file description created using the given queue and inode.
func (r *RegistryImpl) newFD(q *mq.Queue, inode *queueInode, access mq.AccessType, block bool, flags uint32) (*vfs.FileDescription, error) {
	view, err := mq.NewView(q, access, block)
	if err != nil {
		return nil, err
	}

	var dentry kernfs.Dentry
	dentry.Init(&r.fs.Filesystem, inode)

	fd := &queueFD{queue: view}
	err = fd.Init(r.mount, &dentry, inode.queue, inode.Locks(), flags)
	if err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// perm returns a permission mask created using given flags.
func perm(access mq.AccessType) vfs.AccessTypes {
	switch access {
	case mq.ReadWrite:
		return vfs.MayRead | vfs.MayWrite
	case mq.WriteOnly:
		return vfs.MayWrite
	case mq.ReadOnly:
		return vfs.MayRead
	default:
		return 0 // Can't happen, see NewView.
	}
}
