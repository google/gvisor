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

package devpts

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ExternalReplica is a replica node for a terminal that devpts does not
// implement, such as a host TTY. Opening the node opens the terminal through
// kernel.TTYOperations.OpenTTY.
//
// The node does not hold a reference on the terminal. The owner of the
// terminal must call Remove when the terminal is released, and OpenTTY must
// fail after that.
//
// +stateify savable
type ExternalReplica struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotAnonymous
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches
	kernfs.InodeFSOwned

	// root is the devpts root inode. It is immutable.
	root *rootInode

	// n is the pty index. It is immutable.
	n uint32

	// tty is the terminal. It is immutable.
	tty *kernel.TTY
}

var _ kernfs.Inode = (*ExternalReplica)(nil)

// AddExternalReplica creates a replica node for tty in the devpts filesystem
// whose root is vd. The node is owned as if creds created a pty. It sets the
// device number of tty to that of the node.
func AddExternalReplica(ctx context.Context, vd vfs.VirtualDentry, creds *auth.Credentials, tty *kernel.TTY) (*ExternalReplica, error) {
	if _, ok := vd.Mount().Filesystem().Impl().(*filesystem); !ok {
		return nil, fmt.Errorf("%T is not a devpts filesystem", vd.Mount().Filesystem().Impl())
	}
	root, ok := vd.Dentry().Impl().(*kernfs.Dentry).Inode().(*rootInode)
	if !ok {
		return nil, fmt.Errorf("dentry is not the root of a devpts filesystem")
	}

	root.mu.Lock()
	defer root.mu.Unlock()
	idx, err := root.allocateIndexLocked()
	if err != nil {
		return nil, err
	}
	er := &ExternalReplica{
		root: root,
		n:    idx,
		tty:  tty,
	}
	root.initReplicaAttrs(ctx, &er.InodeAttrs, creds, idx)
	tty.SetDeviceID(linux.UNIX98_PTY_REPLICA_MAJOR, idx)
	root.externals[idx] = er
	return er, nil
}

// Index returns the pty index of the node.
func (er *ExternalReplica) Index() uint32 {
	return er.n
}

// Remove removes the node from its devpts filesystem, and clears the device
// number of its terminal.
//
// +checklocksexclude:er.root.mu
func (er *ExternalReplica) Remove(context.Context) {
	er.root.mu.Lock()
	defer er.root.mu.Unlock()
	if er.root.externals[er.n] == er {
		delete(er.root.externals, er.n)
		er.tty.SetDeviceID(0, 0)
	}
}

// Open implements kernfs.Inode.Open.
func (er *ExternalReplica) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := er.tty.OpenTTY(ctx, rp.Mount(), d.VFSDentry(), opts)
	if err != nil {
		return nil, err
	}
	if tsk := kernel.TaskFromContext(ctx); tsk != nil && opts.Flags&linux.O_NOCTTY == 0 {
		// As for other replicas, opening the node sets the process'
		// controlling TTY when possible. See Linux tty_open().
		_ = tsk.ThreadGroup().SetControllingTTY(ctx, er.tty, false /* steal */, fd.IsReadable())
	}
	return fd, nil
}

// Valid implements kernfs.Inode.Valid.
//
// +checklocksexclude:er.root.mu
func (er *ExternalReplica) Valid(context.Context, *kernfs.Dentry, string) bool {
	er.root.mu.Lock()
	defer er.root.mu.Unlock()
	return er.root.externals[er.n] == er
}

// Stat implements kernfs.Inode.Stat.
func (er *ExternalReplica) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	statx, err := er.InodeAttrs.Stat(ctx, vfsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	statx.Blksize = 1024
	statx.RdevMajor = linux.UNIX98_PTY_REPLICA_MAJOR
	statx.RdevMinor = er.n
	return statx, nil
}

// SetStat implements kernfs.Inode.SetStat.
func (er *ExternalReplica) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		return linuxerr.EINVAL
	}
	return er.InodeAttrs.SetStat(ctx, vfsfs, creds, opts)
}
