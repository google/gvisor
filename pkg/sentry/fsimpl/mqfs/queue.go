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
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// queueInode represents an inode for a message queue (/dev/mqueue/[name]).
//
// +stateify savable
type queueInode struct {
	kernfs.DynamicBytesFile

	// queue is the message queue backing this inode.
	queue *mq.Queue
}

var _ kernfs.Inode = (*queueInode)(nil)

// newQueueInode returns a new, initialized queueInode.
func (fs *filesystem) newQueueInode(ctx context.Context, creds *auth.Credentials, q *mq.Queue, perm linux.FileMode) kernfs.Inode {
	inode := &queueInode{queue: q}
	inode.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), q, perm)
	return inode
}

// Keep implements kernfs.Inode.Keep.
func (q *queueInode) Keep() bool {
	// Return true so that the fs keeps newly created dentries. This is done
	// because inodes returned by root.Lookup are not temporary, they exist
	// in the fs, and refer to message queues.
	return true
}

// queueFD implements vfs.FileDescriptionImpl for FD backed by a POSIX message
// queue. It's mostly similar to DynamicBytesFD, but implements more operations.
//
// +stateify savable
type queueFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DynamicBytesFileDescriptionImpl
	vfs.LockFD
	vfs.NoSpliceInFD

	vfsfd vfs.FileDescription
	inode kernfs.Inode

	// queue is a view into the queue backing this fd.
	queue mq.View
}

// Init initializes a queueFD. Mostly copied from DynamicBytesFD.Init, but uses
// the queueFD as FileDescriptionImpl.
func (fd *queueFD) Init(m *vfs.Mount, d *kernfs.Dentry, data vfs.DynamicBytesSource, locks *vfs.FileLocks, flags uint32) error {
	fd.LockFD.Init(locks)
	if err := fd.vfsfd.Init(fd, flags, m, d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return err
	}
	fd.inode = d.Inode()
	fd.SetDataSource(data)
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *queueFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Seek(ctx, offset, whence)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *queueFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Read(ctx, dst, opts)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *queueFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.PRead(ctx, dst, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *queueFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Write(ctx, src, opts)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *queueFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.PWrite(ctx, src, offset, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *queueFD) Release(context.Context) {}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *queueFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *queueFD) SetStat(context.Context, vfs.SetStatOptions) error {
	// DynamicBytesFiles are immutable.
	return linuxerr.EPERM
}

// OnClose implements FileDescriptionImpl.OnClose similar to
// ipc/mqueue.c::mqueue_flush_file.
func (fd *queueFD) OnClose(ctx context.Context) error {
	fd.queue.Flush(ctx)
	return nil
}

// Readiness implements waiter.Waitable.Readiness similar to
// ipc/mqueue.c::mqueue_poll_file.
func (fd *queueFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fd.queue.Readiness(mask)
}

// EventRegister implements Waitable.EventRegister.
func (fd *queueFD) EventRegister(e *waiter.Entry) error {
	return fd.queue.EventRegister(e)
}

// EventUnregister implements Waitable.EventUnregister.
func (fd *queueFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
}
