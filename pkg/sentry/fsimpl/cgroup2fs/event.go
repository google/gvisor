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

package cgroup2fs

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// eventFile represents a generic cgroup event file that supports both poll()
// via a sequence counter and inotify.
//
// +stateify savable
type eventFile struct {
	kernfs.DynamicBytesFile
	c *cgroup

	notifyQueue waiter.Queue
	eventSeq    atomicbitops.Uint64
}

// Valid implements kernfs.Inode.Valid.
func (f *eventFile) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	return !f.c.deleted.Load()
}

func (fs *filesystem) newEventFile(ctx context.Context, uid auth.KUID, gid auth.KGID, c *cgroup, data vfs.DynamicBytesSource, ctrl controller) *eventFile {
	f := &eventFile{c: c}
	f.eventSeq.Store(1)
	var src vfs.DynamicBytesSource
	if ws, ok := data.(vfs.WritableDynamicBytesSource); ok {
		src = &cgroupSourceWritable{c: c, ctrl: ctrl, src: ws}
	} else {
		src = &cgroupSourceReadOnly{c: c, ctrl: ctrl, src: data}
	}
	f.DynamicBytesFile.InitWithIDs(ctx, uid, gid, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), src, 0444)
	return f
}

// SetStat implements kernfs.Inode.SetStat.
func (f *eventFile) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return f.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// Open implements kernfs.Inode.Open overriding DynamicBytesFile open method.
func (f *eventFile) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	data, err := f.Data(ctx)
	if err != nil {
		return nil, err
	}
	fd := &eventFD{ep: f, data: data}
	if err := fd.Init(rp.Mount(), d, fd, opts.Flags, rp.Credentials()); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Notify signals waiters and inotify watches that an event has occurred.
func (f *eventFile) Notify(ctx context.Context) {
	f.eventSeq.Add(1)
	f.notifyQueue.Notify(waiter.EventMask(waiter.EventPri | waiter.ReadableEvents))
	f.Watches().Notify(ctx, "", linux.IN_MODIFY, 0, vfs.InodeEvent, false)
}

// eventFD implements vfs.FileDescriptionImpl providing poll readiness.
//
// +stateify savable
type eventFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DynamicBytesFileDescriptionImpl
	vfs.NoLockFD

	vfsfd vfs.FileDescription
	ep    *eventFile

	lastEventSeq atomicbitops.Uint64
	data         vfs.DynamicBytesSource
}

// Init overrides DynamicBytesFD.Init to initialize vfsfd correctly.
func (fd *eventFD) Init(m *vfs.Mount, d *kernfs.Dentry, data vfs.DynamicBytesSource, flags uint32, creds *auth.Credentials) error {
	if err := fd.vfsfd.Init(fd, flags, creds, m, d.VFSDentry(),
		&vfs.FileDescriptionOptions{
			DenySpliceIn: true,
		},
	); err != nil {
		return err
	}
	fd.DynamicBytesFileDescriptionImpl.Init(&fd.vfsfd, data)
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *eventFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Seek(ctx, offset, whence)
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (fd *eventFD) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fd.lastEventSeq.Store(fd.ep.eventSeq.Load())
	return fd.data.Generate(ctx, buf)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *eventFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.Read(ctx, dst, opts)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *eventFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return fd.DynamicBytesFileDescriptionImpl.PRead(ctx, dst, offset, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *eventFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *eventFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *eventFD) Release(context.Context) {}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *eventFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.ep.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *eventFD) SetStat(context.Context, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *eventFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	ready := waiter.ReadableEvents
	if fd.lastEventSeq.Load() < fd.ep.eventSeq.Load() {
		ready |= waiter.EventPri | waiter.EventErr
	}
	return ready & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *eventFD) EventRegister(e *waiter.Entry) error {
	fd.ep.notifyQueue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *eventFD) EventUnregister(e *waiter.Entry) {
	fd.ep.notifyQueue.EventUnregister(e)
}
