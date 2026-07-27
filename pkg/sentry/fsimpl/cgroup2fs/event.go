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
	// Event files are read-only: eventFD.Write unconditionally returns
	// EBADF. A writable event file would additionally need interfaceFD's
	// opener-namespace capture for the nsdelegate check to apply; reject
	// the combination outright rather than silently mishandling it.
	if _, ok := data.(vfs.WritableDynamicBytesSource); ok {
		panic("cgroup2fs: writable event file sources are not supported")
	}

	f := &eventFile{c: c}
	f.eventSeq.Store(1)

	src := &cgroupSourceReadOnly{c: c, ctrl: ctrl, src: data}
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
	// fd is passed twice, deliberately. As the vfs.FileDescriptionImpl
	// (first argument), VFS dispatches operations to eventFD rather than
	// the embedded DynamicBytesFD, which is what makes the Readiness/
	// EventRegister/EventUnregister overrides and the EBADF Write overrides
	// reachable.  As the bytes source (fourth argument), reads are routed
	// through eventFD.Generate, which snapshots into lastEventSeq the event
	// sequence number current at read time.
	if err := fd.InitWithImpl(fd, rp.Mount(), d, fd, f.Locks(), opts.Flags, rp.Credentials()); err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
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
	kernfs.DynamicBytesFD

	ep *eventFile

	lastEventSeq atomicbitops.Uint64
	data         vfs.DynamicBytesSource
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (fd *eventFD) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fd.lastEventSeq.Store(fd.ep.eventSeq.Load())
	return fd.data.Generate(ctx, buf)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *eventFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *eventFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EBADF
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
