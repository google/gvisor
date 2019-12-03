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

package adaptfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"

	vfs1 "gvisor.dev/gvisor/pkg/sentry/fs"
	vfs2 "gvisor.dev/gvisor/pkg/sentry/vfs"
)

type fileDescription struct {
	vfs2fd vfs2.FileDescription
	vfs2.FileDescriptionDefaultImpl
	vfs1fd *vfs1.File
}

func (fs *filesystem) newFileDescription(vfs1fd *vfs1.File, statusFlags uint32, mnt *vfs2.Mount, d *dentry) *fileDescription {
	fd := &fileDescription{
		vfs1fd: vfs1fd,
	}
	fd.vfs2fd.Init(fd, statusFlags, mnt, &d.vfs2d, &vfs2.FileDescriptionOptions{})
	return fd
}

func (fd *fileDescription) dentry() *dentry {
	return fd.vfs2fd.Dentry().Impl().(*dentry)
}

// Release implements vfs2.FileDescriptionImpl.Release.
func (fd *fileDescription) Release() {
	fd.vfs1fd.DecRef()
	if fd.vfs1fd.Flags().Write {
		fd.vfs2fd.Mount().EndWrite()
	}
}

// OnClose implements vfs2.FileDescriptionImpl.OnClose.
func (fd *fileDescription) OnClose(ctx context.Context) error {
	return fd.vfs1fd.Flush(ctx)
}

// Stat implements vfs2.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs2.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	err := fd.dentry().statTo(ctx, &stat)
	return stat, err
}

// SetStat implements vfs2.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs2.SetStatOptions) error {
	return fd.dentry().setStat(ctx, auth.CredentialsFromContext(ctx), &opts.Stat, fd.vfs2fd.Mount())
}

// StatFS implements vfs2.FileDescriptionImpl.StatFS.
func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.dentry().statfs(ctx)
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *fileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fd.vfs1fd.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *fileDescription) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	fd.vfs1fd.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *fileDescription) EventUnregister(e *waiter.Entry) {
	fd.vfs1fd.EventUnregister(e)
}

// PRead implements vfs2.FileDescriptionImpl.PRead.
func (fd *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs2.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	flags := fd.vfs1fd.Flags()
	if !flags.Read {
		return 0, syserror.EBADF
	}
	if !flags.Pread {
		return 0, syserror.ESPIPE
	}
	return fd.vfs1fd.Preadv(ctx, dst, offset)
}

// Read implements vfs2.FileDescriptionImpl.Read.
func (fd *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs2.ReadOptions) (int64, error) {
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	flags := fd.vfs1fd.Flags()
	if !flags.Read {
		return 0, syserror.EBADF
	}
	return fd.vfs1fd.Readv(ctx, dst)
}

// PWrite implements vfs2.FileDescriptionImpl.PWrite.
func (fd *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs2.WriteOptions) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	flags := fd.vfs1fd.Flags()
	if !flags.Write {
		return 0, syserror.EBADF
	}
	if !flags.Pwrite {
		return 0, syserror.ESPIPE
	}
	return fd.vfs1fd.Pwritev(ctx, src, offset)
}

// Write implements vfs2.FileDescriptionImpl.Write.
func (fd *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs2.WriteOptions) (int64, error) {
	if opts.Flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	flags := fd.vfs1fd.Flags()
	if !flags.Write {
		return 0, syserror.EBADF
	}
	return fd.vfs1fd.Writev(ctx, src)
}

// IterDirents implements vfs2.FileDescriptionImpl.IterDirents.
func (fd *fileDescription) IterDirents(ctx context.Context, cb vfs2.IterDirentsCallback) error {
	// Since each call to IterDirents gets a fresh vfs1DentrySerializer (with
	// handled == 0), each application getdents64() syscall will observe struct
	// linux_dirent64::d_off starting at 1, even if it is resuming iteration
	// from a previous call. Furthermore, since offsets are generated here,
	// lseek() to a returned offset will not have the intended effect. Both of
	// these are consistent with VFS1, in which offsets are generated in the
	// same way in sentry/syscalls/linux/sys_getdents.go.
	err := fd.vfs1fd.Readdir(ctx, vfs1DentrySerializerFromVFS2IterDirentsCallback(cb))
	if _, ok := err.(stopDentrySerializationError); ok {
		return nil
	}
	return err
}

type vfs1DentrySerializer struct {
	cb      vfs2.IterDirentsCallback
	handled int64
}

func vfs1DentrySerializerFromVFS2IterDirentsCallback(cb vfs2.IterDirentsCallback) *vfs1DentrySerializer {
	return &vfs1DentrySerializer{
		cb: cb,
	}
}

// CopyOut implements vfs1.DentrySerializer.CopyOut.
func (ds *vfs1DentrySerializer) CopyOut(name string, attributes vfs1.DentAttr) error {
	if !ds.cb.Handle(vfs2.Dirent{
		Name:    name,
		Type:    vfs1.ToDirentType(attributes.Type),
		Ino:     attributes.InodeID,
		NextOff: ds.handled + 1,
	}) {
		return stopDentrySerializationError{}
	}
	ds.handled++
	return nil
}

// Written implements vfs1.DentrySerializer.Written.
func (ds *vfs1DentrySerializer) Written() int {
	return int(ds.handled)
}

type stopDentrySerializationError struct{}

// Error implements error.Error.
func (stopDentrySerializationError) Error() string {
	return "stopDentrySerializationError"
}

// Seek implements vfs2.FileDescriptionImpl.Seek.
func (fd *fileDescription) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	var vfs1whence vfs1.SeekWhence
	switch whence {
	case linux.SEEK_SET:
		vfs1whence = vfs1.SeekSet
	case linux.SEEK_CUR:
		vfs1whence = vfs1.SeekCurrent
	case linux.SEEK_END:
		vfs1whence = vfs1.SeekEnd
	default:
		return 0, syserror.EINVAL
	}
	return fd.vfs1fd.Seek(ctx, vfs1whence, offset)
}

// Sync implements vfs2.FileDescriptionImpl.Sync.
func (fd *fileDescription) Sync(ctx context.Context) error {
	return fd.vfs1fd.Fsync(ctx, 0, vfs1.FileMaxOffset, vfs1.SyncAll)
}

// ConfigureMMap implements vfs2.FileDescriptionImpl.ConfigureMMap.
func (fd *fileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if err := fd.vfs1fd.ConfigureMMap(ctx, opts); err != nil {
		return err
	}
	if opts.MappingIdentity == fd.vfs1fd {
		// Override opts.MappingIdentity to get vfs2.FileDescription's
		// implementation of memmap.MappingIdentity.MappedName() (since the
		// vfs1.Dirent isn't actually linked into a tree of vfs1.Dirents,
		// vfs1.File.MappedName() will return the wrong value).
		fd.vfs2fd.IncRef()
		opts.MappingIdentity = &fd.vfs2fd
		fd.vfs1fd.DecRef()
	}
	return nil
}

// Ioctl implements vfs2.FileDescriptionImpl.Ioctl.
func (fd *fileDescription) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return fd.vfs1fd.FileOperations.Ioctl(ctx, fd.vfs1fd, uio, args)
}
