// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// fileDescription implements vfs.FileDescriptionImpl for fuse.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD

	// the file handle used in userspace.
	Fh uint64

	// Nonseekable indicates we cannot perform seek on a file.
	Nonseekable bool

	// DirectIO suggests that fuse use direct IO operations.
	DirectIO bool

	// OpenFlag is the flag returned by open.
	OpenFlag uint32

	// off is the file offset.
	off atomicbitops.Int64
}

func (fd *fileDescription) dentry() *kernfs.Dentry {
	return fd.vfsfd.Dentry().Impl().(*kernfs.Dentry)
}

func (fd *fileDescription) inode() *inode {
	return fd.dentry().Inode().(*inode)
}

func (fd *fileDescription) filesystem() *vfs.Filesystem {
	return fd.vfsfd.VirtualDentry().Mount().Filesystem()
}

func (fd *fileDescription) statusFlags() uint32 {
	return fd.vfsfd.StatusFlags()
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release(ctx context.Context) {
	// no need to release if FUSE server doesn't implement Open.
	conn := fd.inode().fs.conn
	if conn.noOpen {
		return
	}

	in := linux.FUSEReleaseIn{
		Fh:    fd.Fh,
		Flags: fd.statusFlags(),
	}
	// TODO(gvisor.dev/issue/3245): add logic when we support file lock owners.
	inode := fd.inode()
	inode.attrMu.Lock()
	defer inode.attrMu.Unlock()
	var opcode linux.FUSEOpcode
	if inode.filemode().IsDir() {
		opcode = linux.FUSE_RELEASEDIR
	} else {
		opcode = linux.FUSE_RELEASE
	}
	// Ignoring errors and FUSE server replies is analogous to Linux's behavior.
	req := conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), inode.nodeID, opcode, &in)
	// The reply will be ignored since no callback is defined in asyncCallBack().
	conn.CallAsync(ctx, req)
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *fileDescription) OnClose(ctx context.Context) error {
	inode := fd.inode()
	conn := inode.fs.conn
	inode.attrMu.Lock()
	defer inode.attrMu.Unlock()

	in := linux.FUSEFlushIn{
		Fh:        fd.Fh,
		LockOwner: 0, // TODO(gvisor.dev/issue/3245): file lock
	}
	req := conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), inode.nodeID, linux.FUSE_FLUSH, &in)
	return conn.CallAsync(ctx, req)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *fileDescription) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := fd.filesystem()
	inode := fd.inode()
	return inode.Stat(ctx, fs, opts)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	fs := fd.filesystem()
	creds := auth.CredentialsFromContext(ctx)
	inode := fd.inode()
	inode.attrMu.Lock()
	defer inode.attrMu.Unlock()
	if err := vfs.CheckSetStat(ctx, creds, &opts, inode.filemode(), auth.KUID(inode.uid.Load()), auth.KGID(inode.gid.Load())); err != nil {
		return err
	}
	return inode.setAttr(ctx, fs, creds, opts, fhOptions{useFh: true, fh: fd.Fh})
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *fileDescription) Sync(ctx context.Context) error {
	inode := fd.inode()
	inode.attrMu.Lock()
	defer inode.attrMu.Unlock()
	conn := inode.fs.conn
	// no need to proceed if FUSE server doesn't implement Open.
	if conn.noOpen {
		return linuxerr.EINVAL
	}

	in := linux.FUSEFsyncIn{
		Fh:         fd.Fh,
		FsyncFlags: fd.statusFlags(),
	}
	// Ignoring errors and FUSE server replies is analogous to Linux's behavior.
	req := conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), inode.nodeID, linux.FUSE_FSYNC, &in)
	// The reply will be ignored since no callback is defined in asyncCallBack().
	conn.CallAsync(ctx, req)
	return nil
}
