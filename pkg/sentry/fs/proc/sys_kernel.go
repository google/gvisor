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

package proc

import (
	"io"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (p *proc) newKernelDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	children := map[string]*fs.Inode{
		"domainname": newUTSNamespaceProcInode(ctx, msrc, (*kernel.UTSNamespace).DomainName),
		"hostname":   newUTSNamespaceProcInode(ctx, msrc, (*kernel.UTSNamespace).HostName),
		"osrelease":  newReleaseProcInode(ctx, msrc),
		"ostype":     newSysNameProcInode(ctx, msrc),
		"shmall":     newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.SHMALL, 10))),
		"shmmax":     newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.SHMMAX, 10))),
		"shmmni":     newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.SHMMNI, 10))),
		"version":    newVersionProcInode(ctx, msrc),
	}

	d := ramfs.NewDir(ctx, children, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

// utsNamespaceFile is a file that returns a field from the current
// kernel.UTSNamespace.
//
// +stateify savable
type utsNamespaceFile struct {
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	// fn returns the contents of this file from the passed
	// UTSNamespace.
	fn func(ns *kernel.UTSNamespace) string
}

// Read implements fs.FileOperations.Read.
func (uf *utsNamespaceFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	utsns := kernel.UTSNamespaceFromContext(ctx)
	contents := []byte(uf.fn(utsns) + "\n")
	if offset >= int64(len(contents)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err

}

var _ fs.FileOperations = (*utsNamespaceFile)(nil)

// utsNamespaceInode is the inode for a file containing a field from the
// UTSNamespace.
//
// +stateify savable
type utsNamespaceInode struct {
	fsutil.SimpleFileInode

	// fn returns the contents of this file from the passed
	// UTSNamespace.
	fn func(ns *kernel.UTSNamespace) string
}

// GetFile implements fs.InodeOperations.GetFile.
func (ui *utsNamespaceInode) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &utsNamespaceFile{fn: ui.fn}), nil
}

var _ fs.InodeOperations = (*utsNamespaceInode)(nil)

// newUTSNamespaceProcInode returns a procfs Inode containing the UTSNamespace
// field returned by fn.
func newUTSNamespaceProcInode(ctx context.Context, msrc *fs.MountSource, fn func(ns *kernel.UTSNamespace) string) *fs.Inode {
	return newProcInode(ctx, &utsNamespaceInode{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		fn:              fn,
	}, msrc, fs.SpecialFile, nil)
}

// utsVersionFile is a file that returns a field from the current
// kernel.Version.
//
// +stateify savable
type utsVersionFile struct {
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	// fn returns the contents of this file from the passed
	// Version.
	fn func(v kernel.Version) string
}

// Read implements fs.FileOperations.Read.
func (uf *utsVersionFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// N.B. Linux can't fail this way, because it always falls back
		// to the "init" value, which we don't have.
		return 0, syserror.ENOENT
	}

	var version kernel.Version
	t.WithMuLocked(func(t *kernel.Task) {
		version = t.SyscallTable().Version
	})

	contents := []byte(uf.fn(version) + "\n")
	if offset >= int64(len(contents)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err

}

var _ fs.FileOperations = (*utsVersionFile)(nil)

// utsVersionInode is the inode for a file containing a field from the Version.
//
// +stateify savable
type utsVersionInode struct {
	fsutil.SimpleFileInode

	// fn returns the contents of this file from the passed Version.
	fn func(v kernel.Version) string
}

// GetFile implements fs.InodeOperations.GetFile.
func (ui *utsVersionInode) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &utsVersionFile{fn: ui.fn}), nil
}

// newUTSVersionProcInode returns a procfs Inode containing the Version field
// returned by fn.
func newUTSVersionProcInode(ctx context.Context, msrc *fs.MountSource, fn func(v kernel.Version) string) *fs.Inode {
	return newProcInode(ctx, &utsVersionInode{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		fn:              fn,
	}, msrc, fs.SpecialFile, nil)
}

// newSysNameProcInode returns a procfs Inode containing the sysname.
func newSysNameProcInode(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	return newUTSVersionProcInode(ctx, msrc, func(v kernel.Version) string {
		return v.Sysname
	})
}

// newReleaseProcInode returns a procfs Inode containing the release.
func newReleaseProcInode(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	return newUTSVersionProcInode(ctx, msrc, func(v kernel.Version) string {
		return v.Release
	})
}

// newVersionProcInode returns a procfs Inode containing the version.
func newVersionProcInode(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	return newUTSVersionProcInode(ctx, msrc, func(v kernel.Version) string {
		return v.Version
	})
}
