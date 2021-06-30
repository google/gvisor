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

package fsbridge

import (
	"io"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// fsFile implements File interface over fs.File.
//
// +stateify savable
type fsFile struct {
	file *fs.File
}

var _ File = (*fsFile)(nil)

// NewFSFile creates a new File over fs.File.
func NewFSFile(file *fs.File) File {
	return &fsFile{file: file}
}

// PathnameWithDeleted implements File.
func (f *fsFile) PathnameWithDeleted(ctx context.Context) string {
	root := fs.RootFromContext(ctx)
	if root == nil {
		// This doesn't correspond to anything in Linux because the vfs is
		// global there.
		return ""
	}
	defer root.DecRef(ctx)

	name, _ := f.file.Dirent.FullName(root)
	return name
}

// ReadFull implements File.
func (f *fsFile) ReadFull(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	var total int64
	for dst.NumBytes() > 0 {
		n, err := f.file.Preadv(ctx, dst, offset+total)
		total += n
		if err == io.EOF && total != 0 {
			return total, io.ErrUnexpectedEOF
		} else if err != nil {
			return total, err
		}
		dst = dst.DropFirst64(n)
	}
	return total, nil
}

// ConfigureMMap implements File.
func (f *fsFile) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return f.file.ConfigureMMap(ctx, opts)
}

// Type implements File.
func (f *fsFile) Type(context.Context) (linux.FileMode, error) {
	return linux.FileMode(f.file.Dirent.Inode.StableAttr.Type.LinuxType()), nil
}

// IncRef implements File.
func (f *fsFile) IncRef() {
	f.file.IncRef()
}

// DecRef implements File.
func (f *fsFile) DecRef(ctx context.Context) {
	f.file.DecRef(ctx)
}

// fsLookup implements Lookup interface using fs.File.
//
// +stateify savable
type fsLookup struct {
	mntns *fs.MountNamespace

	root       *fs.Dirent
	workingDir *fs.Dirent
}

var _ Lookup = (*fsLookup)(nil)

// NewFSLookup creates a new Lookup using VFS1.
func NewFSLookup(mntns *fs.MountNamespace, root, workingDir *fs.Dirent) Lookup {
	return &fsLookup{
		mntns:      mntns,
		root:       root,
		workingDir: workingDir,
	}
}

// OpenPath implements Lookup.
func (l *fsLookup) OpenPath(ctx context.Context, path string, opts vfs.OpenOptions, remainingTraversals *uint, resolveFinal bool) (File, error) {
	var d *fs.Dirent
	var err error
	if resolveFinal {
		d, err = l.mntns.FindInode(ctx, l.root, l.workingDir, path, remainingTraversals)
	} else {
		d, err = l.mntns.FindLink(ctx, l.root, l.workingDir, path, remainingTraversals)
	}
	if err != nil {
		return nil, err
	}
	defer d.DecRef(ctx)

	if !resolveFinal && fs.IsSymlink(d.Inode.StableAttr) {
		return nil, syserror.ELOOP
	}

	fsPerm := openOptionsToPermMask(&opts)
	if err := d.Inode.CheckPermission(ctx, fsPerm); err != nil {
		return nil, err
	}

	// If they claim it's a directory, then make sure.
	if strings.HasSuffix(path, "/") {
		if d.Inode.StableAttr.Type != fs.Directory {
			return nil, syserror.ENOTDIR
		}
	}

	if opts.FileExec && d.Inode.StableAttr.Type != fs.RegularFile {
		ctx.Infof("%q is not a regular file: %v", path, d.Inode.StableAttr.Type)
		return nil, linuxerr.EACCES
	}

	f, err := d.Inode.GetFile(ctx, d, flagsToFileFlags(opts.Flags))
	if err != nil {
		return nil, err
	}

	return &fsFile{file: f}, nil
}

func openOptionsToPermMask(opts *vfs.OpenOptions) fs.PermMask {
	mode := opts.Flags & linux.O_ACCMODE
	return fs.PermMask{
		Read:    mode == linux.O_RDONLY || mode == linux.O_RDWR,
		Write:   mode == linux.O_WRONLY || mode == linux.O_RDWR,
		Execute: opts.FileExec,
	}
}

func flagsToFileFlags(flags uint32) fs.FileFlags {
	return fs.FileFlags{
		Direct:      flags&linux.O_DIRECT != 0,
		DSync:       flags&(linux.O_DSYNC|linux.O_SYNC) != 0,
		Sync:        flags&linux.O_SYNC != 0,
		NonBlocking: flags&linux.O_NONBLOCK != 0,
		Read:        (flags & linux.O_ACCMODE) != linux.O_WRONLY,
		Write:       (flags & linux.O_ACCMODE) != linux.O_RDONLY,
		Append:      flags&linux.O_APPEND != 0,
		Directory:   flags&linux.O_DIRECTORY != 0,
		Async:       flags&linux.O_ASYNC != 0,
		LargeFile:   flags&linux.O_LARGEFILE != 0,
		Truncate:    flags&linux.O_TRUNC != 0,
	}
}
