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

	"gvisor.dev/gvisor/pkg/context"
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
func NewFSFile(file *fs.File) *fsFile {
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
	defer root.DecRef()

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
func (f *fsFile) Type(context.Context) (uint8, error) {
	return fs.ToDirentType(f.file.Dirent.Inode.StableAttr.Type), nil
}

// IncRef implements File.
func (f *fsFile) IncRef() {
	f.file.IncRef()
}

// DecRef implements File.
func (f *fsFile) DecRef() {
	f.file.DecRef()
}

// CheckPermission implements File.
func (f *fsFile) CheckPermission(ctx context.Context, ats vfs.AccessTypes) error {
	fsPerm := accessTypeToPermMask(ats)
	return f.file.Dirent.Inode.CheckPermission(ctx, fsPerm)
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

// NewFSFile creates a new Lookup using VFS1.
func NewFSLookup(mntns *fs.MountNamespace, root, workingDir *fs.Dirent) *fsLookup {
	return &fsLookup{
		mntns:      mntns,
		root:       root,
		workingDir: workingDir,
	}
}

// OpenPath implements Lookup.
func (l *fsLookup) OpenPath(ctx context.Context, path string, ats vfs.AccessTypes, remainingTraversals *uint, resolveFinal bool) (File, error) {
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
	// Defer a DecRef for the sake of failure cases.
	defer d.DecRef()

	if !resolveFinal && fs.IsSymlink(d.Inode.StableAttr) {
		return nil, syserror.ELOOP
	}

	fsPerm := accessTypeToPermMask(ats)
	if err := d.Inode.CheckPermission(ctx, fsPerm); err != nil {
		return nil, err
	}

	f, err := d.Inode.GetFile(ctx, d, fs.FileFlags{Read: true})
	if err != nil {
		return nil, err
	}
	return &fsFile{file: f}, nil
}

func accessTypeToPermMask(ats vfs.AccessTypes) fs.PermMask {
	return fs.PermMask{
		Read:    ats.MayRead(),
		Write:   ats.MayWrite(),
		Execute: ats.MayExec(),
	}
}
