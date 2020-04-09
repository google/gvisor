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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// VFSFile implements File interface over vfs.FileDescription.
//
// +stateify savable
type VFSFile struct {
	file *vfs.FileDescription
}

var _ File = (*VFSFile)(nil)

// NewVFSFile creates a new File over fs.File.
func NewVFSFile(file *vfs.FileDescription) File {
	return &VFSFile{file: file}
}

// PathnameWithDeleted implements File.
func (f *VFSFile) PathnameWithDeleted(ctx context.Context) string {
	root := vfs.RootFromContext(ctx)
	defer root.DecRef()

	vfsObj := f.file.VirtualDentry().Mount().Filesystem().VirtualFilesystem()
	name, _ := vfsObj.PathnameWithDeleted(ctx, root, f.file.VirtualDentry())
	return name
}

// ReadFull implements File.
func (f *VFSFile) ReadFull(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	var total int64
	for dst.NumBytes() > 0 {
		n, err := f.file.PRead(ctx, dst, offset+total, vfs.ReadOptions{})
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
func (f *VFSFile) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return f.file.ConfigureMMap(ctx, opts)
}

// Type implements File.
func (f *VFSFile) Type(ctx context.Context) (linux.FileMode, error) {
	stat, err := f.file.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		return 0, err
	}
	return linux.FileMode(stat.Mode).FileType(), nil
}

// IncRef implements File.
func (f *VFSFile) IncRef() {
	f.file.IncRef()
}

// DecRef implements File.
func (f *VFSFile) DecRef() {
	f.file.DecRef()
}

// FileDescription returns the FileDescription represented by f. It does not
// take an additional reference on the returned FileDescription.
func (f *VFSFile) FileDescription() *vfs.FileDescription {
	return f.file
}

// fsLookup implements Lookup interface using fs.File.
//
// +stateify savable
type vfsLookup struct {
	mntns *vfs.MountNamespace

	root       vfs.VirtualDentry
	workingDir vfs.VirtualDentry
}

var _ Lookup = (*vfsLookup)(nil)

// NewVFSLookup creates a new Lookup using VFS2.
func NewVFSLookup(mntns *vfs.MountNamespace, root, workingDir vfs.VirtualDentry) Lookup {
	return &vfsLookup{
		mntns:      mntns,
		root:       root,
		workingDir: workingDir,
	}
}

// OpenPath implements Lookup.
//
// remainingTraversals is not configurable in VFS2, all callers are using the
// default anyways.
func (l *vfsLookup) OpenPath(ctx context.Context, pathname string, opts vfs.OpenOptions, _ *uint, resolveFinal bool) (File, error) {
	vfsObj := l.mntns.Root().Mount().Filesystem().VirtualFilesystem()
	creds := auth.CredentialsFromContext(ctx)
	path := fspath.Parse(pathname)
	pop := &vfs.PathOperation{
		Root:               l.root,
		Start:              l.workingDir,
		Path:               path,
		FollowFinalSymlink: resolveFinal,
	}
	if path.Absolute {
		pop.Start = l.root
	}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &opts)
	if err != nil {
		return nil, err
	}
	return &VFSFile{file: fd}, nil
}
