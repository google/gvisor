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

package tmpfs

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// nextFileID is used to generate unique file names.
var nextFileID int64

// newTmpfsRoot creates a new tmpfs mount, and returns the root. If the error
// is not nil, then cleanup should be called when the root is no longer needed.
func newTmpfsRoot(ctx context.Context) (*vfs.VirtualFilesystem, vfs.VirtualDentry, func(), error) {
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(); err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("VFS init: %v", err)
	}

	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.GetFilesystemOptions{})
	if err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("failed to create tmpfs root mount: %v", err)
	}
	root := mntns.Root()
	return vfsObj, root, func() {
		root.DecRef()
		mntns.DecRef()
	}, nil
}

// newFileFD creates a new file in a new tmpfs mount, and returns the FD. If
// the returned err is not nil, then cleanup should be called when the FD is no
// longer needed.
func newFileFD(ctx context.Context, mode linux.FileMode) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	filename := fmt.Sprintf("tmpfs-test-file-%d", atomic.AddInt64(&nextFileID, 1))

	// Create the file that will be write/read.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  linux.ModeRegular | mode,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create file %q: %v", filename, err)
	}

	return fd, cleanup, nil
}

// newDirFD is like newFileFD, but for directories.
func newDirFD(ctx context.Context, mode linux.FileMode) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	dirname := fmt.Sprintf("tmpfs-test-dir-%d", atomic.AddInt64(&nextFileID, 1))

	// Create the dir.
	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(dirname),
	}, &vfs.MkdirOptions{
		Mode: linux.ModeDirectory | mode,
	}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create directory %q: %v", dirname, err)
	}

	// Open the dir and return it.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(dirname),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to open directory %q: %v", dirname, err)
	}

	return fd, cleanup, nil
}

// newPipeFD is like newFileFD, but for pipes.
func newPipeFD(ctx context.Context, mode linux.FileMode) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	name := fmt.Sprintf("tmpfs-test-%d", atomic.AddInt64(&nextFileID, 1))

	if err := vfsObj.MknodAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(name),
	}, &vfs.MknodOptions{
		Mode: linux.ModeNamedPipe | mode,
	}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create pipe %q: %v", name, err)
	}

	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(name),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to open pipe %q: %v", name, err)
	}

	return fd, cleanup, nil
}
