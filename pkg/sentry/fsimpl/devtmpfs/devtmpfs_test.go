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

package devtmpfs

import (
	"path"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const devPath = "/dev"

func setupDevtmpfs(t *testing.T) (context.Context, *auth.Credentials, *vfs.VirtualFilesystem, vfs.VirtualDentry, func()) {
	t.Helper()

	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	// Register tmpfs just so that we can have a root filesystem that isn't
	// devtmpfs.
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	vfsObj.MustRegisterFilesystemType("devtmpfs", &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	// Create a test mount namespace with devtmpfs mounted at "/dev".
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "tmpfs" /* source */, "tmpfs" /* fsTypeName */, &vfs.MountOptions{})
	if err != nil {
		t.Fatalf("failed to create tmpfs root mount: %v", err)
	}
	root := mntns.Root()
	root.IncRef()
	devpop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(devPath),
	}
	if err := vfsObj.MkdirAt(ctx, creds, &devpop, &vfs.MkdirOptions{
		Mode: 0755,
	}); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}
	if _, err := vfsObj.MountAt(ctx, creds, "devtmpfs" /* source */, &devpop, "devtmpfs" /* fsTypeName */, &vfs.MountOptions{}); err != nil {
		t.Fatalf("failed to mount devtmpfs: %v", err)
	}

	return ctx, creds, vfsObj, root, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}
}

func TestUserspaceInit(t *testing.T) {
	ctx, creds, vfsObj, root, cleanup := setupDevtmpfs(t)
	defer cleanup()

	a, err := NewAccessor(ctx, vfsObj, creds, "devtmpfs")
	if err != nil {
		t.Fatalf("failed to create devtmpfs.Accessor: %v", err)
	}
	defer a.Release(ctx)

	// Create "userspace-initialized" files using a devtmpfs.Accessor.
	if err := a.UserspaceInit(ctx); err != nil {
		t.Fatalf("failed to userspace-initialize devtmpfs: %v", err)
	}

	// Created files should be visible in the test mount namespace.
	links := []struct {
		source string
		target string
	}{
		{
			source: "fd",
			target: "/proc/self/fd",
		},
		{
			source: "stdin",
			target: "/proc/self/fd/0",
		},
		{
			source: "stdout",
			target: "/proc/self/fd/1",
		},
		{
			source: "stderr",
			target: "/proc/self/fd/2",
		},
		{
			source: "ptmx",
			target: "pts/ptmx",
		},
	}

	for _, link := range links {
		abspath := path.Join(devPath, link.source)
		if gotTarget, err := vfsObj.ReadlinkAt(ctx, creds, &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(abspath),
		}); err != nil || gotTarget != link.target {
			t.Errorf("readlink(%q): got (%q, %v), wanted (%q, nil)", abspath, gotTarget, err, link.target)
		}
	}

	dirs := []struct {
		path string
		mode uint16
	}{
		{
			path: "shm",
			mode: 01777,
		},
		{
			path: "pts",
			mode: 0755,
		},
	}
	for _, dir := range dirs {
		abspath := path.Join(devPath, dir.path)
		statx, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(abspath),
		}, &vfs.StatOptions{
			Mask: linux.STATX_MODE,
		})
		if err != nil {
			t.Errorf("stat(%q): got error %v ", abspath, err)
			continue
		}
		if want := dir.mode | linux.S_IFDIR; statx.Mode != want {
			t.Errorf("stat(%q): got mode %x, want %x", abspath, statx.Mode, want)
		}
	}
}

func TestCreateDeviceFile(t *testing.T) {
	ctx, creds, vfsObj, root, cleanup := setupDevtmpfs(t)
	defer cleanup()

	a, err := NewAccessor(ctx, vfsObj, creds, "devtmpfs")
	if err != nil {
		t.Fatalf("failed to create devtmpfs.Accessor: %v", err)
	}
	defer a.Release(ctx)

	devFiles := []struct {
		path  string
		kind  vfs.DeviceKind
		major uint32
		minor uint32
		perms uint16
	}{
		{
			path:  "dummy",
			kind:  vfs.CharDevice,
			major: 12,
			minor: 34,
			perms: 0600,
		},
		{
			path:  "foo/bar",
			kind:  vfs.BlockDevice,
			major: 13,
			minor: 35,
			perms: 0660,
		},
		{
			path:  "foo/baz",
			kind:  vfs.CharDevice,
			major: 12,
			minor: 40,
			perms: 0666,
		},
		{
			path:  "a/b/c/d/e",
			kind:  vfs.BlockDevice,
			major: 12,
			minor: 34,
			perms: 0600,
		},
	}

	for _, f := range devFiles {
		if err := a.CreateDeviceFile(ctx, f.path, f.kind, f.major, f.minor, f.perms); err != nil {
			t.Fatalf("failed to create device file: %v", err)
		}
		// The device special file should be visible in the test mount namespace.
		abspath := path.Join(devPath, f.path)
		stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(abspath),
		}, &vfs.StatOptions{
			Mask: linux.STATX_TYPE | linux.STATX_MODE,
		})
		if err != nil {
			t.Fatalf("failed to stat device file at %q: %v", abspath, err)
		}
		if stat.RdevMajor != f.major {
			t.Errorf("major device number: got %v, wanted %v", stat.RdevMajor, f.major)
		}
		if stat.RdevMinor != f.minor {
			t.Errorf("minor device number: got %v, wanted %v", stat.RdevMinor, f.minor)
		}
		wantMode := f.perms
		switch f.kind {
		case vfs.CharDevice:
			wantMode |= linux.S_IFCHR
		case vfs.BlockDevice:
			wantMode |= linux.S_IFBLK
		}
		if stat.Mode != wantMode {
			t.Errorf("device file mode: got %v, wanted %v", stat.Mode, wantMode)
		}
	}
}
