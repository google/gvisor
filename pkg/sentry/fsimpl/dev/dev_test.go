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

package dev

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	testDevMajor    = 111
	testDevMinor    = 11
	testDevPathname = "test"
	testDevPerms    = 0655
)

func setupDev(t *testing.T) (context.Context, *auth.Credentials, *vfs.VirtualFilesystem, vfs.VirtualDentry, func()) {
	t.Helper()

	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	// Register tmpfs.
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	vfsObj.MustRegisterFilesystemType(Name, &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{})

	vfsObj.RegisterDevice(vfs.CharDevice, testDevMajor, testDevMinor, nil, &vfs.RegisterDeviceOptions{
		GroupName: "test",
		Pathname:  testDevPathname,
		FilePerms: testDevPerms,
	})

	// Create a test mount namespace with devfs mounted at root.
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "dev" /* source */, Name /* fsTypeName */, &vfs.MountOptions{}, nil)
	if err != nil {
		t.Fatalf("failed to create tmpfs root mount: %v", err)
	}
	root := mntns.Root(ctx)

	return ctx, creds, vfsObj, root, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}
}

func TestUserspaceFiles(t *testing.T) {
	ctx, creds, vfsObj, root, cleanup := setupDev(t)
	defer cleanup()

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
		if gotTarget, err := vfsObj.ReadlinkAt(ctx, creds, &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(link.source),
		}); err != nil || gotTarget != link.target {
			t.Errorf("readlink(%q): got (%q, %v), wanted (%q, nil)", link.source, gotTarget, err, link.target)
		}
	}

	dirs := []string{"shm", "pts"}
	for _, dir := range dirs {
		statx, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(dir),
		}, &vfs.StatOptions{
			Mask: linux.STATX_MODE,
		})
		if err != nil {
			t.Errorf("stat(%q): got error %v ", dir, err)
			continue
		}
		if want := uint16(0755) | linux.S_IFDIR; statx.Mode != want {
			t.Errorf("stat(%q): got mode %x, want %x", dir, statx.Mode, want)
		}
	}
}

func TestDeviceFile(t *testing.T) {
	ctx, creds, vfsObj, root, cleanup := setupDev(t)
	defer cleanup()

	// Test that the test device is created.
	stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(testDevPathname),
	}, &vfs.StatOptions{
		Mask: linux.STATX_TYPE | linux.STATX_MODE,
	})
	if err != nil {
		t.Fatalf("failed to stat device file at %q: %v", testDevPathname, err)
	}
	if stat.RdevMajor != testDevMajor {
		t.Errorf("major device number: got %v, wanted %v", stat.RdevMajor, testDevMajor)
	}
	if stat.RdevMinor != testDevMinor {
		t.Errorf("minor device number: got %v, wanted %v", stat.RdevMinor, testDevMinor)
	}
	if wantMode := uint16(linux.S_IFCHR | testDevPerms); stat.Mode != wantMode {
		t.Errorf("device file mode: got %v, wanted %v", stat.Mode, wantMode)
	}
}
