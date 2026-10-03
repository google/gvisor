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

package overlay

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// newRootAndCwd returns two distinct directories on a new tmpfs mount, so that
// a caller can tell which one a pathname resolved from.
func newRootAndCwd(t *testing.T, ctx context.Context, vfsObj *vfs.VirtualFilesystem) (vfs.VirtualDentry, vfs.VirtualDentry) {
	t.Helper()
	creds := auth.CredentialsFromContext(ctx)
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
	if err != nil {
		t.Fatalf("failed to create tmpfs root mount: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })
	root := mntns.Root(ctx)
	t.Cleanup(func() { root.DecRef(ctx) })

	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("cwd")}
	if err := vfsObj.MkdirAt(ctx, creds, pop, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("failed to create cwd: %v", err)
	}
	cwd, err := vfsObj.GetDentryAt(ctx, creds, pop, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("failed to resolve cwd: %v", err)
	}
	t.Cleanup(func() { cwd.DecRef(ctx) })
	return root, cwd
}

// resolveStart decides which directory a mount option pathname resolves from.
// The no-working-directory case cannot be reached from mount(2), because a task
// always has a working directory, so it is only testable here.
func TestResolveStart(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	root, cwd := newRootAndCwd(t, ctx, vfsObj)

	for _, test := range []struct {
		name    string
		path    string
		cwd     vfs.VirtualDentry
		want    vfs.VirtualDentry
		wantErr bool
	}{
		{
			name: "absolute pathname resolves from the root",
			path: "/l0",
			cwd:  cwd,
			want: root,
		},
		{
			name: "relative pathname resolves from the working directory",
			path: "l0",
			cwd:  cwd,
			want: cwd,
		},
		{
			name:    "relative pathname without a working directory is rejected",
			path:    "l0",
			cwd:     vfs.VirtualDentry{},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveStart(root, test.cwd, fspath.Parse(test.path))
			if test.wantErr {
				if !linuxerr.Equals(linuxerr.EINVAL, err) {
					t.Fatalf("resolveStart(%q) returned %v, wanted EINVAL", test.path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveStart(%q) failed: %v", test.path, err)
			}
			if got != test.want {
				t.Errorf("resolveStart(%q) resolved from the wrong directory", test.path)
			}
		})
	}
}

// GetFilesystem rejects pathnames it cannot resolve. The empty workdir case
// also guards a crash: without the length check, fspath.Parse("" + "/work")
// is absolute, so resolveStart returns the zero vfsroot and MkdirAt runs
// against it.
func TestGetFilesystemRejectsPathnamesItCannotResolve(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{"relative lowerdir", "lowerdir=l0"},
		{"relative upperdir", "upperdir=u"},
		{"relative workdir", "upperdir=/u,workdir=w"},
		{"empty lowerdir", "lowerdir="},
		{"empty upperdir", "upperdir="},
		{"empty workdir", "upperdir=/u,workdir="},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			creds := auth.CredentialsFromContext(ctx)
			vfsObj := &vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				t.Fatalf("VFS init: %v", err)
			}
			fs, root, err := FilesystemType{}.GetFilesystem(ctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
				Data: test.data,
			})
			if err == nil {
				fs.DecRef(ctx)
				root.DecRef(ctx)
				t.Fatalf("GetFilesystem with %q succeeded, wanted EINVAL", test.data)
			}
			if !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("GetFilesystem with %q returned %v, wanted EINVAL", test.data, err)
			}
		})
	}
}
