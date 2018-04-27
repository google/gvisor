// Copyright 2018 Google Inc.
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

package fs_test

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	ramfstest "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs/test"
)

// Creates a new MountNamespace with filesystem:
// /       (root dir)
// |-foo   (dir)
//   |-bar (file)
func createMountNamespace(ctx context.Context) (*fs.MountNamespace, error) {
	perms := fs.FilePermsFromMode(0777)
	m := fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{})

	barFile := ramfstest.NewFile(ctx, perms)
	fooDir := ramfstest.NewDir(ctx, map[string]*fs.Inode{
		"bar": fs.NewInode(barFile, m, fs.StableAttr{Type: fs.RegularFile}),
	}, perms)
	rootDir := ramfstest.NewDir(ctx, map[string]*fs.Inode{
		"foo": fs.NewInode(fooDir, m, fs.StableAttr{Type: fs.Directory}),
	}, perms)

	return fs.NewMountNamespace(ctx, fs.NewInode(rootDir, m, fs.StableAttr{Type: fs.Directory}))
}

func TestFindLink(t *testing.T) {
	ctx := contexttest.Context(t)
	mm, err := createMountNamespace(ctx)
	if err != nil {
		t.Fatalf("createMountNamespace failed: %v", err)
	}

	root := mm.Root()
	defer root.DecRef()
	foo, err := root.Walk(ctx, root, "foo")
	if err != nil {
		t.Fatalf("Error walking to foo: %v", err)
	}

	// Positive cases.
	for _, tc := range []struct {
		findPath string
		wd       *fs.Dirent
		wantPath string
	}{
		{".", root, "/"},
		{".", foo, "/foo"},
		{"..", foo, "/"},
		{"../../..", foo, "/"},
		{"///foo", foo, "/foo"},
		{"/foo", foo, "/foo"},
		{"/foo/bar", foo, "/foo/bar"},
		{"/foo/.///./bar", foo, "/foo/bar"},
		{"/foo///bar", foo, "/foo/bar"},
		{"/foo/../foo/bar", foo, "/foo/bar"},
		{"foo/bar", root, "/foo/bar"},
		{"foo////bar", root, "/foo/bar"},
		{"bar", foo, "/foo/bar"},
	} {
		wdPath, _ := tc.wd.FullName(root)
		if d, err := mm.FindLink(ctx, root, tc.wd, tc.findPath, 0); err != nil {
			t.Errorf("FindLink(%q, wd=%q) failed: %v", tc.findPath, wdPath, err)
		} else if got, _ := d.FullName(root); got != tc.wantPath {
			t.Errorf("FindLink(%q, wd=%q) got dirent %q, want %q", tc.findPath, wdPath, got, tc.wantPath)
		}
	}

	// Negative cases.
	for _, tc := range []struct {
		findPath string
		wd       *fs.Dirent
	}{
		{"bar", root},
		{"/bar", root},
		{"/foo/../../bar", root},
		{"foo", foo},
	} {
		wdPath, _ := tc.wd.FullName(root)
		if _, err := mm.FindLink(ctx, root, tc.wd, tc.findPath, 0); err == nil {
			t.Errorf("FindLink(%q, wd=%q) did not return error", tc.findPath, wdPath)
		}
	}
}
