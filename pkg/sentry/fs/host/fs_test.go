// Copyright 2018 Google LLC
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

package host

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// newTestMountNamespace creates a MountNamespace with a ramfs root.
// It returns the host folder created, which should be removed when done.
func newTestMountNamespace(t *testing.T) (*fs.MountNamespace, string, error) {
	p, err := ioutil.TempDir("", "root")
	if err != nil {
		return nil, "", err
	}

	fd, err := open(nil, p)
	if err != nil {
		os.RemoveAll(p)
		return nil, "", err
	}
	ctx := contexttest.Context(t)
	root, err := newInode(ctx, newMountSource(ctx, p, fs.RootOwner, &Filesystem{}, fs.MountSourceFlags{}, false), fd, false, false)
	if err != nil {
		os.RemoveAll(p)
		return nil, "", err
	}
	mm, err := fs.NewMountNamespace(ctx, root)
	if err != nil {
		os.RemoveAll(p)
		return nil, "", err
	}
	return mm, p, nil
}

// createTestDirs populates the root with some test files and directories.
// /a/a1.txt
// /a/a2.txt
// /b/b1.txt
// /b/c/c1.txt
// /symlinks/normal.txt
// /symlinks/to_normal.txt -> /symlinks/normal.txt
// /symlinks/recursive -> /symlinks
func createTestDirs(ctx context.Context, t *testing.T, m *fs.MountNamespace) error {
	r := m.Root()
	defer r.DecRef()

	if err := r.CreateDirectory(ctx, r, "a", fs.FilePermsFromMode(0777)); err != nil {
		return err
	}

	a, err := r.Walk(ctx, r, "a")
	if err != nil {
		return err
	}
	defer a.DecRef()

	a1, err := a.Create(ctx, r, "a1.txt", fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0666))
	if err != nil {
		return err
	}
	a1.DecRef()

	a2, err := a.Create(ctx, r, "a2.txt", fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0666))
	if err != nil {
		return err
	}
	a2.DecRef()

	if err := r.CreateDirectory(ctx, r, "b", fs.FilePermsFromMode(0777)); err != nil {
		return err
	}

	b, err := r.Walk(ctx, r, "b")
	if err != nil {
		return err
	}
	defer b.DecRef()

	b1, err := b.Create(ctx, r, "b1.txt", fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0666))
	if err != nil {
		return err
	}
	b1.DecRef()

	if err := b.CreateDirectory(ctx, r, "c", fs.FilePermsFromMode(0777)); err != nil {
		return err
	}

	c, err := b.Walk(ctx, r, "c")
	if err != nil {
		return err
	}
	defer c.DecRef()

	c1, err := c.Create(ctx, r, "c1.txt", fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0666))
	if err != nil {
		return err
	}
	c1.DecRef()

	if err := r.CreateDirectory(ctx, r, "symlinks", fs.FilePermsFromMode(0777)); err != nil {
		return err
	}

	symlinks, err := r.Walk(ctx, r, "symlinks")
	if err != nil {
		return err
	}
	defer symlinks.DecRef()

	normal, err := symlinks.Create(ctx, r, "normal.txt", fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0666))
	if err != nil {
		return err
	}
	normal.DecRef()

	if err := symlinks.CreateLink(ctx, r, "/symlinks/normal.txt", "to_normal.txt"); err != nil {
		return err
	}

	return symlinks.CreateLink(ctx, r, "/symlinks", "recursive")
}

// allPaths returns a slice of all paths of entries visible in the rootfs.
func allPaths(ctx context.Context, t *testing.T, m *fs.MountNamespace, base string) ([]string, error) {
	var paths []string
	root := m.Root()
	defer root.DecRef()

	maxTraversals := uint(1)
	d, err := m.FindLink(ctx, root, nil, base, &maxTraversals)
	if err != nil {
		t.Logf("FindLink failed for %q", base)
		return paths, err
	}
	defer d.DecRef()

	if fs.IsDir(d.Inode.StableAttr) {
		dir, err := d.Inode.GetFile(ctx, d, fs.FileFlags{Read: true})
		if err != nil {
			return nil, fmt.Errorf("failed to open directory %q: %v", base, err)
		}
		iter, ok := dir.FileOperations.(fs.DirIterator)
		if !ok {
			return nil, fmt.Errorf("cannot directly iterate on host directory %q", base)
		}
		dirCtx := &fs.DirCtx{
			Serializer: noopDentrySerializer{},
		}
		if _, err := fs.DirentReaddir(ctx, d, iter, root, dirCtx, 0); err != nil {
			return nil, err
		}
		for name := range dirCtx.DentAttrs() {
			if name == "." || name == ".." {
				continue
			}

			fullName := path.Join(base, name)
			paths = append(paths, fullName)

			// Recurse.
			subpaths, err := allPaths(ctx, t, m, fullName)
			if err != nil {
				return paths, err
			}
			paths = append(paths, subpaths...)
		}
	}

	return paths, nil
}

type noopDentrySerializer struct{}

func (noopDentrySerializer) CopyOut(string, fs.DentAttr) error {
	return nil
}
func (noopDentrySerializer) Written() int {
	return 4096
}

// pathsEqual returns true if the two string slices contain the same entries.
func pathsEqual(got, want []string) bool {
	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

func TestWhitelist(t *testing.T) {
	for _, test := range []struct {
		// description of the test.
		desc string
		// paths are the paths to whitelist
		paths []string
		// want are all of the directory entries that should be
		// visible (nothing beyond this set should be visible).
		want []string
	}{
		{
			desc:  "root",
			paths: []string{"/"},
			want:  []string{"/a", "/a/a1.txt", "/a/a2.txt", "/b", "/b/b1.txt", "/b/c", "/b/c/c1.txt", "/symlinks", "/symlinks/normal.txt", "/symlinks/to_normal.txt", "/symlinks/recursive"},
		},
		{
			desc:  "top-level directories",
			paths: []string{"/a", "/b"},
			want:  []string{"/a", "/a/a1.txt", "/a/a2.txt", "/b", "/b/b1.txt", "/b/c", "/b/c/c1.txt"},
		},
		{
			desc:  "nested directories (1/2)",
			paths: []string{"/b", "/b/c"},
			want:  []string{"/b", "/b/b1.txt", "/b/c", "/b/c/c1.txt"},
		},
		{
			desc:  "nested directories (2/2)",
			paths: []string{"/b/c", "/b"},
			want:  []string{"/b", "/b/b1.txt", "/b/c", "/b/c/c1.txt"},
		},
		{
			desc:  "single file",
			paths: []string{"/b/c/c1.txt"},
			want:  []string{"/b", "/b/c", "/b/c/c1.txt"},
		},
		{
			desc:  "single file and directory",
			paths: []string{"/a/a1.txt", "/b/c"},
			want:  []string{"/a", "/a/a1.txt", "/b", "/b/c", "/b/c/c1.txt"},
		},
		{
			desc:  "symlink",
			paths: []string{"/symlinks/to_normal.txt"},
			want:  []string{"/symlinks", "/symlinks/normal.txt", "/symlinks/to_normal.txt"},
		},
		{
			desc:  "recursive symlink",
			paths: []string{"/symlinks/recursive/normal.txt"},
			want:  []string{"/symlinks", "/symlinks/normal.txt", "/symlinks/recursive"},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			m, p, err := newTestMountNamespace(t)
			if err != nil {
				t.Errorf("Failed to create MountNamespace: %v", err)
			}
			defer os.RemoveAll(p)

			ctx := withRoot(contexttest.RootContext(t), m.Root())
			if err := createTestDirs(ctx, t, m); err != nil {
				t.Errorf("Failed to create test dirs: %v", err)
			}

			if err := installWhitelist(ctx, m, test.paths); err != nil {
				t.Errorf("installWhitelist(%v) err got %v want nil", test.paths, err)
			}

			got, err := allPaths(ctx, t, m, "/")
			if err != nil {
				t.Fatalf("Failed to lookup paths (whitelisted: %v): %v", test.paths, err)
			}

			if !pathsEqual(got, test.want) {
				t.Errorf("For paths %v got %v want %v", test.paths, got, test.want)
			}
		})
	}
}

func TestRootPath(t *testing.T) {
	// Create a temp dir, which will be the root of our mounted fs.
	rootPath, err := ioutil.TempDir(os.TempDir(), "root")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}
	defer os.RemoveAll(rootPath)

	// Create two files inside the new root, one which will be whitelisted
	// and one not.
	whitelisted, err := ioutil.TempFile(rootPath, "white")
	if err != nil {
		t.Fatalf("TempFile failed: %v", err)
	}
	if _, err := ioutil.TempFile(rootPath, "black"); err != nil {
		t.Fatalf("TempFile failed: %v", err)
	}

	// Create a mount with a root path and single whitelisted file.
	hostFS := &Filesystem{}
	ctx := contexttest.Context(t)
	data := fmt.Sprintf("%s=%s,%s=%s", rootPathKey, rootPath, whitelistKey, whitelisted.Name())
	inode, err := hostFS.Mount(ctx, "", fs.MountSourceFlags{}, data)
	if err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	mm, err := fs.NewMountNamespace(ctx, inode)
	if err != nil {
		t.Fatalf("NewMountNamespace failed: %v", err)
	}
	if err := hostFS.InstallWhitelist(ctx, mm); err != nil {
		t.Fatalf("InstallWhitelist failed: %v", err)
	}

	// Get the contents of the root directory.
	rootDir := mm.Root()
	rctx := withRoot(ctx, rootDir)
	f, err := rootDir.Inode.GetFile(rctx, rootDir, fs.FileFlags{})
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}
	c := &fs.CollectEntriesSerializer{}
	if err := f.Readdir(rctx, c); err != nil {
		t.Fatalf("Readdir failed: %v", err)
	}

	// We should have only our whitelisted file, plus the dots.
	want := []string{path.Base(whitelisted.Name()), ".", ".."}
	got := c.Order
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Readdir got %v, wanted %v", got, want)
	}
}

type rootContext struct {
	context.Context
	root *fs.Dirent
}

// withRoot returns a copy of ctx with the given root.
func withRoot(ctx context.Context, root *fs.Dirent) context.Context {
	return &rootContext{
		Context: ctx,
		root:    root,
	}
}

// Value implements Context.Value.
func (rc rootContext) Value(key interface{}) interface{} {
	switch key {
	case fs.CtxRoot:
		rc.root.IncRef()
		return rc.root
	default:
		return rc.Context.Value(key)
	}
}
