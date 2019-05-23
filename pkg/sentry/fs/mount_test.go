// Copyright 2018 The gVisor Authors.
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

package fs

import (
	"fmt"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
)

// cacheReallyContains iterates through the dirent cache to determine whether
// it contains the given dirent.
func cacheReallyContains(cache *DirentCache, d *Dirent) bool {
	for i := cache.list.Front(); i != nil; i = i.Next() {
		if i == d {
			return true
		}
	}
	return false
}

func mountPathsAre(root *Dirent, got []*Mount, want ...string) error {
	gotPaths := make(map[string]struct{}, len(got))
	gotStr := make([]string, len(got))
	for i, g := range got {
		groot := g.Root()
		name, _ := groot.FullName(root)
		groot.DecRef()
		gotStr[i] = name
		gotPaths[name] = struct{}{}
	}
	if len(got) != len(want) {
		return fmt.Errorf("mount paths are different, got: %q, want: %q", gotStr, want)
	}
	for _, w := range want {
		if _, ok := gotPaths[w]; !ok {
			return fmt.Errorf("no mount with path %q found", w)
		}
	}
	return nil
}

// TestMountSourceOnlyCachedOnce tests that a Dirent that is mounted over only ends
// up in a single Dirent Cache. NOTE(b/63848693): Having a dirent in multiple
// caches causes major consistency issues.
func TestMountSourceOnlyCachedOnce(t *testing.T) {
	ctx := contexttest.Context(t)

	rootCache := NewDirentCache(100)
	rootInode := NewMockInode(ctx, NewMockMountSource(rootCache), StableAttr{
		Type: Directory,
	})
	mm, err := NewMountNamespace(ctx, rootInode)
	if err != nil {
		t.Fatalf("NewMountNamespace failed: %v", err)
	}
	rootDirent := mm.Root()
	defer rootDirent.DecRef()

	// Get a child of the root which we will mount over.  Note that the
	// MockInodeOperations causes Walk to always succeed.
	child, err := rootDirent.Walk(ctx, rootDirent, "child")
	if err != nil {
		t.Fatalf("failed to walk to child dirent: %v", err)
	}
	child.maybeExtendReference() // Cache.

	// Ensure that the root cache contains the child.
	if !cacheReallyContains(rootCache, child) {
		t.Errorf("wanted rootCache to contain child dirent, but it did not")
	}

	// Create a new cache and inode, and mount it over child.
	submountCache := NewDirentCache(100)
	submountInode := NewMockInode(ctx, NewMockMountSource(submountCache), StableAttr{
		Type: Directory,
	})
	if err := mm.Mount(ctx, child, submountInode); err != nil {
		t.Fatalf("failed to mount over child: %v", err)
	}

	// Walk to the child again.
	child2, err := rootDirent.Walk(ctx, rootDirent, "child")
	if err != nil {
		t.Fatalf("failed to walk to child dirent: %v", err)
	}

	// Should have a different Dirent than before.
	if child == child2 {
		t.Fatalf("expected %v not equal to %v, but they are the same", child, child2)
	}

	// Neither of the caches should no contain the child.
	if cacheReallyContains(rootCache, child) {
		t.Errorf("wanted rootCache not to contain child dirent, but it did")
	}
	if cacheReallyContains(submountCache, child) {
		t.Errorf("wanted submountCache not to contain child dirent, but it did")
	}
}

func TestAllMountsUnder(t *testing.T) {
	ctx := contexttest.Context(t)

	rootCache := NewDirentCache(100)
	rootInode := NewMockInode(ctx, NewMockMountSource(rootCache), StableAttr{
		Type: Directory,
	})
	mm, err := NewMountNamespace(ctx, rootInode)
	if err != nil {
		t.Fatalf("NewMountNamespace failed: %v", err)
	}
	rootDirent := mm.Root()
	defer rootDirent.DecRef()

	// Add mounts at the following paths:
	paths := []string{
		"/foo",
		"/foo/bar",
		"/foo/bar/baz",
		"/foo/qux",
		"/waldo",
	}

	var maxTraversals uint
	for _, p := range paths {
		maxTraversals = 0
		d, err := mm.FindLink(ctx, rootDirent, nil, p, &maxTraversals)
		if err != nil {
			t.Fatalf("could not find path %q in mount manager: %v", p, err)
		}

		submountInode := NewMockInode(ctx, NewMockMountSource(nil), StableAttr{
			Type: Directory,
		})
		if err := mm.Mount(ctx, d, submountInode); err != nil {
			t.Fatalf("could not mount at %q: %v", p, err)
		}
		d.DecRef()
	}

	// mm root should contain all submounts (and does not include the root mount).
	rootMnt := mm.FindMount(rootDirent)
	submounts := mm.AllMountsUnder(rootMnt)
	allPaths := append(paths, "/")
	if err := mountPathsAre(rootDirent, submounts, allPaths...); err != nil {
		t.Error(err)
	}

	// Each mount should have a unique ID.
	foundIDs := make(map[uint64]struct{})
	for _, m := range submounts {
		if _, ok := foundIDs[m.ID]; ok {
			t.Errorf("got multiple mounts with id %d", m.ID)
		}
		foundIDs[m.ID] = struct{}{}
	}

	// Root mount should have no parent.
	if p := rootMnt.ParentID; p != invalidMountID {
		t.Errorf("root.Parent got %v wanted nil", p)
	}

	// Check that "foo" mount has 3 children.
	maxTraversals = 0
	d, err := mm.FindLink(ctx, rootDirent, nil, "/foo", &maxTraversals)
	if err != nil {
		t.Fatalf("could not find path %q in mount manager: %v", "/foo", err)
	}
	defer d.DecRef()
	submounts = mm.AllMountsUnder(mm.FindMount(d))
	if err := mountPathsAre(rootDirent, submounts, "/foo", "/foo/bar", "/foo/qux", "/foo/bar/baz"); err != nil {
		t.Error(err)
	}

	// "waldo" mount should have no children.
	maxTraversals = 0
	waldo, err := mm.FindLink(ctx, rootDirent, nil, "/waldo", &maxTraversals)
	if err != nil {
		t.Fatalf("could not find path %q in mount manager: %v", "/waldo", err)
	}
	defer waldo.DecRef()
	submounts = mm.AllMountsUnder(mm.FindMount(waldo))
	if err := mountPathsAre(rootDirent, submounts, "/waldo"); err != nil {
		t.Error(err)
	}
}

func TestUnmount(t *testing.T) {
	ctx := contexttest.Context(t)

	rootCache := NewDirentCache(100)
	rootInode := NewMockInode(ctx, NewMockMountSource(rootCache), StableAttr{
		Type: Directory,
	})
	mm, err := NewMountNamespace(ctx, rootInode)
	if err != nil {
		t.Fatalf("NewMountNamespace failed: %v", err)
	}
	rootDirent := mm.Root()
	defer rootDirent.DecRef()

	// Add mounts at the following paths:
	paths := []string{
		"/foo",
		"/foo/bar",
		"/foo/bar/goo",
		"/foo/bar/goo/abc",
		"/foo/abc",
		"/foo/def",
		"/waldo",
		"/wally",
	}

	var maxTraversals uint
	for _, p := range paths {
		maxTraversals = 0
		d, err := mm.FindLink(ctx, rootDirent, nil, p, &maxTraversals)
		if err != nil {
			t.Fatalf("could not find path %q in mount manager: %v", p, err)
		}

		submountInode := NewMockInode(ctx, NewMockMountSource(nil), StableAttr{
			Type: Directory,
		})
		if err := mm.Mount(ctx, d, submountInode); err != nil {
			t.Fatalf("could not mount at %q: %v", p, err)
		}
		d.DecRef()
	}

	allPaths := make([]string, len(paths)+1)
	allPaths[0] = "/"
	copy(allPaths[1:], paths)

	rootMnt := mm.FindMount(rootDirent)
	for i := len(paths) - 1; i >= 0; i-- {
		maxTraversals = 0
		p := paths[i]
		d, err := mm.FindLink(ctx, rootDirent, nil, p, &maxTraversals)
		if err != nil {
			t.Fatalf("could not find path %q in mount manager: %v", p, err)
		}

		if err := mm.Unmount(ctx, d, false); err != nil {
			t.Fatalf("could not unmount at %q: %v", p, err)
		}
		d.DecRef()

		// Remove the path that has been unmounted and the check that the remaining
		// mounts are still there.
		allPaths = allPaths[:len(allPaths)-1]
		submounts := mm.AllMountsUnder(rootMnt)
		if err := mountPathsAre(rootDirent, submounts, allPaths...); err != nil {
			t.Error(err)
		}
	}
}
