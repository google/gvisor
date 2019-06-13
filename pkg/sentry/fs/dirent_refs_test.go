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
	"syscall"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
)

func newMockDirInode(ctx context.Context, cache *DirentCache) *Inode {
	return NewMockInode(ctx, NewMockMountSource(cache), StableAttr{Type: Directory})
}

func TestWalkPositive(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	root := NewDirent(newMockDirInode(ctx, nil), "root")

	if got := root.ReadRefs(); got != 1 {
		t.Fatalf("root has a ref count of %d, want %d", got, 1)
	}

	name := "d"
	d, err := root.walk(ctx, root, name, false)
	if err != nil {
		t.Fatalf("root.walk(root, %q) got %v, want nil", name, err)
	}

	if got := root.ReadRefs(); got != 2 {
		t.Fatalf("root has a ref count of %d, want %d", got, 2)
	}

	if got := d.ReadRefs(); got != 1 {
		t.Fatalf("child name = %q has a ref count of %d, want %d", d.name, got, 1)
	}

	d.DecRef()

	if got := root.ReadRefs(); got != 1 {
		t.Fatalf("root has a ref count of %d, want %d", got, 1)
	}

	if got := d.ReadRefs(); got != 0 {
		t.Fatalf("child name = %q has a ref count of %d, want %d", d.name, got, 0)
	}

	root.flush()

	if got := len(root.children); got != 0 {
		t.Fatalf("root has %d children, want %d", got, 0)
	}
}

func TestWalkNegative(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	root := NewDirent(NewEmptyDir(ctx, nil), "root")
	mn := root.Inode.InodeOperations.(*mockInodeOperationsLookupNegative)

	if got := root.ReadRefs(); got != 1 {
		t.Fatalf("root has a ref count of %d, want %d", got, 1)
	}

	name := "d"
	for i := 0; i < 100; i++ {
		_, err := root.walk(ctx, root, name, false)
		if err != syscall.ENOENT {
			t.Fatalf("root.walk(root, %q) got %v, want %v", name, err, syscall.ENOENT)
		}
	}

	if got := root.ReadRefs(); got != 1 {
		t.Fatalf("root has a ref count of %d, want %d", got, 1)
	}

	if got := len(root.children); got != 1 {
		t.Fatalf("root has %d children, want %d", got, 1)
	}

	w, ok := root.children[name]
	if !ok {
		t.Fatalf("root wants child at %q", name)
	}

	child := w.Get()
	if child == nil {
		t.Fatalf("root wants to resolve weak reference")
	}

	if !child.(*Dirent).IsNegative() {
		t.Fatalf("root found positive child at %q, want negative", name)
	}

	if got := child.(*Dirent).ReadRefs(); got != 2 {
		t.Fatalf("child has a ref count of %d, want %d", got, 2)
	}

	child.DecRef()

	if got := child.(*Dirent).ReadRefs(); got != 1 {
		t.Fatalf("child has a ref count of %d, want %d", got, 1)
	}

	if got := len(root.children); got != 1 {
		t.Fatalf("root has %d children, want %d", got, 1)
	}

	root.DecRef()

	if got := root.ReadRefs(); got != 0 {
		t.Fatalf("root has a ref count of %d, want %d", got, 0)
	}

	AsyncBarrier()

	if got := mn.releaseCalled; got != true {
		t.Fatalf("root.Close was called %v, want true", got)
	}
}

type mockInodeOperationsLookupNegative struct {
	*MockInodeOperations
	releaseCalled bool
}

func NewEmptyDir(ctx context.Context, cache *DirentCache) *Inode {
	m := NewMockMountSource(cache)
	return NewInode(&mockInodeOperationsLookupNegative{
		MockInodeOperations: NewMockInodeOperations(ctx),
	}, m, StableAttr{Type: Directory})
}

func (m *mockInodeOperationsLookupNegative) Lookup(ctx context.Context, dir *Inode, p string) (*Dirent, error) {
	return NewNegativeDirent(p), nil
}

func (m *mockInodeOperationsLookupNegative) Release(context.Context) {
	m.releaseCalled = true
}

func TestHashNegativeToPositive(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	root := NewDirent(NewEmptyDir(ctx, nil), "root")

	name := "d"
	_, err := root.walk(ctx, root, name, false)
	if err != syscall.ENOENT {
		t.Fatalf("root.walk(root, %q) got %v, want %v", name, err, syscall.ENOENT)
	}

	if got := root.exists(ctx, root, name); got != false {
		t.Fatalf("got %q exists, want does not exist", name)
	}

	f, err := root.Create(ctx, root, name, FileFlags{}, FilePermissions{})
	if err != nil {
		t.Fatalf("root.Create(%q, _), got error %v, want nil", name, err)
	}
	d := f.Dirent

	if d.IsNegative() {
		t.Fatalf("got negative Dirent, want positive")
	}

	if got := d.ReadRefs(); got != 1 {
		t.Fatalf("child %q has a ref count of %d, want %d", name, got, 1)
	}

	if got := root.ReadRefs(); got != 2 {
		t.Fatalf("root has a ref count of %d, want %d", got, 2)
	}

	if got := len(root.children); got != 1 {
		t.Fatalf("got %d children, want %d", got, 1)
	}

	w, ok := root.children[name]
	if !ok {
		t.Fatalf("failed to find weak reference to %q", name)
	}

	child := w.Get()
	if child == nil {
		t.Fatalf("want to resolve weak reference")
	}

	if child.(*Dirent) != d {
		t.Fatalf("got foreign child")
	}
}

func TestRevalidate(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// Whether to make negative Dirents.
		makeNegative bool
	}{
		{
			desc:         "Revalidate negative Dirent",
			makeNegative: true,
		},
		{
			desc:         "Revalidate positive Dirent",
			makeNegative: false,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			root := NewDirent(NewMockInodeRevalidate(ctx, test.makeNegative), "root")

			name := "d"
			d1, err := root.walk(ctx, root, name, false)
			if !test.makeNegative && err != nil {
				t.Fatalf("root.walk(root, %q) got %v, want nil", name, err)
			}
			d2, err := root.walk(ctx, root, name, false)
			if !test.makeNegative && err != nil {
				t.Fatalf("root.walk(root, %q) got %v, want nil", name, err)
			}
			if !test.makeNegative && d1 == d2 {
				t.Fatalf("revalidating walk got same *Dirent, want different")
			}
			if got := len(root.children); got != 1 {
				t.Errorf("revalidating walk got %d children, want %d", got, 1)
			}
		})
	}
}

type MockInodeOperationsRevalidate struct {
	*MockInodeOperations
	makeNegative bool
}

func NewMockInodeRevalidate(ctx context.Context, makeNegative bool) *Inode {
	mn := NewMockInodeOperations(ctx)
	m := NewMockMountSource(nil)
	m.MountSourceOperations.(*MockMountSourceOps).revalidate = true
	return NewInode(&MockInodeOperationsRevalidate{MockInodeOperations: mn, makeNegative: makeNegative}, m, StableAttr{Type: Directory})
}

func (m *MockInodeOperationsRevalidate) Lookup(ctx context.Context, dir *Inode, p string) (*Dirent, error) {
	if !m.makeNegative {
		return m.MockInodeOperations.Lookup(ctx, dir, p)
	}
	return NewNegativeDirent(p), nil
}

func TestCreateExtraRefs(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// root is the Dirent to create from.
		root *Dirent

		// expected references on walked Dirent.
		refs int64
	}{
		{
			desc: "Create caching",
			root: NewDirent(NewEmptyDir(ctx, NewDirentCache(1)), "root"),
			refs: 2,
		},
		{
			desc: "Create not caching",
			root: NewDirent(NewEmptyDir(ctx, nil), "root"),
			refs: 1,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			name := "d"
			f, err := test.root.Create(ctx, test.root, name, FileFlags{}, FilePermissions{})
			if err != nil {
				t.Fatalf("root.Create(root, %q) failed: %v", name, err)
			}
			d := f.Dirent

			if got := d.ReadRefs(); got != test.refs {
				t.Errorf("dirent has a ref count of %d, want %d", got, test.refs)
			}
		})
	}
}

func TestRemoveExtraRefs(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// root is the Dirent to make and remove from.
		root *Dirent
	}{
		{
			desc: "Remove caching",
			root: NewDirent(NewEmptyDir(ctx, NewDirentCache(1)), "root"),
		},
		{
			desc: "Remove not caching",
			root: NewDirent(NewEmptyDir(ctx, nil), "root"),
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			name := "d"
			f, err := test.root.Create(ctx, test.root, name, FileFlags{}, FilePermissions{})
			if err != nil {
				t.Fatalf("root.Create(%q, _) failed: %v", name, err)
			}
			d := f.Dirent

			if err := test.root.Remove(contexttest.Context(t), test.root, name); err != nil {
				t.Fatalf("root.Remove(root, %q) failed: %v", name, err)
			}

			if got := d.ReadRefs(); got != 1 {
				t.Fatalf("dirent has a ref count of %d, want %d", got, 1)
			}

			d.DecRef()

			test.root.flush()

			if got := len(test.root.children); got != 0 {
				t.Errorf("root has %d children, want %d", got, 0)
			}
		})
	}
}

func TestRenameExtraRefs(t *testing.T) {
	// refs == 0 -> one reference.
	// refs == -1 -> has been destroyed.

	ctx := contexttest.Context(t)
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// cache of extra Dirent references, may be nil.
		cache *DirentCache
	}{
		{
			desc:  "Rename no caching",
			cache: nil,
		},
		{
			desc:  "Rename caching",
			cache: NewDirentCache(5),
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			dirAttr := StableAttr{Type: Directory}

			oldParent := NewDirent(NewMockInode(ctx, NewMockMountSource(test.cache), dirAttr), "old_parent")
			newParent := NewDirent(NewMockInode(ctx, NewMockMountSource(test.cache), dirAttr), "new_parent")

			renamed, err := oldParent.Walk(ctx, oldParent, "old_child")
			if err != nil {
				t.Fatalf("Walk(oldParent, %q) got error %v, want nil", "old_child", err)
			}
			replaced, err := newParent.Walk(ctx, oldParent, "new_child")
			if err != nil {
				t.Fatalf("Walk(newParent, %q) got error %v, want nil", "new_child", err)
			}

			if err := Rename(contexttest.RootContext(t), oldParent /*root */, oldParent, "old_child", newParent, "new_child"); err != nil {
				t.Fatalf("Rename got error %v, want nil", err)
			}

			oldParent.flush()
			newParent.flush()

			// Expect to have only active references.
			if got := renamed.ReadRefs(); got != 1 {
				t.Errorf("renamed has ref count %d, want only active references %d", got, 1)
			}
			if got := replaced.ReadRefs(); got != 1 {
				t.Errorf("replaced has ref count %d, want only active references %d", got, 1)
			}
		})
	}
}
