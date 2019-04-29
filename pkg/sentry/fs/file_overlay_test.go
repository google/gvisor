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

package fs_test

import (
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/contexttest"
)

func TestReaddir(t *testing.T) {
	ctx := contexttest.Context(t)
	ctx = &rootContext{
		Context: ctx,
		root:    fs.NewDirent(newTestRamfsDir(ctx, nil, nil), "root"),
	}
	for _, test := range []struct {
		// Test description.
		desc string

		// Lookup parameters.
		dir *fs.Inode

		// Want from lookup.
		err   error
		names []string
	}{
		{
			desc: "no upper, lower has entries",
			dir: fs.NewTestOverlayDir(ctx,
				nil, /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
					{name: "b"},
				}, nil), /* lower */
				false /* revalidate */),
			names: []string{".", "..", "a", "b"},
		},
		{
			desc: "upper has entries, no lower",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
					{name: "b"},
				}, nil), /* upper */
				nil, /* lower */
				false /* revalidate */),
			names: []string{".", "..", "a", "b"},
		},
		{
			desc: "upper and lower, entries combine",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
				}, nil), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{name: "b"},
				}, nil), /* lower */
				false /* revalidate */),
			names: []string{".", "..", "a", "b"},
		},
		{
			desc: "upper and lower, entries combine, none are masked",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
				}, []string{"b"}), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{name: "c"},
				}, nil), /* lower */
				false /* revalidate */),
			names: []string{".", "..", "a", "c"},
		},
		{
			desc: "upper and lower, entries combine, upper masks some of lower",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
				}, []string{"b"}), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{name: "b"}, /* will be masked */
					{name: "c"},
				}, nil), /* lower */
				false /* revalidate */),
			names: []string{".", "..", "a", "c"},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			openDir, err := test.dir.GetFile(ctx, fs.NewDirent(test.dir, "stub"), fs.FileFlags{Read: true})
			if err != nil {
				t.Fatalf("GetFile got error %v, want nil", err)
			}
			stubSerializer := &fs.CollectEntriesSerializer{}
			err = openDir.Readdir(ctx, stubSerializer)
			if err != test.err {
				t.Fatalf("Readdir got error %v, want nil", err)
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(stubSerializer.Order, test.names) {
				t.Errorf("Readdir got names %v, want %v", stubSerializer.Order, test.names)
			}
		})
	}
}

func TestReaddirRevalidation(t *testing.T) {
	ctx := contexttest.Context(t)
	ctx = &rootContext{
		Context: ctx,
		root:    fs.NewDirent(newTestRamfsDir(ctx, nil, nil), "root"),
	}

	// Create an overlay with two directories, each with one file.
	upper := newTestRamfsDir(ctx, []dirContent{{name: "a"}}, nil)
	lower := newTestRamfsDir(ctx, []dirContent{{name: "b"}}, nil)
	overlay := fs.NewTestOverlayDir(ctx, upper, lower, true /* revalidate */)

	// Get a handle to the dirent in the upper filesystem so that we can
	// modify it without going through the dirent.
	upperDir := upper.InodeOperations.(*dir).InodeOperations.(*ramfs.Dir)

	// Check that overlay returns the files from both upper and lower.
	openDir, err := overlay.GetFile(ctx, fs.NewDirent(overlay, "stub"), fs.FileFlags{Read: true})
	if err != nil {
		t.Fatalf("GetFile got error %v, want nil", err)
	}
	ser := &fs.CollectEntriesSerializer{}
	if err := openDir.Readdir(ctx, ser); err != nil {
		t.Fatalf("Readdir got error %v, want nil", err)
	}
	got, want := ser.Order, []string{".", "..", "a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Readdir got names %v, want %v", got, want)
	}

	// Remove "a" from the upper and add "c".
	if err := upperDir.Remove(ctx, upper, "a"); err != nil {
		t.Fatalf("error removing child: %v", err)
	}
	upperDir.AddChild(ctx, "c", fs.NewInode(fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermissions{}, 0),
		upper.MountSource, fs.StableAttr{Type: fs.RegularFile}))

	// Seek to beginning of the directory and do the readdir again.
	if _, err := openDir.Seek(ctx, fs.SeekSet, 0); err != nil {
		t.Fatalf("error seeking to beginning of dir: %v", err)
	}
	ser = &fs.CollectEntriesSerializer{}
	if err := openDir.Readdir(ctx, ser); err != nil {
		t.Fatalf("Readdir got error %v, want nil", err)
	}

	// Readdir should return the updated children.
	got, want = ser.Order, []string{".", "..", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Readdir got names %v, want %v", got, want)
	}
}

// TestReaddirOverlayFrozen tests that calling Readdir on an overlay file with
// a frozen dirent tree does not make Readdir calls to the underlying files.
func TestReaddirOverlayFrozen(t *testing.T) {
	ctx := contexttest.Context(t)

	// Create an overlay with two directories, each with two files.
	upper := newTestRamfsDir(ctx, []dirContent{{name: "upper-file1"}, {name: "upper-file2"}}, nil)
	lower := newTestRamfsDir(ctx, []dirContent{{name: "lower-file1"}, {name: "lower-file2"}}, nil)
	overlayInode := fs.NewTestOverlayDir(ctx, upper, lower, false)

	// Set that overlay as the root.
	root := fs.NewDirent(overlayInode, "root")
	ctx = &rootContext{
		Context: ctx,
		root:    root,
	}

	// Check that calling Readdir on the root now returns all 4 files (2
	// from each layer in the overlay).
	rootFile, err := root.Inode.GetFile(ctx, root, fs.FileFlags{Read: true})
	if err != nil {
		t.Fatalf("root.Inode.GetFile failed: %v", err)
	}
	defer rootFile.DecRef()
	ser := &fs.CollectEntriesSerializer{}
	if err := rootFile.Readdir(ctx, ser); err != nil {
		t.Fatalf("rootFile.Readdir failed: %v", err)
	}
	if got, want := ser.Order, []string{".", "..", "lower-file1", "lower-file2", "upper-file1", "upper-file2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Readdir got names %v, want %v", got, want)
	}

	// Readdir should have been called on upper and lower.
	upperDir := upper.InodeOperations.(*dir)
	lowerDir := lower.InodeOperations.(*dir)
	if !upperDir.ReaddirCalled {
		t.Errorf("upperDir.ReaddirCalled got %v, want true", upperDir.ReaddirCalled)
	}
	if !lowerDir.ReaddirCalled {
		t.Errorf("lowerDir.ReaddirCalled got %v, want true", lowerDir.ReaddirCalled)
	}

	// Reset.
	upperDir.ReaddirCalled = false
	lowerDir.ReaddirCalled = false

	// Take references on "upper-file1" and "lower-file1", pinning them in
	// the dirent tree.
	for _, name := range []string{"upper-file1", "lower-file1"} {
		if _, err := root.Walk(ctx, root, name); err != nil {
			t.Fatalf("root.Walk(%q) failed: %v", name, err)
		}
		// Don't drop a reference on the returned dirent so that it
		// will stay in the tree.
	}

	// Freeze the dirent tree.
	root.Freeze()

	// Seek back to the beginning of the file.
	if _, err := rootFile.Seek(ctx, fs.SeekSet, 0); err != nil {
		t.Fatalf("error seeking to beginning of directory: %v", err)
	}

	// Calling Readdir on the root now will return only the pinned
	// children.
	ser = &fs.CollectEntriesSerializer{}
	if err := rootFile.Readdir(ctx, ser); err != nil {
		t.Fatalf("rootFile.Readdir failed: %v", err)
	}
	if got, want := ser.Order, []string{".", "..", "lower-file1", "upper-file1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Readdir got names %v, want %v", got, want)
	}

	// Readdir should NOT have been called on upper or lower.
	if upperDir.ReaddirCalled {
		t.Errorf("upperDir.ReaddirCalled got %v, want false", upperDir.ReaddirCalled)
	}
	if lowerDir.ReaddirCalled {
		t.Errorf("lowerDir.ReaddirCalled got %v, want false", lowerDir.ReaddirCalled)
	}
}

type rootContext struct {
	context.Context
	root *fs.Dirent
}

// Value implements context.Context.
func (r *rootContext) Value(key interface{}) interface{} {
	switch key {
	case fs.CtxRoot:
		r.root.IncRef()
		return r.root
	default:
		return r.Context.Value(key)
	}
}
