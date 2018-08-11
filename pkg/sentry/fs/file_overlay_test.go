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
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	ramfstest "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs/test"
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
	upperDir := upper.InodeOperations.(*dir).InodeOperations.(*ramfstest.Dir)

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
	upperDir.AddChild(ctx, "c", fs.NewInode(ramfstest.NewFile(ctx, fs.FilePermissions{}),
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
