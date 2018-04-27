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
			),
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
			),
			names: []string{".", "..", "a", "b"},
		},
		{
			desc: "upper and lower, entries combine",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
				}, nil), /* lower */
				newTestRamfsDir(ctx, []dirContent{
					{name: "b"},
				}, nil), /* lower */
			),
			names: []string{".", "..", "a", "b"},
		},
		{
			desc: "upper and lower, entries combine, none are masked",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
				}, []string{"b"}), /* lower */
				newTestRamfsDir(ctx, []dirContent{
					{name: "c"},
				}, nil), /* lower */
			),
			names: []string{".", "..", "a", "c"},
		},
		{
			desc: "upper and lower, entries combine, upper masks some of lower",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{name: "a"},
				}, []string{"b"}), /* lower */
				newTestRamfsDir(ctx, []dirContent{
					{name: "b"}, /* will be masked */
					{name: "c"},
				}, nil), /* lower */
			),
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
