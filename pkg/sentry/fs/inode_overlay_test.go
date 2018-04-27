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
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

func TestLookup(t *testing.T) {
	ctx := contexttest.Context(t)
	for _, test := range []struct {
		// Test description.
		desc string

		// Lookup parameters.
		dir  *fs.Inode
		name string

		// Want from lookup.
		err      error
		found    bool
		hasUpper bool
		hasLower bool
	}{
		{
			desc: "no upper, lower has name",
			dir: fs.NewTestOverlayDir(ctx,
				nil, /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: false,
			hasLower: true,
		},
		{
			desc: "no lower, upper has name",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* upper */
				nil, /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: true,
			hasLower: false,
		},
		{
			desc: "upper and lower, only lower has name",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "b",
						dir:  false,
					},
				}, nil), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: false,
			hasLower: true,
		},
		{
			desc: "upper and lower, only upper has name",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "b",
						dir:  false,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: true,
			hasLower: false,
		},
		{
			desc: "upper and lower, both have file",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: true,
			hasLower: false,
		},
		{
			desc: "upper and lower, both have directory",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  true,
					},
				}, nil), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  true,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: true,
			hasLower: true,
		},
		{
			desc: "upper and lower, upper negative masks lower file",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, nil, []string{"a"}), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    false,
			hasUpper: false,
			hasLower: false,
		},
		{
			desc: "upper and lower, upper negative does not mask lower file",
			dir: fs.NewTestOverlayDir(ctx,
				newTestRamfsDir(ctx, nil, []string{"b"}), /* upper */
				newTestRamfsDir(ctx, []dirContent{
					{
						name: "a",
						dir:  false,
					},
				}, nil), /* lower */
			),
			name:     "a",
			found:    true,
			hasUpper: false,
			hasLower: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			dirent, err := test.dir.Lookup(ctx, test.name)
			if err != test.err {
				t.Fatalf("lookup got error %v, want %v", err, test.err)
			}
			if test.found && dirent.IsNegative() {
				t.Fatalf("lookup expected to find %q, got negative dirent", test.name)
			}
			if !test.found {
				return
			}
			if hasUpper := dirent.Inode.TestHasUpperFS(); hasUpper != test.hasUpper {
				t.Fatalf("lookup got upper filesystem %v, want %v", hasUpper, test.hasUpper)
			}
			if hasLower := dirent.Inode.TestHasLowerFS(); hasLower != test.hasLower {
				t.Errorf("lookup got lower filesystem %v, want %v", hasLower, test.hasLower)
			}
		})
	}
}

type dir struct {
	fs.InodeOperations

	// list of negative child names.
	negative []string
}

func (d *dir) Getxattr(inode *fs.Inode, name string) ([]byte, error) {
	for _, n := range d.negative {
		if name == fs.XattrOverlayWhiteout(n) {
			return []byte("y"), nil
		}
	}
	return nil, syserror.ENOATTR
}

type dirContent struct {
	name string
	dir  bool
}

func newTestRamfsDir(ctx context.Context, contains []dirContent, negative []string) *fs.Inode {
	msrc := fs.NewCachingMountSource(nil, fs.MountSourceFlags{})
	contents := make(map[string]*fs.Inode)
	for _, c := range contains {
		if c.dir {
			contents[c.name] = newTestRamfsDir(ctx, nil, nil)
		} else {
			contents[c.name] = fs.NewInode(ramfstest.NewFile(ctx, fs.FilePermissions{}), msrc, fs.StableAttr{Type: fs.RegularFile})
		}
	}
	dops := ramfstest.NewDir(ctx, contents, fs.FilePermissions{
		User: fs.PermMask{Read: true, Execute: true},
	})
	return fs.NewInode(&dir{
		InodeOperations: dops,
		negative:        negative,
	}, msrc, fs.StableAttr{Type: fs.Directory})
}
