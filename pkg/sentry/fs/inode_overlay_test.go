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
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/syserror"
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
				false /* revalidate */),
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
				false /* revalidate */),
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
				false /* revalidate */),
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
				false /* revalidate */),
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
				false /* revalidate */),
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
				false /* revalidate */),
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
				false /* revalidate */),
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
				false /* revalidate */),
			name:     "a",
			found:    true,
			hasUpper: false,
			hasLower: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			dirent, err := test.dir.Lookup(ctx, test.name)
			if test.found && (err == syserror.ENOENT || dirent.IsNegative()) {
				t.Fatalf("lookup %q expected to find positive dirent, got dirent %v err %v", test.name, dirent, err)
			}
			if !test.found {
				if err != syserror.ENOENT && !dirent.IsNegative() {
					t.Errorf("lookup %q expected to return ENOENT or negative dirent, got dirent %v err %v", test.name, dirent, err)
				}
				// Nothing more to check.
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

func TestLookupRevalidation(t *testing.T) {
	// File name used in the tests.
	fileName := "foofile"
	ctx := contexttest.Context(t)
	for _, tc := range []struct {
		// Test description.
		desc string

		// Upper and lower fs for the overlay.
		upper *fs.Inode
		lower *fs.Inode

		// Whether the upper requires revalidation.
		revalidate bool

		// Whether we should get the same dirent on second lookup.
		wantSame bool
	}{
		{
			desc:       "file from upper with no revalidation",
			upper:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			lower:      newTestRamfsDir(ctx, nil, nil),
			revalidate: false,
			wantSame:   true,
		},
		{
			desc:       "file from upper with revalidation",
			upper:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			lower:      newTestRamfsDir(ctx, nil, nil),
			revalidate: true,
			wantSame:   false,
		},
		{
			desc:       "file from lower with no revalidation",
			upper:      newTestRamfsDir(ctx, nil, nil),
			lower:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			revalidate: false,
			wantSame:   true,
		},
		{
			desc:       "file from lower with revalidation",
			upper:      newTestRamfsDir(ctx, nil, nil),
			lower:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			revalidate: true,
			// The file does not exist in the upper, so we do not
			// need to revalidate it.
			wantSame: true,
		},
		{
			desc:       "file from upper and lower with no revalidation",
			upper:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			lower:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			revalidate: false,
			wantSame:   true,
		},
		{
			desc:       "file from upper and lower with revalidation",
			upper:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			lower:      newTestRamfsDir(ctx, []dirContent{{name: fileName}}, nil),
			revalidate: true,
			wantSame:   false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			root := fs.NewDirent(ctx, newTestRamfsDir(ctx, nil, nil), "root")
			ctx = &rootContext{
				Context: ctx,
				root:    root,
			}
			overlay := fs.NewDirent(ctx, fs.NewTestOverlayDir(ctx, tc.upper, tc.lower, tc.revalidate), "overlay")
			// Lookup the file twice through the overlay.
			first, err := overlay.Walk(ctx, root, fileName)
			if err != nil {
				t.Fatalf("overlay.Walk(%q) failed: %v", fileName, err)
			}
			second, err := overlay.Walk(ctx, root, fileName)
			if err != nil {
				t.Fatalf("overlay.Walk(%q) failed: %v", fileName, err)
			}

			if tc.wantSame && first != second {
				t.Errorf("dirent lookup got different dirents, wanted same\nfirst=%+v\nsecond=%+v", first, second)
			} else if !tc.wantSame && first == second {
				t.Errorf("dirent lookup got the same dirent, wanted different: %+v", first)
			}
		})
	}
}

func TestCacheFlush(t *testing.T) {
	ctx := contexttest.Context(t)

	// Upper and lower each have a file.
	upperFileName := "file-from-upper"
	lowerFileName := "file-from-lower"
	upper := newTestRamfsDir(ctx, []dirContent{{name: upperFileName}}, nil)
	lower := newTestRamfsDir(ctx, []dirContent{{name: lowerFileName}}, nil)

	overlay := fs.NewTestOverlayDir(ctx, upper, lower, true /* revalidate */)

	mns, err := fs.NewMountNamespace(ctx, overlay)
	if err != nil {
		t.Fatalf("NewMountNamespace failed: %v", err)
	}
	root := mns.Root()
	defer root.DecRef(ctx)

	ctx = &rootContext{
		Context: ctx,
		root:    root,
	}

	for _, fileName := range []string{upperFileName, lowerFileName} {
		// Walk to the file.
		maxTraversals := uint(0)
		dirent, err := mns.FindInode(ctx, root, nil, fileName, &maxTraversals)
		if err != nil {
			t.Fatalf("FindInode(%q) failed: %v", fileName, err)
		}

		// Get a file from the dirent.
		file, err := dirent.Inode.GetFile(ctx, dirent, fs.FileFlags{Read: true})
		if err != nil {
			t.Fatalf("GetFile() failed: %v", err)
		}

		// The dirent should have 3 refs, one from us, one from the
		// file, and one from the dirent cache.
		// dirent cache.
		if got, want := dirent.ReadRefs(), 3; int(got) != want {
			t.Errorf("dirent.ReadRefs() got %d want %d", got, want)
		}

		// Drop the file reference.
		file.DecRef(ctx)

		// Dirent should have 2 refs left.
		if got, want := dirent.ReadRefs(), 2; int(got) != want {
			t.Errorf("dirent.ReadRefs() got %d want %d", got, want)
		}

		// Flush the dirent cache.
		mns.FlushMountSourceRefs()

		// Dirent should have 1 ref left from the dirent cache.
		if got, want := dirent.ReadRefs(), 1; int(got) != want {
			t.Errorf("dirent.ReadRefs() got %d want %d", got, want)
		}

		// Drop our ref.
		dirent.DecRef(ctx)

		// We should be back to zero refs.
		if got, want := dirent.ReadRefs(), 0; int(got) != want {
			t.Errorf("dirent.ReadRefs() got %d want %d", got, want)
		}
	}

}

type dir struct {
	fs.InodeOperations

	// List of negative child names.
	negative []string

	// ReaddirCalled records whether Readdir was called on a file
	// corresponding to this inode.
	ReaddirCalled bool
}

// GetXattr implements InodeOperations.GetXattr.
func (d *dir) GetXattr(_ context.Context, _ *fs.Inode, name string, _ uint64) (string, error) {
	for _, n := range d.negative {
		if name == fs.XattrOverlayWhiteout(n) {
			return "y", nil
		}
	}
	return "", syserror.ENOATTR
}

// GetFile implements InodeOperations.GetFile.
func (d *dir) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	file, err := d.InodeOperations.GetFile(ctx, dirent, flags)
	if err != nil {
		return nil, err
	}
	defer file.DecRef(ctx)
	// Wrap the file's FileOperations in a dirFile.
	fops := &dirFile{
		FileOperations: file.FileOperations,
		inode:          d,
	}
	return fs.NewFile(ctx, dirent, flags, fops), nil
}

type dirContent struct {
	name string
	dir  bool
}

type dirFile struct {
	fs.FileOperations
	inode *dir
}

type inode struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotAllocatable       `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeNotTruncatable       `state:"nosave"`
	fsutil.InodeNotVirtual           `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeStaticFileGetter
}

// Readdir implements fs.FileOperations.Readdir. It sets the ReaddirCalled
// field on the inode.
func (f *dirFile) Readdir(ctx context.Context, file *fs.File, ser fs.DentrySerializer) (int64, error) {
	f.inode.ReaddirCalled = true
	return f.FileOperations.Readdir(ctx, file, ser)
}

func newTestRamfsInode(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	inode := fs.NewInode(ctx, &inode{
		InodeStaticFileGetter: fsutil.InodeStaticFileGetter{
			Contents: []byte("foobar"),
		},
	}, msrc, fs.StableAttr{Type: fs.RegularFile})
	return inode
}

func newTestRamfsDir(ctx context.Context, contains []dirContent, negative []string) *fs.Inode {
	msrc := fs.NewPseudoMountSource(ctx)
	contents := make(map[string]*fs.Inode)
	for _, c := range contains {
		if c.dir {
			contents[c.name] = newTestRamfsDir(ctx, nil, nil)
		} else {
			contents[c.name] = newTestRamfsInode(ctx, msrc)
		}
	}
	dops := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermissions{
		User: fs.PermMask{Read: true, Execute: true},
	})
	return fs.NewInode(ctx, &dir{
		InodeOperations: dops,
		negative:        negative,
	}, msrc, fs.StableAttr{Type: fs.Directory})
}
