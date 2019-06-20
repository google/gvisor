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

package gofer

import (
	"fmt"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/p9/p9test"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// rootTest runs a test with a p9 mock and an fs.InodeOperations created from
// the attached root directory. The root file will be closed and client
// disconnected, but additional files must be closed manually.
func rootTest(t *testing.T, name string, cp cachePolicy, fn func(context.Context, *p9test.Harness, *p9test.Mock, *fs.Inode)) {
	t.Run(name, func(t *testing.T) {
		h, c := p9test.NewHarness(t)
		defer h.Finish()

		// Create a new root. Note that we pass an empty, but non-nil
		// map here. This allows tests to extend the root children
		// dynamically.
		root := h.NewDirectory(map[string]p9test.Generator{})(nil)

		// Return this as the root.
		h.Attacher.EXPECT().Attach().Return(root, nil).Times(1)

		// ... and open via the client.
		rootFile, err := c.Attach("/")
		if err != nil {
			t.Fatalf("unable to attach: %v", err)
		}
		defer rootFile.Close()

		// Wrap an a session.
		s := &session{
			mounter:     fs.RootOwner,
			cachePolicy: cp,
			client:      c,
		}

		// ... and an INode, with only the mode being explicitly valid for now.
		ctx := contexttest.Context(t)
		sattr, rootInodeOperations := newInodeOperations(ctx, s, contextFile{
			file: rootFile,
		}, root.QID, p9.AttrMaskAll(), root.Attr, false /* socket */)
		m := fs.NewMountSource(ctx, s, &filesystem{}, fs.MountSourceFlags{})
		rootInode := fs.NewInode(ctx, rootInodeOperations, m, sattr)

		// Ensure that the cache is fully invalidated, so that any
		// close actions actually take place before the full harness is
		// torn down.
		defer func() {
			m.FlushDirentRefs()

			// Wait for all resources to be released, otherwise the
			// operations may fail after we close the rootFile.
			fs.AsyncBarrier()
		}()

		// Execute the test.
		fn(ctx, h, root, rootInode)
	})
}

func TestLookup(t *testing.T) {
	type lookupTest struct {
		// Name of the test.
		name string

		// Expected return value.
		want error
	}

	tests := []lookupTest{
		{
			name: "mock Walk passes (function succeeds)",
			want: nil,
		},
		{
			name: "mock Walk fails (function fails)",
			want: syscall.ENOENT,
		},
	}

	const file = "file" // The walked target file.

	for _, test := range tests {
		rootTest(t, test.name, cacheNone, func(ctx context.Context, h *p9test.Harness, rootFile *p9test.Mock, rootInode *fs.Inode) {
			// Setup the appropriate result.
			rootFile.WalkCallback = func() error {
				return test.want
			}
			if test.want == nil {
				// Set the contents of the root. We expect a
				// normal file generator for ppp above. This is
				// overriden by setting WalkErr in the mock.
				rootFile.AddChild(file, h.NewFile())
			}

			// Call function.
			dirent, err := rootInode.Lookup(ctx, file)

			// Unwrap the InodeOperations.
			var newInodeOperations fs.InodeOperations
			if dirent != nil {
				if dirent.IsNegative() {
					err = syscall.ENOENT
				} else {
					newInodeOperations = dirent.Inode.InodeOperations
				}
			}

			// Check return values.
			if err != test.want {
				t.Errorf("Lookup got err %v, want %v", err, test.want)
			}
			if err == nil && newInodeOperations == nil {
				t.Errorf("Lookup got non-nil err and non-nil node, wanted at least one non-nil")
			}
		})
	}
}

func TestRevalidation(t *testing.T) {
	type revalidationTest struct {
		cachePolicy cachePolicy

		// Whether dirent should be reloaded before any modifications.
		preModificationWantReload bool

		// Whether dirent should be reloaded after updating an unstable
		// attribute on the remote fs.
		postModificationWantReload bool

		// Whether dirent unstable attributes should be updated after
		// updating an attribute on the remote fs.
		postModificationWantUpdatedAttrs bool

		// Whether dirent should be reloaded after the remote has
		// removed the file.
		postRemovalWantReload bool
	}

	tests := []revalidationTest{
		{
			// Policy cacheNone causes Revalidate to always return
			// true.
			cachePolicy:                      cacheNone,
			preModificationWantReload:        true,
			postModificationWantReload:       true,
			postModificationWantUpdatedAttrs: true,
			postRemovalWantReload:            true,
		},
		{
			// Policy cacheAll causes Revalidate to always return
			// false.
			cachePolicy:                      cacheAll,
			preModificationWantReload:        false,
			postModificationWantReload:       false,
			postModificationWantUpdatedAttrs: false,
			postRemovalWantReload:            false,
		},
		{
			// Policy cacheAllWritethrough causes Revalidate to
			// always return false.
			cachePolicy:                      cacheAllWritethrough,
			preModificationWantReload:        false,
			postModificationWantReload:       false,
			postModificationWantUpdatedAttrs: false,
			postRemovalWantReload:            false,
		},
		{
			// Policy cacheRemoteRevalidating causes Revalidate to
			// return update cached unstable attrs, and returns
			// true only when the remote inode itself has been
			// removed or replaced.
			cachePolicy:                      cacheRemoteRevalidating,
			preModificationWantReload:        false,
			postModificationWantReload:       false,
			postModificationWantUpdatedAttrs: true,
			postRemovalWantReload:            true,
		},
	}

	const file = "file" // The file walked below.

	for _, test := range tests {
		name := fmt.Sprintf("cachepolicy=%s", test.cachePolicy)
		rootTest(t, name, test.cachePolicy, func(ctx context.Context, h *p9test.Harness, rootFile *p9test.Mock, rootInode *fs.Inode) {
			// Wrap in a dirent object.
			rootDir := fs.NewDirent(ctx, rootInode, "root")

			// Create a mock file a child of the root. We save when
			// this is generated, so that when the time changed, we
			// can update the original entry.
			var origMocks []*p9test.Mock
			rootFile.AddChild(file, func(parent *p9test.Mock) *p9test.Mock {
				// Regular a regular file that has a consistent
				// path number. This might be used by
				// validation so we don't change it.
				m := h.NewMock(parent, 0, p9.Attr{
					Mode: p9.ModeRegular,
				})
				origMocks = append(origMocks, m)
				return m
			})

			// Do the walk.
			dirent, err := rootDir.Walk(ctx, rootDir, file)
			if err != nil {
				t.Fatalf("Lookup failed: %v", err)
			}

			// We must release the dirent, of the test will fail
			// with a reference leak. This is tracked by p9test.
			defer dirent.DecRef()

			// Walk again. Depending on the cache policy, we may
			// get a new dirent.
			newDirent, err := rootDir.Walk(ctx, rootDir, file)
			if err != nil {
				t.Fatalf("Lookup failed: %v", err)
			}
			if test.preModificationWantReload && dirent == newDirent {
				t.Errorf("Lookup with cachePolicy=%s got old dirent %+v, wanted a new dirent", test.cachePolicy, dirent)
			}
			if !test.preModificationWantReload && dirent != newDirent {
				t.Errorf("Lookup with cachePolicy=%s got new dirent %+v, wanted old dirent %+v", test.cachePolicy, newDirent, dirent)
			}
			newDirent.DecRef() // See above.

			// Modify the underlying mocked file's modification
			// time for the next walk that occurs.
			nowSeconds := time.Now().Unix()
			rootFile.AddChild(file, func(parent *p9test.Mock) *p9test.Mock {
				// Ensure that the path is the same as above,
				// but we change only the modification time of
				// the file.
				return h.NewMock(parent, 0, p9.Attr{
					Mode:         p9.ModeRegular,
					MTimeSeconds: uint64(nowSeconds),
				})
			})

			// We also modify the original time, so that GetAttr
			// behaves as expected for the caching case.
			for _, m := range origMocks {
				m.Attr.MTimeSeconds = uint64(nowSeconds)
			}

			// Walk again. Depending on the cache policy, we may
			// get a new dirent.
			newDirent, err = rootDir.Walk(ctx, rootDir, file)
			if err != nil {
				t.Fatalf("Lookup failed: %v", err)
			}
			if test.postModificationWantReload && dirent == newDirent {
				t.Errorf("Lookup with cachePolicy=%s got old dirent, wanted a new dirent", test.cachePolicy)
			}
			if !test.postModificationWantReload && dirent != newDirent {
				t.Errorf("Lookup with cachePolicy=%s got new dirent, wanted old dirent", test.cachePolicy)
			}
			uattrs, err := newDirent.Inode.UnstableAttr(ctx)
			if err != nil {
				t.Fatalf("Error getting unstable attrs: %v", err)
			}
			gotModTimeSeconds := uattrs.ModificationTime.Seconds()
			if test.postModificationWantUpdatedAttrs && gotModTimeSeconds != nowSeconds {
				t.Fatalf("Lookup with cachePolicy=%s got new modification time %v, wanted %v", test.cachePolicy, gotModTimeSeconds, nowSeconds)
			}
			newDirent.DecRef() // See above.

			// Remove the file from the remote fs, subsequent walks
			// should now fail to find anything.
			rootFile.RemoveChild(file)

			// Walk again. Depending on the cache policy, we may
			// get ENOENT.
			newDirent, err = rootDir.Walk(ctx, rootDir, file)
			if test.postRemovalWantReload && err == nil {
				t.Errorf("Lookup with cachePolicy=%s got nil error, wanted ENOENT", test.cachePolicy)
			}
			if !test.postRemovalWantReload && (err != nil || dirent != newDirent) {
				t.Errorf("Lookup with cachePolicy=%s got new dirent and error %v, wanted old dirent and nil error", test.cachePolicy, err)
			}
			if err == nil {
				newDirent.DecRef() // See above.
			}
		})
	}
}
