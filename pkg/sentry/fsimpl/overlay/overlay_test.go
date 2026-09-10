// Copyright 2026 The gVisor Authors.
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

package overlay

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// testOverlay is an overlay filesystem mounted over two tmpfs layers.
type testOverlay struct {
	ctx       context.Context
	creds     *auth.Credentials
	vfsObj    *vfs.VirtualFilesystem
	lowerRoot vfs.VirtualDentry
	root      vfs.VirtualDentry
	mntns     *vfs.MountNamespace
	cleanup   func()
}

// mntnsContext supplies the overlay's mount namespace, which RenameAt asks the
// context for. A reference is taken on each retrieval, as
// vfs.MountNamespaceFromContext promises, since the caller releases it.
type mntnsContext struct {
	context.Context
	mntns *vfs.MountNamespace
}

func (c *mntnsContext) Value(key any) any {
	if key == vfs.CtxMountNamespace {
		c.mntns.IncRef()
		return c.mntns
	}
	return c.Context.Value(key)
}

// newTestOverlay returns an overlay with an empty tmpfs upper layer and a
// single tmpfs lower layer. The caller must call cleanup when done.
func newTestOverlay(t *testing.T) *testOverlay {
	t.Helper()
	ctx := contexttest.Context(t)
	// Root credentials, rather than the context's anonymous ones: renaming a
	// merged directory makes it opaque with a trusted.* xattr on the upper
	// layer, which needs CAP_SYS_ADMIN.
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	newLayer := func() vfs.VirtualDentry {
		mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
		if err != nil {
			cleanup()
			t.Fatalf("failed to create tmpfs layer: %v", err)
		}
		root := mntns.Root(ctx)
		cleanups = append(cleanups, func() {
			root.DecRef(ctx)
			mntns.DecRef(ctx)
		})
		return root
	}
	lowerRoot := newLayer()
	upperRoot := newLayer()

	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOptions{
				UpperRoot:  upperRoot,
				LowerRoots: []vfs.VirtualDentry{lowerRoot},
			},
		},
	}, nil)
	if err != nil {
		cleanup()
		t.Fatalf("failed to create overlay mount: %v", err)
	}
	root := mntns.Root(ctx)
	cleanups = append(cleanups, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	})

	return &testOverlay{
		ctx:       ctx,
		creds:     creds,
		vfsObj:    vfsObj,
		lowerRoot: lowerRoot,
		root:      root,
		mntns:     mntns,
		cleanup:   cleanup,
	}
}

// createLowerFile creates a regular file named name in the lower layer.
func (o *testOverlay) createLowerFile(t *testing.T, name string) {
	t.Helper()
	fd, err := o.vfsObj.OpenAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  o.lowerRoot,
		Start: o.lowerRoot,
		Path:  fspath.Parse(name),
	}, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("failed to create %q in the lower layer: %v", name, err)
	}
	fd.DecRef(o.ctx)
}

// getDentry returns the overlay dentry for name, on which the caller holds a
// reference.
func (o *testOverlay) getDentry(t *testing.T, name string) vfs.VirtualDentry {
	t.Helper()
	vd, err := o.vfsObj.GetDentryAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(name),
	}, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("failed to look up %q: %v", name, err)
	}
	return vd
}

// copyUp copies name up to the upper layer by opening it for writing.
func (o *testOverlay) copyUp(t *testing.T, name string) {
	t.Helper()
	fd, err := o.vfsObj.OpenAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(name),
	}, &vfs.OpenOptions{
		Flags: linux.O_WRONLY,
	})
	if err != nil {
		t.Fatalf("failed to open %q for writing: %v", name, err)
	}
	fd.DecRef(o.ctx)
}

// createLowerDir creates a directory named name in the lower layer.
func (o *testOverlay) createLowerDir(t *testing.T, name string) {
	t.Helper()
	if err := o.vfsObj.MkdirAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  o.lowerRoot,
		Start: o.lowerRoot,
		Path:  fspath.Parse(name),
	}, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("failed to create directory %q in the lower layer: %v", name, err)
	}
}

// rename renames oldName to newName on the overlay.
func (o *testOverlay) rename(t *testing.T, oldName, newName string) {
	t.Helper()
	ctx := &mntnsContext{Context: o.ctx, mntns: o.mntns}
	if err := o.vfsObj.RenameAt(ctx, o.creds, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(oldName),
	}, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(newName),
	}, &vfs.RenameOptions{}); err != nil {
		t.Fatalf("failed to rename %q to %q: %v", oldName, newName, err)
	}
}

// TestPinnedInodeIdentitySurvivesCopyUp verifies that once a file's identity
// has been pinned, as landlock_add_rule(2) pins the identity of the file a rule
// names, a dentry instantiated for that file after it is copied up reports the
// same identity, even though it only exists on the upper layer by then.
func TestPinnedInodeIdentitySurvivesCopyUp(t *testing.T) {
	for _, test := range []struct {
		name           string
		pinAfterCopyUp bool
	}{
		{name: "PinBeforeCopyUp"},
		{name: "PinAfterCopyUp", pinAfterCopyUp: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := newTestOverlay(t)
			defer o.cleanup()
			const filename = "file"
			o.createLowerFile(t, filename)

			vd := o.getDentry(t, filename)
			d := vd.Dentry().Impl().(*dentry)
			if !d.isOnLower() {
				t.Fatalf("%q was not found on the lower layer", filename)
			}
			if test.pinAfterCopyUp {
				o.copyUp(t, filename)
				if !d.isCopiedUp() {
					t.Fatalf("%q was not copied up", filename)
				}
			}
			vd.Dentry().PinInodeIdentity()
			pinnedID := vd.Dentry().InodeIdentity()
			if !pinnedID.Ok() {
				t.Fatalf("%q has no identity", filename)
			}
			// Drop the dentry the identity was taken from, as closing the file
			// descriptor passed to landlock_add_rule(2) does.
			vd.DecRef(o.ctx)

			if !test.pinAfterCopyUp {
				o.copyUp(t, filename)
			}

			vd2 := o.getDentry(t, filename)
			defer vd2.DecRef(o.ctx)
			if d2 := vd2.Dentry().Impl().(*dentry); d2.isOnLower() {
				t.Fatalf("the dentry for %q still has its lower layers, so it was not reinstantiated after copy-up and this test proves nothing", filename)
			}
			if got := vd2.Dentry().InodeIdentity(); got != pinnedID {
				t.Errorf("identity of %q after copy-up = %+v, want %+v", filename, got, pinnedID)
			}
		})
	}
}

// TestPinnedInodeIdentitySurvivesDirectoryRename verifies that a pinned
// identity keeps naming the same file across a rename of a covered directory.
// A rename happens on the upper layer only, so a lookup at the new name finds
// nothing in the lower layer even for a directory, which is otherwise merged;
// a dentry instantiated there must still report the identity that was pinned,
// or a Landlock rule added on the directory would silently stop matching.
func TestPinnedInodeIdentitySurvivesDirectoryRename(t *testing.T) {
	const (
		dirname    = "dir"
		newDirname = "dir2"
		childname  = "dir/child"
	)
	for _, test := range []struct {
		name        string
		path        string
		renamedPath string
	}{
		// The renamed directory itself.
		{name: "Directory", path: dirname, renamedPath: newDirname},
		// A file inside it: the rename copies up the whole subtree, and lookups
		// of the file afterwards go through an upper-only parent.
		{name: "FileInDirectory", path: childname, renamedPath: newDirname + "/child"},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := newTestOverlay(t)
			defer o.cleanup()
			o.createLowerDir(t, dirname)
			o.createLowerFile(t, childname)

			vd := o.getDentry(t, test.path)
			if !vd.Dentry().Impl().(*dentry).isOnLower() {
				t.Fatalf("%q was not found on the lower layer", test.path)
			}
			vd.Dentry().PinInodeIdentity()
			pinnedID := vd.Dentry().InodeIdentity()
			if !pinnedID.Ok() {
				t.Fatalf("%q has no identity", test.path)
			}
			// Drop the dentry the identity was taken from, as closing the file
			// descriptor passed to landlock_add_rule(2) does.
			vd.DecRef(o.ctx)

			o.rename(t, dirname, newDirname)

			vd2 := o.getDentry(t, test.renamedPath)
			defer vd2.DecRef(o.ctx)
			if d2 := vd2.Dentry().Impl().(*dentry); d2.isOnLower() {
				t.Fatalf("the dentry for %q still has its lower layers, so it was not reinstantiated after the rename and this test proves nothing", test.renamedPath)
			}
			if got := vd2.Dentry().InodeIdentity(); got != pinnedID {
				t.Errorf("identity of %q after directory rename = %+v, want %+v", test.renamedPath, got, pinnedID)
			}
		})
	}
}

// pinRecordingDentry is a stub layer dentry that records PinInodeIdentity
// calls, standing in for a layer (like gofer) whose inode numbers are only
// stable while the dentry is pinned.
type pinRecordingDentry struct {
	vfsd     vfs.Dentry
	identity vfs.InodeIdentity
	pins     int
}

func (d *pinRecordingDentry) IncRef()                {}
func (d *pinRecordingDentry) TryIncRef() bool        { return true }
func (d *pinRecordingDentry) DecRef(context.Context) {}
func (d *pinRecordingDentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
}
func (d *pinRecordingDentry) Watches() *vfs.Watches            { return nil }
func (d *pinRecordingDentry) OnZeroWatches(context.Context)    {}
func (d *pinRecordingDentry) InodeIdentity() vfs.InodeIdentity { return d.identity }
func (d *pinRecordingDentry) PinInodeIdentity()                { d.pins++ }

// TestPinInodeIdentityPropagatesToLayers verifies that pinning an overlay
// dentry's identity also pins the layer dentries the identity can come from:
// layer inode numbers (gofer's in particular) are only stable across
// save/restore while the layer dentry stays alive, so the pin must reach the
// bottommost lower layer that answers InodeIdentity() and the upper layer
// that dentries instantiated after a copy-up fall back to.
func TestPinInodeIdentityPropagatesToLayers(t *testing.T) {
	o := newTestOverlay(t)
	defer o.cleanup()
	// MakeVirtualDentry takes no references, and the pin path only reads the
	// dentry, so borrowing the test mount is safe.
	mnt := o.root.Mount()

	newLayer := func(ino uint64) *pinRecordingDentry {
		l := &pinRecordingDentry{identity: vfs.MakeInodeIdentity(&vfs.Filesystem{}, ino)}
		l.vfsd.Init(l)
		return l
	}

	t.Run("LowerAndUpper", func(t *testing.T) {
		fs := filesystem{}
		lower := newLayer(1)
		upper := newLayer(2)
		d := &dentry{fs: &fs}
		d.lowerVDs = []vfs.VirtualDentry{vfs.MakeVirtualDentry(mnt, &lower.vfsd)}
		d.upperVD = vfs.MakeVirtualDentry(mnt, &upper.vfsd)
		d.vfsd.Init(d)
		d.vfsd.PinInodeIdentity()
		if lower.pins != 1 {
			t.Errorf("lower layer pinned %d times, want 1", lower.pins)
		}
		if upper.pins != 1 {
			t.Errorf("upper layer pinned %d times, want 1", upper.pins)
		}
	})

	t.Run("PureUpper", func(t *testing.T) {
		fs := filesystem{}
		upper := newLayer(3)
		d := &dentry{fs: &fs}
		d.upperVD = vfs.MakeVirtualDentry(mnt, &upper.vfsd)
		d.vfsd.Init(d)
		d.vfsd.PinInodeIdentity()
		if upper.pins != 1 {
			t.Errorf("upper layer pinned %d times, want 1", upper.pins)
		}
	})
}
