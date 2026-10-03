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

// testOverlay is an overlay filesystem mounted over tmpfs layers.
type testOverlay struct {
	ctx    context.Context
	creds  *auth.Credentials
	vfsObj *vfs.VirtualFilesystem
	// lowerRoot is the topmost lower layer, lowerRoots[0].
	lowerRoot  vfs.VirtualDentry
	lowerRoots []vfs.VirtualDentry
	upperRoot  vfs.VirtualDentry
	root       vfs.VirtualDentry
	mntns      *vfs.MountNamespace
	// cleanups tears down the mounts made so far, in reverse order of making.
	cleanups []func()
}

// cleanup tears down every mount the testOverlay made, most recent first.
func (o *testOverlay) cleanup() {
	for i := len(o.cleanups) - 1; i >= 0; i-- {
		o.cleanups[i]()
	}
}

// newLayer returns the root of a fresh, empty tmpfs, torn down at cleanup.
func (o *testOverlay) newLayer(t *testing.T) vfs.VirtualDentry {
	t.Helper()
	mntns, err := o.vfsObj.NewMountNamespace(o.ctx, o.creds, "", "tmpfs", &vfs.MountOptions{}, nil)
	if err != nil {
		o.cleanup()
		t.Fatalf("failed to create tmpfs layer: %v", err)
	}
	root := mntns.Root(o.ctx)
	o.cleanups = append(o.cleanups, func() {
		root.DecRef(o.ctx)
		mntns.DecRef(o.ctx)
	})
	return root
}

// mountOverlay mounts an overlay with the given upper layer, which may be the
// zero VirtualDentry for none, and lower layers, topmost first. On success it
// returns the overlay's root and mount namespace, torn down at cleanup.
func (o *testOverlay) mountOverlay(upper vfs.VirtualDentry, lowers []vfs.VirtualDentry) (vfs.VirtualDentry, *vfs.MountNamespace, error) {
	mntns, err := o.vfsObj.NewMountNamespace(o.ctx, o.creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOptions{
				UpperRoot:  upper,
				LowerRoots: lowers,
			},
		},
	}, nil)
	if err != nil {
		return vfs.VirtualDentry{}, nil, err
	}
	root := mntns.Root(o.ctx)
	o.cleanups = append(o.cleanups, func() {
		root.DecRef(o.ctx)
		mntns.DecRef(o.ctx)
	})
	return root, mntns, nil
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
	return newTestOverlayN(t, 1)
}

// newTestOverlayN returns an overlay with an empty tmpfs upper layer and
// numLower tmpfs lower layers, topmost first. The caller must call cleanup when
// done.
func newTestOverlayN(t *testing.T, numLower int) *testOverlay {
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

	o := &testOverlay{
		ctx:    ctx,
		creds:  creds,
		vfsObj: vfsObj,
	}
	o.lowerRoots = make([]vfs.VirtualDentry, numLower)
	for i := range o.lowerRoots {
		o.lowerRoots[i] = o.newLayer(t)
	}
	o.lowerRoot = o.lowerRoots[0]
	o.upperRoot = o.newLayer(t)

	root, mntns, err := o.mountOverlay(o.upperRoot, o.lowerRoots)
	if err != nil {
		o.cleanup()
		t.Fatalf("failed to create overlay mount: %v", err)
	}
	o.root = root
	o.mntns = mntns
	return o
}

// createFileOn creates a regular file named name under the given layer root.
func (o *testOverlay) createFileOn(t *testing.T, layerRoot vfs.VirtualDentry, name string) {
	t.Helper()
	fd, err := o.vfsObj.OpenAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  layerRoot,
		Start: layerRoot,
		Path:  fspath.Parse(name),
	}, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("failed to create %q in the layer: %v", name, err)
	}
	fd.DecRef(o.ctx)
}

// layerIno returns the inode number that name has on the given layer root.
func (o *testOverlay) layerIno(t *testing.T, layerRoot vfs.VirtualDentry, name string) uint64 {
	t.Helper()
	stat, err := o.vfsObj.StatAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  layerRoot,
		Start: layerRoot,
		Path:  fspath.Parse(name),
	}, &vfs.StatOptions{})
	if err != nil {
		t.Fatalf("failed to stat %q on the layer: %v", name, err)
	}
	return stat.Ino
}

// createDirOn creates a directory named name under the given layer root.
func (o *testOverlay) createDirOn(t *testing.T, layerRoot vfs.VirtualDentry, name string) {
	t.Helper()
	if err := o.vfsObj.MkdirAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  layerRoot,
		Start: layerRoot,
		Path:  fspath.Parse(name),
	}, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("failed to create directory %q in the layer: %v", name, err)
	}
}

// lookupOn returns the dentry for name under root, on which the caller holds a
// reference.
func (o *testOverlay) lookupOn(t *testing.T, root vfs.VirtualDentry, name string) vfs.VirtualDentry {
	t.Helper()
	vd, err := o.vfsObj.GetDentryAt(o.ctx, o.creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(name),
	}, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("failed to look up %q: %v", name, err)
	}
	return vd
}

// createLowerFile creates a regular file named name in the topmost lower layer.
func (o *testOverlay) createLowerFile(t *testing.T, name string) {
	t.Helper()
	o.createFileOn(t, o.lowerRoot, name)
}

// getDentry returns the overlay dentry for name, on which the caller holds a
// reference.
func (o *testOverlay) getDentry(t *testing.T, name string) vfs.VirtualDentry {
	t.Helper()
	return o.lookupOn(t, o.root, name)
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

// unlink unlinks name on the overlay.
func (o *testOverlay) unlink(t *testing.T, name string) {
	t.Helper()
	ctx := &mntnsContext{Context: o.ctx, mntns: o.mntns}
	if err := o.vfsObj.UnlinkAt(ctx, o.creds, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(name),
	}); err != nil {
		t.Fatalf("failed to unlink %q: %v", name, err)
	}
}

// rmdir removes the directory name on the overlay.
func (o *testOverlay) rmdir(t *testing.T, name string) {
	t.Helper()
	ctx := &mntnsContext{Context: o.ctx, mntns: o.mntns}
	if err := o.vfsObj.RmdirAt(ctx, o.creds, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(name),
	}); err != nil {
		t.Fatalf("failed to rmdir %q: %v", name, err)
	}
}

// create creates a regular file or directory named name on the overlay, which
// puts it in the upper layer. Creating over a whiteout removes the whiteout,
// which asks the context for the mount namespace as a deletion does.
func (o *testOverlay) create(t *testing.T, name string, dir bool) {
	t.Helper()
	ctx := &mntnsContext{Context: o.ctx, mntns: o.mntns}
	pop := vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(name),
	}
	if dir {
		if err := o.vfsObj.MkdirAt(ctx, o.creds, &pop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
			t.Fatalf("failed to create directory %q on the overlay: %v", name, err)
		}
		return
	}
	fd, err := o.vfsObj.OpenAt(ctx, o.creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("failed to create %q on the overlay: %v", name, err)
	}
	fd.DecRef(o.ctx)
}

// fs returns the overlay filesystem.
func (o *testOverlay) fs() *filesystem {
	return o.root.Mount().Filesystem().Impl().(*filesystem)
}

// getObject returns the Landlock object for vd's file with a new reference, as
// landlock_add_rule(2) gets it for the file a rule names.
func (o *testOverlay) getObject(t *testing.T, vd vfs.VirtualDentry) *vfs.LandlockObject {
	t.Helper()
	obj, err := vfs.GetLandlockObject(vd)
	if err != nil {
		t.Fatalf("GetLandlockObject(%v): %v", vd, err)
	}
	return obj
}

// objectOf returns the Landlock object that vd's file currently has, which is
// what a Landlock access check matches rules against.
func objectOf(vd vfs.VirtualDentry) *vfs.LandlockObject {
	return vd.Dentry().Impl().LandlockObjectSlot().Object()
}

// objectAt returns the Landlock object that the file at name under root
// currently has.
func (o *testOverlay) objectAt(t *testing.T, root vfs.VirtualDentry, name string) *vfs.LandlockObject {
	t.Helper()
	vd := o.lookupOn(t, root, name)
	defer vd.DecRef(o.ctx)
	return objectOf(vd)
}

// link creates a hard link newName to oldName on the overlay.
func (o *testOverlay) link(t *testing.T, oldName, newName string) {
	t.Helper()
	ctx := auth.ContextWithCredentials(o.ctx, o.creds)
	if err := o.vfsObj.LinkAt(ctx, o.creds, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(oldName),
	}, &vfs.PathOperation{
		Root:  o.root,
		Start: o.root,
		Path:  fspath.Parse(newName),
	}); err != nil {
		t.Fatalf("failed to link %q to %q: %v", newName, oldName, err)
	}
}

// checkReleased verifies that releasing obj, the last reference on it, drops
// its reference on d, the dentry it was created for, and removes its slot from
// the overlay's table.
func (o *testOverlay) checkReleased(t *testing.T, obj *vfs.LandlockObject, d *dentry) {
	t.Helper()
	obj.DecRef(o.ctx)
	if got := d.refs.Load(); got != -1 {
		t.Errorf("dentry has %d references once its Landlock object is released, want it destroyed", got)
	}
	fs := o.fs()
	if m := fs.landlockSlots.Load(); m != nil {
		t.Errorf("overlay has %d Landlock slots once its only object is released, want 0", len(*m))
	}
}

// TestLandlockObjectSurvivesCopyUp verifies that a file keeps its Landlock
// object across copy-up, whether the Landlock object is created before or
// after the copy-up, including once the dentry it was created for is gone. The
// Landlock object holds a reference on that dentry, so a lookup of the file
// after the copy-up returns it rather than instantiating one that sees only
// the upper layer.
func TestLandlockObjectSurvivesCopyUp(t *testing.T) {
	for _, test := range []struct {
		name              string
		objectAfterCopyUp bool
	}{
		{name: "ObjectBeforeCopyUp"},
		{name: "ObjectAfterCopyUp", objectAfterCopyUp: true},
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
			if test.objectAfterCopyUp {
				o.copyUp(t, filename)
				if !d.isCopiedUp() {
					t.Fatalf("%q was not copied up", filename)
				}
			}
			obj := o.getObject(t, vd)
			// Drop the dentry the Landlock object was created for, as closing
			// the file descriptor passed to landlock_add_rule(2) does.
			vd.DecRef(o.ctx)
			if got := d.refs.Load(); got != 1 {
				t.Errorf("%q has %d references after the caller dropped its own, want the object's 1", filename, got)
			}

			if !test.objectAfterCopyUp {
				o.copyUp(t, filename)
			}

			vd2 := o.getDentry(t, filename)
			d2 := vd2.Dentry().Impl().(*dentry)
			if d2 != d {
				t.Errorf("lookup of %q after copy-up returned a new dentry, so the object did not keep the original alive", filename)
			}
			if !d2.isCopiedUp() {
				t.Errorf("%q was not copied up", filename)
			}
			if got := objectOf(vd2); got != obj {
				t.Errorf("object of %q after copy-up = %p, want %p", filename, got, obj)
			}
			vd2.DecRef(o.ctx)

			o.checkReleased(t, obj, d)
			if got := o.objectAt(t, o.root, filename); got != nil {
				t.Errorf("%q has object %p once its object is released, want none", filename, got)
			}
		})
	}
}

// TestLandlockObjectSurvivesRename verifies that a file keeps its Landlock
// object across a rename of the file or of a directory covering it. Renaming a
// lower-layer file copies it up and moves the copy on the upper layer, and
// renaming a directory happens on the upper layer only; the Landlock object
// keeps the original dentry alive, and the rename re-parents it.
func TestLandlockObjectSurvivesRename(t *testing.T) {
	const (
		filename   = "a.txt"
		dirname    = "dir"
		childname  = "dir/child"
		newDirname = "dir2"
	)
	for _, test := range []struct {
		name        string
		path        string
		oldName     string
		newName     string
		renamedPath string
	}{
		{name: "File", path: filename, oldName: filename, newName: "b.txt", renamedPath: "b.txt"},
		{name: "Directory", path: dirname, oldName: dirname, newName: newDirname, renamedPath: newDirname},
		// A file inside the renamed directory: the rename copies up the whole
		// subtree, and lookups of the file afterwards go through the
		// re-parented directory.
		{name: "FileInDirectory", path: childname, oldName: dirname, newName: newDirname, renamedPath: newDirname + "/child"},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := newTestOverlay(t)
			defer o.cleanup()
			o.createLowerFile(t, filename)
			o.createLowerDir(t, dirname)
			o.createLowerFile(t, childname)

			vd := o.getDentry(t, test.path)
			d := vd.Dentry().Impl().(*dentry)
			obj := o.getObject(t, vd)
			vd.DecRef(o.ctx)

			o.rename(t, test.oldName, test.newName)

			vd2 := o.getDentry(t, test.renamedPath)
			defer vd2.DecRef(o.ctx)
			if d2 := vd2.Dentry().Impl().(*dentry); d2 != d {
				t.Errorf("lookup of %q after the rename returned a new dentry, so the object did not keep the original alive", test.renamedPath)
			}
			if got := objectOf(vd2); got != obj {
				t.Errorf("object of %q after rename = %p, want %p", test.renamedPath, got, obj)
			}
		})
	}
}

// TestLandlockObjectSharedByHardLinks verifies that a hard link to a file has
// the file's Landlock object, as a hard link shares the overlay inode in Linux,
// whether the file was on the lower layer, and is copied up by the link, or on
// the upper layer, and whether the Landlock object was created before or after
// the link. It also verifies that the link keeps the Landlock object across
// lookups, after its own dentry is dropped.
func TestLandlockObjectSharedByHardLinks(t *testing.T) {
	const (
		a = "a"
		b = "b"
	)
	for _, test := range []struct {
		name            string
		upperSource     bool
		objectAfterLink bool
	}{
		{name: "LowerSource"},
		{name: "LowerSourceObjectAfterLink", objectAfterLink: true},
		{name: "UpperSource", upperSource: true},
		{name: "UpperSourceObjectAfterLink", upperSource: true, objectAfterLink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := newTestOverlay(t)
			defer o.cleanup()
			if test.upperSource {
				o.create(t, a, false)
			} else {
				o.createLowerFile(t, a)
			}

			var obj *vfs.LandlockObject
			getObj := func() {
				vd := o.getDentry(t, a)
				obj = o.getObject(t, vd)
				vd.DecRef(o.ctx)
			}
			if !test.objectAfterLink {
				getObj()
			}
			o.link(t, a, b)
			if test.objectAfterLink {
				getObj()
			}

			if got := o.objectAt(t, o.root, b); got != obj {
				t.Errorf("object of hard link %q = %p, want %q's %p", b, got, a, obj)
			}
			// The lookup above dropped the only reference on b's dentry, so
			// this one instantiates a new dentry for b.
			if got := o.objectAt(t, o.root, b); got != obj {
				t.Errorf("object of hard link %q on a later lookup = %p, want %q's %p", b, got, a, obj)
			}
			if got := o.objectAt(t, o.root, a); got != obj {
				t.Errorf("object of %q after the link = %p, want %p", a, got, obj)
			}
		})
	}
}

// TestLandlockObjectOutlivesDeletion verifies that deleting a file leaves its
// Landlock object, and the dentry it holds, alone, as Linux leaves the
// Landlock object of an unlinked inode until the last rule referring to it
// goes away, and that the file found at the same name afterwards does not have
// the Landlock object.
func TestLandlockObjectOutlivesDeletion(t *testing.T) {
	const (
		name  = "victim"
		other = "other"
	)
	for _, test := range []struct {
		name   string
		dir    bool
		remove func(t *testing.T, o *testOverlay)
		// replaced is whether remove leaves another file at name, so that none
		// needs to be created to look one up there.
		replaced bool
	}{
		{name: "Unlink", remove: func(t *testing.T, o *testOverlay) { o.unlink(t, name) }},
		{name: "Rmdir", dir: true, remove: func(t *testing.T, o *testOverlay) { o.rmdir(t, name) }},
		{name: "RenameOver", remove: func(t *testing.T, o *testOverlay) { o.rename(t, other, name) }, replaced: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := newTestOverlay(t)
			defer o.cleanup()
			if test.dir {
				o.createLowerDir(t, name)
			} else {
				o.createLowerFile(t, name)
				o.createLowerFile(t, other)
			}

			vd := o.getDentry(t, name)
			d := vd.Dentry().Impl().(*dentry)
			obj := o.getObject(t, vd)
			vd.DecRef(o.ctx)

			test.remove(t, o)

			if got := d.refs.Load(); got != 1 {
				t.Errorf("the dentry for %q has %d references after its deletion, want the object's 1", name, got)
			}
			if !test.replaced {
				o.create(t, name, test.dir)
			}
			if got := o.objectAt(t, o.root, name); got != nil {
				t.Errorf("the file at %q after the deletion has object %p, want none", name, got)
			}

			o.checkReleased(t, obj, d)
		})
	}
}

// TestLandlockObjectDistinctFromLayers verifies that an overlay file's Landlock
// object is neither its lower layer file's nor, once copied up, its upper layer
// file's. On Linux the overlay inode is distinct from both layer inodes, so a
// Landlock rule on a layer file never covers the merged file or the reverse,
// which the selftest layout2_overlay.same_content_different_file checks.
func TestLandlockObjectDistinctFromLayers(t *testing.T) {
	o := newTestOverlay(t)
	defer o.cleanup()
	const filename = "file"
	o.createLowerFile(t, filename)

	lowerVD := o.lookupOn(t, o.lowerRoot, filename)
	lowerObj := o.getObject(t, lowerVD)
	lowerVD.DecRef(o.ctx)
	if got := o.objectAt(t, o.root, filename); got != nil {
		t.Errorf("overlay %q has its lower layer file's object %p", filename, got)
	}
	vd := o.getDentry(t, filename)
	obj := o.getObject(t, vd)
	vd.DecRef(o.ctx)
	if obj == lowerObj {
		t.Errorf("overlay object of %q equals its lower layer file's object %p", filename, obj)
	}
	if got := o.objectAt(t, o.lowerRoot, filename); got != lowerObj {
		t.Errorf("lower %q has object %p once the overlay file has one, want %p", filename, got, lowerObj)
	}

	o.copyUp(t, filename)
	if got := o.objectAt(t, o.upperRoot, filename); got != nil {
		t.Errorf("upper %q has object %p, want none", filename, got)
	}
	if got := o.objectAt(t, o.root, filename); got != obj {
		t.Errorf("object of %q changed across copy-up: %p then %p", filename, obj, got)
	}
}

// TestLandlockObjectDistinctAcrossLayers verifies that files drawn from
// different layers have distinct Landlock objects even when their inode numbers
// on their layers coincide, as they do for two fresh tmpfs layers, which number
// their files from the same starting point.
func TestLandlockObjectDistinctAcrossLayers(t *testing.T) {
	o := newTestOverlayN(t, 2)
	defer o.cleanup()
	const (
		topName    = "top"
		bottomName = "bottom"
	)
	o.createFileOn(t, o.lowerRoots[0], topName)
	o.createFileOn(t, o.lowerRoots[1], bottomName)
	if topIno, bottomIno := o.layerIno(t, o.lowerRoots[0], topName), o.layerIno(t, o.lowerRoots[1], bottomName); topIno != bottomIno {
		t.Fatalf("layer inode numbers of %q and %q differ (%d and %d), so this test proves nothing", topName, bottomName, topIno, bottomIno)
	}

	topVD := o.getDentry(t, topName)
	defer topVD.DecRef(o.ctx)
	topObj := o.getObject(t, topVD)
	bottomVD := o.getDentry(t, bottomName)
	defer bottomVD.DecRef(o.ctx)
	if got := objectOf(bottomVD); got != nil {
		t.Errorf("%q, on a different layer with an equal inode number, has %q's object %p", bottomName, topName, got)
	}
	if bottomObj := o.getObject(t, bottomVD); bottomObj == topObj {
		t.Errorf("%q and %q, on different layers with equal inode numbers, share the object %p", topName, bottomName, topObj)
	}
}

// TestLandlockObjectDistinctThroughNestedLayers verifies that a file reached
// through two lower layers that are both built on one filesystem, two overlays
// over it, is two distinct files to the overlay on top, as it is on Linux,
// where the two have distinct overlay inodes and may differ in content once
// one of the intermediate overlays copies the file up. tmpfs A holds x/f;
// overlays O1 and O1b are each mounted over A; O2 is mounted over [O1/x, O1b],
// so O2/f reaches A/x/f through O1 and O2/x/f reaches it through O1b. The
// Landlock objects must also stay distinct from the intermediate overlays' own
// and the base file's, and survive the overlay dentries being dropped.
func TestLandlockObjectDistinctThroughNestedLayers(t *testing.T) {
	o := newTestOverlay(t)
	defer o.cleanup()

	base := o.newLayer(t)
	o.createDirOn(t, base, "x")
	o.createFileOn(t, base, "x/f")
	o1, _, err := o.mountOverlay(o.newLayer(t), []vfs.VirtualDentry{base})
	if err != nil {
		t.Fatalf("failed to mount the first overlay over the base: %v", err)
	}
	o1b, _, err := o.mountOverlay(o.newLayer(t), []vfs.VirtualDentry{base})
	if err != nil {
		t.Fatalf("failed to mount the second overlay over the base: %v", err)
	}
	o1x := o.lookupOn(t, o1, "x")
	defer o1x.DecRef(o.ctx)
	o2, _, err := o.mountOverlay(o.newLayer(t), []vfs.VirtualDentry{o1x, o1b})
	if err != nil {
		t.Fatalf("failed to mount an overlay over the two overlays: %v", err)
	}

	objects := make(map[*vfs.LandlockObject]string)
	for _, file := range []struct {
		root vfs.VirtualDentry
		name string
		desc string
	}{
		{o2, "f", "O2/f"},
		{o2, "x/f", "O2/x/f"},
		{o1, "x/f", "O1/x/f"},
		{base, "x/f", "A/x/f"},
	} {
		vd := o.lookupOn(t, file.root, file.name)
		obj := o.getObject(t, vd)
		vd.DecRef(o.ctx)
		if prev, ok := objects[obj]; ok {
			t.Errorf("%s and %s share the object %p", prev, file.desc, obj)
		}
		objects[obj] = file.desc
		if got := o.objectAt(t, file.root, file.name); got != obj {
			t.Errorf("object of %s on a later lookup = %p, want %p", file.desc, got, obj)
		}
	}
}
