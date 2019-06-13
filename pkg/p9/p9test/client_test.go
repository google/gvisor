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

package p9test

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/p9"
)

func TestPanic(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	// Create a new root.
	d := h.NewDirectory(nil)(nil)
	defer d.Close() // Needed manually.
	h.Attacher.EXPECT().Attach().Return(d, nil).Do(func() {
		// Panic here, and ensure that we get back EFAULT.
		panic("handler")
	})

	// Attach to the client.
	if _, err := c.Attach("/"); err != syscall.EFAULT {
		t.Fatalf("got attach err %v, want EFAULT", err)
	}
}

func TestAttachNoLeak(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	// Create a new root.
	d := h.NewDirectory(nil)(nil)
	h.Attacher.EXPECT().Attach().Return(d, nil).Times(1)

	// Attach to the client.
	f, err := c.Attach("/")
	if err != nil {
		t.Fatalf("got attach err %v, want nil", err)
	}

	// Don't close the file. This should be closed automatically when the
	// client disconnects. The mock asserts that everything is closed
	// exactly once. This statement just removes the unused variable error.
	_ = f
}

func TestBadAttach(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	// Return an error on attach.
	h.Attacher.EXPECT().Attach().Return(nil, syscall.EINVAL).Times(1)

	// Attach to the client.
	if _, err := c.Attach("/"); err != syscall.EINVAL {
		t.Fatalf("got attach err %v, want syscall.EINVAL", err)
	}
}

func TestWalkAttach(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	// Create a new root.
	d := h.NewDirectory(map[string]Generator{
		"a": h.NewDirectory(map[string]Generator{
			"b": h.NewFile(),
		}),
	})(nil)
	h.Attacher.EXPECT().Attach().Return(d, nil).Times(1)

	// Attach to the client as a non-root, and ensure that the walk above
	// occurs as expected. We should get back b, and all references should
	// be dropped when the file is closed.
	f, err := c.Attach("/a/b")
	if err != nil {
		t.Fatalf("got attach err %v, want nil", err)
	}
	defer f.Close()

	// Check that's a regular file.
	if _, _, attr, err := f.GetAttr(p9.AttrMaskAll()); err != nil {
		t.Errorf("got err %v, want nil", err)
	} else if !attr.Mode.IsRegular() {
		t.Errorf("got mode %v, want regular file", err)
	}
}

// newTypeMap returns a new type map dictionary.
func newTypeMap(h *Harness) map[string]Generator {
	return map[string]Generator{
		"directory":        h.NewDirectory(map[string]Generator{}),
		"file":             h.NewFile(),
		"symlink":          h.NewSymlink(),
		"block-device":     h.NewBlockDevice(),
		"character-device": h.NewCharacterDevice(),
		"named-pipe":       h.NewNamedPipe(),
		"socket":           h.NewSocket(),
	}
}

// newRoot returns a new root filesystem.
//
// This is set up in a deterministic way for testing most operations.
//
// The represented file system looks like:
// - file
// - symlink
// - directory
// ...
// + one
//   - file
//   - symlink
//   - directory
//   ...
//   + two
//     - file
//     - symlink
//     - directory
//     ...
// + three
//   - file
//   - symlink
//   - directory
//   ...
func newRoot(h *Harness, c *p9.Client) (*Mock, p9.File) {
	root := newTypeMap(h)
	one := newTypeMap(h)
	two := newTypeMap(h)
	three := newTypeMap(h)
	one["two"] = h.NewDirectory(two)      // Will be nested in one.
	root["one"] = h.NewDirectory(one)     // Top level.
	root["three"] = h.NewDirectory(three) // Alternate top-level.

	// Create a new root.
	rootBackend := h.NewDirectory(root)(nil)
	h.Attacher.EXPECT().Attach().Return(rootBackend, nil)

	// Attach to the client.
	r, err := c.Attach("/")
	if err != nil {
		h.t.Fatalf("got attach err %v, want nil", err)
	}

	return rootBackend, r
}

func allInvalidNames(from string) []string {
	return []string{
		from + "/other",
		from + "/..",
		from + "/.",
		from + "/",
		"other/" + from,
		"/" + from,
		"./" + from,
		"../" + from,
		".",
		"..",
		"/",
		"",
	}
}

func TestWalkInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	// Run relevant tests.
	for name := range newTypeMap(h) {
		// These are all the various ways that one might attempt to
		// construct compound paths. They should all be rejected, as
		// any compound that contains a / is not allowed, as well as
		// the singular paths of '.' and '..'.
		if _, _, err := root.Walk([]string{".", name}); err != syscall.EINVAL {
			t.Errorf("Walk through . %s wanted EINVAL, got %v", name, err)
		}
		if _, _, err := root.Walk([]string{"..", name}); err != syscall.EINVAL {
			t.Errorf("Walk through . %s wanted EINVAL, got %v", name, err)
		}
		if _, _, err := root.Walk([]string{name, "."}); err != syscall.EINVAL {
			t.Errorf("Walk through %s . wanted EINVAL, got %v", name, err)
		}
		if _, _, err := root.Walk([]string{name, ".."}); err != syscall.EINVAL {
			t.Errorf("Walk through %s .. wanted EINVAL, got %v", name, err)
		}
		for _, invalidName := range allInvalidNames(name) {
			if _, _, err := root.Walk([]string{invalidName}); err != syscall.EINVAL {
				t.Errorf("Walk through %s wanted EINVAL, got %v", invalidName, err)
			}
		}
		wantErr := syscall.EINVAL
		if name == "directory" {
			// We can attempt a walk through a directory. However,
			// we should never see a file named "other", so we
			// expect this to return ENOENT.
			wantErr = syscall.ENOENT
		}
		if _, _, err := root.Walk([]string{name, "other"}); err != wantErr {
			t.Errorf("Walk through %s/other wanted %v, got %v", name, wantErr, err)
		}

		// Do a successful walk.
		_, f, err := root.Walk([]string{name})
		if err != nil {
			t.Errorf("Walk to %s wanted nil, got %v", name, err)
		}
		defer f.Close()
		local := h.Pop(f)

		// Check that the file matches.
		_, localMask, localAttr, localErr := local.GetAttr(p9.AttrMaskAll())
		if _, mask, attr, err := f.GetAttr(p9.AttrMaskAll()); mask != localMask || attr != localAttr || err != localErr {
			t.Errorf("GetAttr got (%v, %v, %v), wanted (%v, %v, %v)",
				mask, attr, err, localMask, localAttr, localErr)
		}

		// Ensure we can't walk backwards.
		if _, _, err := f.Walk([]string{"."}); err != syscall.EINVAL {
			t.Errorf("Walk through %s/. wanted EINVAL, got %v", name, err)
		}
		if _, _, err := f.Walk([]string{".."}); err != syscall.EINVAL {
			t.Errorf("Walk through %s/.. wanted EINVAL, got %v", name, err)
		}
	}
}

// fileGenerator is a function to generate files via walk or create.
//
// Examples are:
//	- walkHelper
//	- walkAndOpenHelper
//	- createHelper
type fileGenerator func(*Harness, string, p9.File) (*Mock, *Mock, p9.File)

// walkHelper walks to the given file.
//
// The backends of the parent and walked file are returned, as well as the
// walked client file.
func walkHelper(h *Harness, name string, dir p9.File) (parentBackend *Mock, walkedBackend *Mock, walked p9.File) {
	_, parent, err := dir.Walk(nil)
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer parent.Close()
	parentBackend = h.Pop(parent)

	_, walked, err = parent.Walk([]string{name})
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	walkedBackend = h.Pop(walked)

	return parentBackend, walkedBackend, walked
}

// walkAndOpenHelper additionally opens the walked file, if possible.
func walkAndOpenHelper(h *Harness, name string, dir p9.File) (*Mock, *Mock, p9.File) {
	parentBackend, walkedBackend, walked := walkHelper(h, name, dir)
	if p9.CanOpen(walkedBackend.Attr.Mode) {
		// Open for all file types that we can. We stick to a read-only
		// open here because directories may not be opened otherwise.
		walkedBackend.EXPECT().Open(p9.ReadOnly).Times(1)
		if _, _, _, err := walked.Open(p9.ReadOnly); err != nil {
			h.t.Errorf("got open err %v, want nil", err)
		}
	} else {
		// ... or assert an error for others.
		if _, _, _, err := walked.Open(p9.ReadOnly); err != syscall.EINVAL {
			h.t.Errorf("got open err %v, want EINVAL", err)
		}
	}
	return parentBackend, walkedBackend, walked
}

// createHelper creates the given file and returns the parent directory,
// created file and client file, which must be closed when done.
func createHelper(h *Harness, name string, dir p9.File) (*Mock, *Mock, p9.File) {
	// Clone the directory first, since Create replaces the existing file.
	// We change the type after calling create.
	_, dirThenFile, err := dir.Walk(nil)
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}

	// Create a new server-side file. On the server-side, the a new file is
	// returned from a create call. The client will reuse the same file,
	// but we still expect the normal chain of closes. This complicates
	// things a bit because the "parent" will always chain to the cloned
	// dir above.
	dirBackend := h.Pop(dirThenFile)   // New backend directory.
	newFile := h.NewFile()(dirBackend) // New file with backend parent.
	dirBackend.EXPECT().Create(name, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, newFile, newFile.QID, uint32(0), nil)

	// Create via the client.
	_, dirThenFile, _, _, err = dirThenFile.Create(name, p9.ReadOnly, 0, 0, 0)
	if err != nil {
		h.t.Fatalf("got create err %v, want nil", err)
	}

	// Ensure subsequent walks succeed.
	dirBackend.AddChild(name, h.NewFile())
	return dirBackend, newFile, dirThenFile
}

// deprecatedRemover allows us to access the deprecated Remove operation within
// the p9.File client object.
type deprecatedRemover interface {
	Remove() error
}

// checkDeleted asserts that relevant methods fail for an unlinked file.
//
// This function will close the file at the end.
func checkDeleted(h *Harness, file p9.File) {
	defer file.Close() // See doc.

	if _, _, _, err := file.Open(p9.ReadOnly); err != syscall.EINVAL {
		h.t.Errorf("open while deleted, got %v, want EINVAL", err)
	}
	if _, _, _, _, err := file.Create("created", p9.ReadOnly, 0, 0, 0); err != syscall.EINVAL {
		h.t.Errorf("create while deleted, got %v, want EINVAL", err)
	}
	if _, err := file.Symlink("old", "new", 0, 0); err != syscall.EINVAL {
		h.t.Errorf("symlink while deleted, got %v, want EINVAL", err)
	}
	// N.B. This link is technically invalid, but if a call to link is
	// actually made in the backend then the mock will panic.
	if err := file.Link(file, "new"); err != syscall.EINVAL {
		h.t.Errorf("link while deleted, got %v, want EINVAL", err)
	}
	if err := file.RenameAt("src", file, "dst"); err != syscall.EINVAL {
		h.t.Errorf("renameAt while deleted, got %v, want EINVAL", err)
	}
	if err := file.UnlinkAt("file", 0); err != syscall.EINVAL {
		h.t.Errorf("unlinkAt while deleted, got %v, want EINVAL", err)
	}
	if err := file.Rename(file, "dst"); err != syscall.EINVAL {
		h.t.Errorf("rename while deleted, got %v, want EINVAL", err)
	}
	if _, err := file.Readlink(); err != syscall.EINVAL {
		h.t.Errorf("readlink while deleted, got %v, want EINVAL", err)
	}
	if _, err := file.Mkdir("dir", p9.ModeDirectory, 0, 0); err != syscall.EINVAL {
		h.t.Errorf("mkdir while deleted, got %v, want EINVAL", err)
	}
	if _, err := file.Mknod("dir", p9.ModeDirectory, 0, 0, 0, 0); err != syscall.EINVAL {
		h.t.Errorf("mknod while deleted, got %v, want EINVAL", err)
	}
	if _, err := file.Readdir(0, 1); err != syscall.EINVAL {
		h.t.Errorf("readdir while deleted, got %v, want EINVAL", err)
	}
	if _, err := file.Connect(p9.ConnectFlags(0)); err != syscall.EINVAL {
		h.t.Errorf("connect while deleted, got %v, want EINVAL", err)
	}

	// The remove method is technically deprecated, but we want to ensure
	// that it still checks for deleted appropriately. We must first clone
	// the file because remove is equivalent to close.
	_, newFile, err := file.Walk(nil)
	if err == syscall.EBUSY {
		// We can't walk from here because this reference is open
		// aleady. Okay, we will also have unopened cases through
		// TestUnlink, just skip the remove operation for now.
		return
	} else if err != nil {
		h.t.Fatalf("clone failed, got %v, want nil", err)
	}
	if err := newFile.(deprecatedRemover).Remove(); err != syscall.EINVAL {
		h.t.Errorf("remove while deleted, got %v, want EINVAL", err)
	}
}

// deleter is a function to remove a file.
type deleter func(parent p9.File, name string) error

// unlinkAt is a deleter.
func unlinkAt(parent p9.File, name string) error {
	// Call unlink. Note that a filesystem may normally impose additional
	// constaints on unlinkat success, such as ensuring that a directory is
	// empty, requiring AT_REMOVEDIR in flags to remove a directory, etc.
	// None of that is required internally (entire trees can be marked
	// deleted when this operation succeeds), so the mock will succeed.
	return parent.UnlinkAt(name, 0)
}

// remove is a deleter.
func remove(parent p9.File, name string) error {
	// See notes above re: remove.
	_, newFile, err := parent.Walk([]string{name})
	if err != nil {
		// Should not be expected.
		return err
	}

	// Do the actual remove.
	if err := newFile.(deprecatedRemover).Remove(); err != nil {
		return err
	}

	// Ensure that the remove closed the file.
	if err := newFile.(deprecatedRemover).Remove(); err != syscall.EBADF {
		return syscall.EBADF // Propagate this code.
	}

	return nil
}

// unlinkHelper unlinks the noted path, and ensures that all relevant
// operations on that path, acquired from multiple paths, start failing.
func unlinkHelper(h *Harness, root p9.File, targetNames []string, targetGen fileGenerator, deleteFn deleter) {
	// name is the file to be unlinked.
	name := targetNames[len(targetNames)-1]

	// Walk to the directory containing the target.
	_, parent, err := root.Walk(targetNames[:len(targetNames)-1])
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer parent.Close()
	parentBackend := h.Pop(parent)

	// Walk to or generate the target file.
	_, _, target := targetGen(h, name, parent)
	defer checkDeleted(h, target)

	// Walk to a second reference.
	_, second, err := parent.Walk([]string{name})
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer checkDeleted(h, second)

	// Walk to a third reference, from the start.
	_, third, err := root.Walk(targetNames)
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer checkDeleted(h, third)

	// This will be translated in the backend to an unlinkat.
	parentBackend.EXPECT().UnlinkAt(name, uint32(0)).Return(nil)

	// Actually perform the deletion.
	if err := deleteFn(parent, name); err != nil {
		h.t.Fatalf("got delete err %v, want nil", err)
	}
}

func unlinkTest(t *testing.T, targetNames []string, targetGen fileGenerator) {
	t.Run(fmt.Sprintf("unlinkAt(%s)", strings.Join(targetNames, "/")), func(t *testing.T) {
		h, c := NewHarness(t)
		defer h.Finish()

		_, root := newRoot(h, c)
		defer root.Close()

		unlinkHelper(h, root, targetNames, targetGen, unlinkAt)
	})
	t.Run(fmt.Sprintf("remove(%s)", strings.Join(targetNames, "/")), func(t *testing.T) {
		h, c := NewHarness(t)
		defer h.Finish()

		_, root := newRoot(h, c)
		defer root.Close()

		unlinkHelper(h, root, targetNames, targetGen, remove)
	})
}

func TestUnlink(t *testing.T) {
	// Unlink all files.
	for name := range newTypeMap(nil) {
		unlinkTest(t, []string{name}, walkHelper)
		unlinkTest(t, []string{name}, walkAndOpenHelper)
		unlinkTest(t, []string{"one", name}, walkHelper)
		unlinkTest(t, []string{"one", name}, walkAndOpenHelper)
		unlinkTest(t, []string{"one", "two", name}, walkHelper)
		unlinkTest(t, []string{"one", "two", name}, walkAndOpenHelper)
	}

	// Unlink a directory.
	unlinkTest(t, []string{"one"}, walkHelper)
	unlinkTest(t, []string{"one"}, walkAndOpenHelper)
	unlinkTest(t, []string{"one", "two"}, walkHelper)
	unlinkTest(t, []string{"one", "two"}, walkAndOpenHelper)

	// Unlink created files.
	unlinkTest(t, []string{"created"}, createHelper)
	unlinkTest(t, []string{"one", "created"}, createHelper)
	unlinkTest(t, []string{"one", "two", "created"}, createHelper)
}

func TestUnlinkAtInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			if err := root.UnlinkAt(invalidName, 0); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

// expectRenamed asserts an ordered sequence of rename calls, based on all the
// elements in elements being the source, and the first element therein
// changing to dstName, parented at dstParent.
func expectRenamed(file *Mock, elements []string, dstParent *Mock, dstName string) *gomock.Call {
	if len(elements) > 0 {
		// Recurse to the parent, if necessary.
		call := expectRenamed(file.parent, elements[:len(elements)-1], dstParent, dstName)

		// Recursive case: this element is unchanged, but should have
		// it's hook called after the parent.
		return file.EXPECT().Renamed(file.parent, elements[len(elements)-1]).Do(func(p p9.File, _ string) {
			file.parent = p.(*Mock)
		}).After(call)
	}

	// Base case: this is the changed element.
	return file.EXPECT().Renamed(dstParent, dstName).Do(func(p p9.File, name string) {
		file.parent = p.(*Mock)
	})
}

// renamer is a rename function.
type renamer func(h *Harness, srcParent, dstParent p9.File, origName, newName string, selfRename bool) error

// renameAt is a renamer.
func renameAt(_ *Harness, srcParent, dstParent p9.File, srcName, dstName string, selfRename bool) error {
	return srcParent.RenameAt(srcName, dstParent, dstName)
}

// rename is a renamer.
func rename(h *Harness, srcParent, dstParent p9.File, srcName, dstName string, selfRename bool) error {
	_, f, err := srcParent.Walk([]string{srcName})
	if err != nil {
		return err
	}
	defer f.Close()
	if !selfRename {
		backend := h.Pop(f)
		backend.EXPECT().Renamed(gomock.Any(), dstName).Do(func(p p9.File, name string) {
			backend.parent = p.(*Mock) // Required for close ordering.
		})
	}
	return f.Rename(dstParent, dstName)
}

// renameHelper executes a rename, and asserts that all relevant elements
// receive expected notifications. If overwriting a file, this includes
// ensuring that the target has been appropriately marked as unlinked.
func renameHelper(h *Harness, root p9.File, srcNames []string, dstNames []string, target fileGenerator, renameFn renamer) {
	// Walk to the directory containing the target.
	srcQID, targetParent, err := root.Walk(srcNames[:len(srcNames)-1])
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer targetParent.Close()
	targetParentBackend := h.Pop(targetParent)

	// Walk to or generate the target file.
	_, targetBackend, src := target(h, srcNames[len(srcNames)-1], targetParent)
	defer src.Close()

	// Walk to a second reference.
	_, second, err := targetParent.Walk([]string{srcNames[len(srcNames)-1]})
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer second.Close()
	secondBackend := h.Pop(second)

	// Walk to a third reference, from the start.
	_, third, err := root.Walk(srcNames)
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer third.Close()
	thirdBackend := h.Pop(third)

	// Find the common suffix to identify the rename parent.
	var (
		renameDestPath []string
		renameSrcPath  []string
		selfRename     bool
	)
	for i := 1; i <= len(srcNames) && i <= len(dstNames); i++ {
		if srcNames[len(srcNames)-i] != dstNames[len(dstNames)-i] {
			// Take the full prefix of dstNames up until this
			// point, including the first mismatched name. The
			// first mismatch must be the renamed entry.
			renameDestPath = dstNames[:len(dstNames)-i+1]
			renameSrcPath = srcNames[:len(srcNames)-i+1]

			// Does the renameDestPath fully contain the
			// renameSrcPath here? If yes, then this is a mismatch.
			// We can't rename the src to some subpath of itself.
			if len(renameDestPath) > len(renameSrcPath) &&
				reflect.DeepEqual(renameDestPath[:len(renameSrcPath)], renameSrcPath) {
				renameDestPath = nil
				renameSrcPath = nil
				continue
			}
			break
		}
	}
	if len(renameSrcPath) == 0 || len(renameDestPath) == 0 {
		// This must be a rename to self, or a tricky look-alike. This
		// happens iff we fail to find a suitable divergence in the two
		// paths. It's a true self move if the path length is the same.
		renameDestPath = dstNames
		renameSrcPath = srcNames
		selfRename = len(srcNames) == len(dstNames)
	}

	// Walk to the source parent.
	_, srcParent, err := root.Walk(renameSrcPath[:len(renameSrcPath)-1])
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer srcParent.Close()
	srcParentBackend := h.Pop(srcParent)

	// Walk to the destination parent.
	_, dstParent, err := root.Walk(renameDestPath[:len(renameDestPath)-1])
	if err != nil {
		h.t.Fatalf("got walk err %v, want nil", err)
	}
	defer dstParent.Close()
	dstParentBackend := h.Pop(dstParent)

	// expectedErr is the result of the rename operation.
	var expectedErr error

	// Walk to the target file, if one exists.
	dstQID, dst, err := root.Walk(renameDestPath)
	if err == nil {
		if !selfRename && srcQID[0].Type == dstQID[0].Type {
			// If there is a destination file, and is it of the
			// same type as the source file, then we expect the
			// rename to succeed. We expect the destination file to
			// be deleted, so we run a deletion test on it in this
			// case.
			defer checkDeleted(h, dst)
		} else {
			if !selfRename {
				// If the type is different than the
				// destination, then we expect the rename to
				// fail. We expect ensure that this is
				// returned.
				expectedErr = syscall.EINVAL
			} else {
				// This is the file being renamed to itself.
				// This is technically allowed and a no-op, but
				// all the triggers will fire.
			}
			dst.Close()
		}
	}
	dstName := renameDestPath[len(renameDestPath)-1] // Renamed element.
	srcName := renameSrcPath[len(renameSrcPath)-1]   // Renamed element.
	if expectedErr == nil && !selfRename {
		// Expect all to be renamed appropriately. Note that if this is
		// a final file being renamed, then we expect the file to be
		// called with the new parent. If not, then we expect the
		// rename hook to be called, but the parent will remain
		// unchanged.
		elements := srcNames[len(renameSrcPath):]
		expectRenamed(targetBackend, elements, dstParentBackend, dstName)
		expectRenamed(secondBackend, elements, dstParentBackend, dstName)
		expectRenamed(thirdBackend, elements, dstParentBackend, dstName)

		// The target parent has also been opened, and may be moved
		// directly or indirectly.
		if len(elements) > 1 {
			expectRenamed(targetParentBackend, elements[:len(elements)-1], dstParentBackend, dstName)
		}
	}

	// Expect the rename if it's not the same file. Note that like unlink,
	// renames are always translated to the at variant in the backend.
	if !selfRename {
		srcParentBackend.EXPECT().RenameAt(srcName, dstParentBackend, dstName).Return(expectedErr)
	}

	// Perform the actual rename; everything has been lined up.
	if err := renameFn(h, srcParent, dstParent, srcName, dstName, selfRename); err != expectedErr {
		h.t.Fatalf("got rename err %v, want %v", err, expectedErr)
	}
}

func renameTest(t *testing.T, srcNames []string, dstNames []string, target fileGenerator) {
	t.Run(fmt.Sprintf("renameAt(%s->%s)", strings.Join(srcNames, "/"), strings.Join(dstNames, "/")), func(t *testing.T) {
		h, c := NewHarness(t)
		defer h.Finish()

		_, root := newRoot(h, c)
		defer root.Close()

		renameHelper(h, root, srcNames, dstNames, target, renameAt)
	})
	t.Run(fmt.Sprintf("rename(%s->%s)", strings.Join(srcNames, "/"), strings.Join(dstNames, "/")), func(t *testing.T) {
		h, c := NewHarness(t)
		defer h.Finish()

		_, root := newRoot(h, c)
		defer root.Close()

		renameHelper(h, root, srcNames, dstNames, target, rename)
	})
}

func TestRename(t *testing.T) {
	// In-directory rename, simple case.
	for name := range newTypeMap(nil) {
		// Within the root.
		renameTest(t, []string{name}, []string{"renamed"}, walkHelper)
		renameTest(t, []string{name}, []string{"renamed"}, walkAndOpenHelper)

		// Within a subdirectory.
		renameTest(t, []string{"one", name}, []string{"one", "renamed"}, walkHelper)
		renameTest(t, []string{"one", name}, []string{"one", "renamed"}, walkAndOpenHelper)
	}

	// ... with created files.
	renameTest(t, []string{"created"}, []string{"renamed"}, createHelper)
	renameTest(t, []string{"one", "created"}, []string{"one", "renamed"}, createHelper)

	// Across directories.
	for name := range newTypeMap(nil) {
		// Down one level.
		renameTest(t, []string{"one", name}, []string{"one", "two", "renamed"}, walkHelper)
		renameTest(t, []string{"one", name}, []string{"one", "two", "renamed"}, walkAndOpenHelper)

		// Up one level.
		renameTest(t, []string{"one", "two", name}, []string{"one", "renamed"}, walkHelper)
		renameTest(t, []string{"one", "two", name}, []string{"one", "renamed"}, walkAndOpenHelper)

		// Across at the same level.
		renameTest(t, []string{"one", name}, []string{"three", "renamed"}, walkHelper)
		renameTest(t, []string{"one", name}, []string{"three", "renamed"}, walkAndOpenHelper)
	}

	// ... with created files.
	renameTest(t, []string{"one", "created"}, []string{"one", "two", "renamed"}, createHelper)
	renameTest(t, []string{"one", "two", "created"}, []string{"one", "renamed"}, createHelper)
	renameTest(t, []string{"one", "created"}, []string{"three", "renamed"}, createHelper)

	// Renaming parents.
	for name := range newTypeMap(nil) {
		// Rename a parent.
		renameTest(t, []string{"one", name}, []string{"renamed", name}, walkHelper)
		renameTest(t, []string{"one", name}, []string{"renamed", name}, walkAndOpenHelper)

		// Rename a super parent.
		renameTest(t, []string{"one", "two", name}, []string{"renamed", name}, walkHelper)
		renameTest(t, []string{"one", "two", name}, []string{"renamed", name}, walkAndOpenHelper)
	}

	// ... with created files.
	renameTest(t, []string{"one", "created"}, []string{"renamed", "created"}, createHelper)
	renameTest(t, []string{"one", "two", "created"}, []string{"renamed", "created"}, createHelper)

	// Over existing files, including itself.
	for name := range newTypeMap(nil) {
		for other := range newTypeMap(nil) {
			// Overwrite the noted file (may be itself).
			renameTest(t, []string{"one", name}, []string{"one", other}, walkHelper)
			renameTest(t, []string{"one", name}, []string{"one", other}, walkAndOpenHelper)

			// Overwrite other files in another directory.
			renameTest(t, []string{"one", name}, []string{"one", "two", other}, walkHelper)
			renameTest(t, []string{"one", name}, []string{"one", "two", other}, walkAndOpenHelper)
		}

		// Overwrite by moving the parent.
		renameTest(t, []string{"three", name}, []string{"one", name}, walkHelper)
		renameTest(t, []string{"three", name}, []string{"one", name}, walkAndOpenHelper)

		// Create over the types.
		renameTest(t, []string{"one", "created"}, []string{"one", name}, createHelper)
		renameTest(t, []string{"one", "created"}, []string{"one", "two", name}, createHelper)
		renameTest(t, []string{"three", "created"}, []string{"one", name}, createHelper)
	}
}

func TestRenameInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			if err := root.Rename(root, invalidName); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

func TestRenameAtInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			if err := root.RenameAt(invalidName, root, "okay"); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
			if err := root.RenameAt("okay", root, invalidName); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

func TestReadlink(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			// Walk to the file normally.
			_, f, err := root.Walk([]string{name})
			if err != nil {
				t.Fatalf("walk failed: got %v, wanted nil", err)
			}
			defer f.Close()
			backend := h.Pop(f)

			const symlinkTarget = "symlink-target"

			if backend.Attr.Mode.IsSymlink() {
				// This should only go through on symlinks.
				backend.EXPECT().Readlink().Return(symlinkTarget, nil)
			}

			// Attempt a Readlink operation.
			target, err := f.Readlink()
			if err != nil && err != syscall.EINVAL {
				t.Errorf("readlink got %v, wanted EINVAL", err)
			} else if err == nil && target != symlinkTarget {
				t.Errorf("readlink got %v, wanted %v", target, symlinkTarget)
			}
		})
	}
}

// fdTest is a wrapper around operations that may send file descriptors. This
// asserts that the file descriptors are working as intended.
func fdTest(t *testing.T, sendFn func(*fd.FD) *fd.FD) {
	// Create a pipe that we can read from.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("unable to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// Attempt to send the write end.
	wFD, err := fd.NewFromFile(w)
	if err != nil {
		t.Fatalf("unable to convert file: %v", err)
	}
	defer wFD.Close() // This is a copy.

	// Send wFD and receive newFD.
	newFD := sendFn(wFD)
	defer newFD.Close()

	// Attempt to write.
	const message = "hello"
	if _, err := newFD.Write([]byte(message)); err != nil {
		t.Fatalf("write got %v, wanted nil", err)
	}

	// Should see the message on our end.
	buffer := []byte(message)
	if _, err := io.ReadFull(r, buffer); err != nil {
		t.Fatalf("read got %v, wanted nil", err)
	}
	if string(buffer) != message {
		t.Errorf("got message %v, wanted %v", string(buffer), message)
	}
}

func TestConnect(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			// Walk to the file normally.
			_, backend, f := walkHelper(h, name, root)
			defer f.Close()

			// Catch all the non-socket cases.
			if !backend.Attr.Mode.IsSocket() {
				// This has been set up to fail if Connect is called.
				if _, err := f.Connect(p9.ConnectFlags(0)); err != syscall.EINVAL {
					t.Errorf("connect got %v, wanted EINVAL", err)
				}
				return
			}

			// Ensure the fd exchange works.
			fdTest(t, func(send *fd.FD) *fd.FD {
				backend.EXPECT().Connect(p9.ConnectFlags(0)).Return(send, nil)
				recv, err := backend.Connect(p9.ConnectFlags(0))
				if err != nil {
					t.Fatalf("connect got %v, wanted nil", err)
				}
				return recv
			})
		})
	}
}

func TestReaddir(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			// Walk to the file normally.
			_, backend, f := walkHelper(h, name, root)
			defer f.Close()

			// Catch all the non-directory cases.
			if !backend.Attr.Mode.IsDir() {
				// This has also been set up to fail if Readdir is called.
				if _, err := f.Readdir(0, 1); err != syscall.EINVAL {
					t.Errorf("readdir got %v, wanted EINVAL", err)
				}
				return
			}

			// Ensure that readdir works for directories.
			if _, err := f.Readdir(0, 1); err != syscall.EINVAL {
				t.Errorf("readdir got %v, wanted EINVAL", err)
			}
			if _, _, _, err := f.Open(p9.ReadWrite); err != syscall.EINVAL {
				t.Errorf("readdir got %v, wanted EINVAL", err)
			}
			if _, _, _, err := f.Open(p9.WriteOnly); err != syscall.EINVAL {
				t.Errorf("readdir got %v, wanted EINVAL", err)
			}
			backend.EXPECT().Open(p9.ReadOnly).Times(1)
			if _, _, _, err := f.Open(p9.ReadOnly); err != nil {
				t.Errorf("readdir got %v, wanted nil", err)
			}
			backend.EXPECT().Readdir(uint64(0), uint32(1)).Times(1)
			if _, err := f.Readdir(0, 1); err != nil {
				t.Errorf("readdir got %v, wanted nil", err)
			}
		})
	}
}

func TestOpen(t *testing.T) {
	type openTest struct {
		name  string
		mode  p9.OpenFlags
		err   error
		match func(p9.FileMode) bool
	}

	cases := []openTest{
		{
			name:  "invalid",
			mode:  ^p9.OpenFlagsModeMask,
			err:   syscall.EINVAL,
			match: func(p9.FileMode) bool { return true },
		},
		{
			name:  "not-openable-read-only",
			mode:  p9.ReadOnly,
			err:   syscall.EINVAL,
			match: func(mode p9.FileMode) bool { return !p9.CanOpen(mode) },
		},
		{
			name:  "not-openable-write-only",
			mode:  p9.WriteOnly,
			err:   syscall.EINVAL,
			match: func(mode p9.FileMode) bool { return !p9.CanOpen(mode) },
		},
		{
			name:  "not-openable-read-write",
			mode:  p9.ReadWrite,
			err:   syscall.EINVAL,
			match: func(mode p9.FileMode) bool { return !p9.CanOpen(mode) },
		},
		{
			name:  "directory-read-only",
			mode:  p9.ReadOnly,
			err:   nil,
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
		},
		{
			name:  "directory-read-write",
			mode:  p9.ReadWrite,
			err:   syscall.EINVAL,
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
		},
		{
			name:  "directory-write-only",
			mode:  p9.WriteOnly,
			err:   syscall.EINVAL,
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
		},
		{
			name:  "read-only",
			mode:  p9.ReadOnly,
			err:   nil,
			match: func(mode p9.FileMode) bool { return p9.CanOpen(mode) },
		},
		{
			name:  "write-only",
			mode:  p9.WriteOnly,
			err:   nil,
			match: func(mode p9.FileMode) bool { return p9.CanOpen(mode) && !mode.IsDir() },
		},
		{
			name:  "read-write",
			mode:  p9.ReadWrite,
			err:   nil,
			match: func(mode p9.FileMode) bool { return p9.CanOpen(mode) && !mode.IsDir() },
		},
	}

	// Open(mode OpenFlags) (*fd.FD, QID, uint32, error)
	// - only works on Regular, NamedPipe, BLockDevice, CharacterDevice
	// - returning a file works as expected
	for name := range newTypeMap(nil) {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s-%s", tc.name, name), func(t *testing.T) {
				h, c := NewHarness(t)
				defer h.Finish()

				_, root := newRoot(h, c)
				defer root.Close()

				// Walk to the file normally.
				_, backend, f := walkHelper(h, name, root)
				defer f.Close()

				// Does this match the case?
				if !tc.match(backend.Attr.Mode) {
					t.SkipNow()
				}

				// Ensure open-required operations fail.
				if _, err := f.ReadAt([]byte("hello"), 0); err != syscall.EINVAL {
					t.Errorf("readAt got %v, wanted EINVAL", err)
				}
				if _, err := f.WriteAt(make([]byte, 6), 0); err != syscall.EINVAL {
					t.Errorf("writeAt got %v, wanted EINVAL", err)
				}
				if err := f.FSync(); err != syscall.EINVAL {
					t.Errorf("fsync got %v, wanted EINVAL", err)
				}
				if _, err := f.Readdir(0, 1); err != syscall.EINVAL {
					t.Errorf("readdir got %v, wanted EINVAL", err)
				}

				// Attempt the given open.
				if tc.err != nil {
					// We expect an error, just test and return.
					if _, _, _, err := f.Open(tc.mode); err != tc.err {
						t.Fatalf("open with mode %v got %v, want %v", tc.mode, err, tc.err)
					}
					return
				}

				// Run an FD test, since we expect success.
				fdTest(t, func(send *fd.FD) *fd.FD {
					backend.EXPECT().Open(tc.mode).Return(send, p9.QID{}, uint32(0), nil).Times(1)
					recv, _, _, err := f.Open(tc.mode)
					if err != tc.err {
						t.Fatalf("open with mode %v got %v, want %v", tc.mode, err, tc.err)
					}
					return recv
				})

				// If the open was successful, attempt another one.
				if _, _, _, err := f.Open(tc.mode); err != syscall.EINVAL {
					t.Errorf("second open with mode %v got %v, want EINVAL", tc.mode, err)
				}

				// Ensure that all illegal operations fail.
				if _, _, err := f.Walk(nil); err != syscall.EINVAL && err != syscall.EBUSY {
					t.Errorf("walk got %v, wanted EINVAL or EBUSY", err)
				}
				if _, _, _, _, err := f.WalkGetAttr(nil); err != syscall.EINVAL && err != syscall.EBUSY {
					t.Errorf("walkgetattr got %v, wanted EINVAL or EBUSY", err)
				}
			})
		}
	}
}

func TestClose(t *testing.T) {
	type closeTest struct {
		name    string
		closeFn func(backend *Mock, f p9.File)
	}

	cases := []closeTest{
		{
			name: "close",
			closeFn: func(_ *Mock, f p9.File) {
				f.Close()
			},
		},
		{
			name: "remove",
			closeFn: func(backend *Mock, f p9.File) {
				// Allow the rename call in the parent, automatically translated.
				backend.parent.EXPECT().UnlinkAt(gomock.Any(), gomock.Any()).Times(1)
				f.(deprecatedRemover).Remove()
			},
		},
	}

	for name := range newTypeMap(nil) {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s(%s)", tc.name, name), func(t *testing.T) {
				h, c := NewHarness(t)
				defer h.Finish()

				_, root := newRoot(h, c)
				defer root.Close()

				// Walk to the file normally.
				_, backend, f := walkHelper(h, name, root)

				// Close via the prescribed method.
				tc.closeFn(backend, f)

				// Everything should fail with EBADF.
				if _, _, err := f.Walk(nil); err != syscall.EBADF {
					t.Errorf("walk got %v, wanted EBADF", err)
				}
				if _, err := f.StatFS(); err != syscall.EBADF {
					t.Errorf("statfs got %v, wanted EBADF", err)
				}
				if _, _, _, err := f.GetAttr(p9.AttrMaskAll()); err != syscall.EBADF {
					t.Errorf("getattr got %v, wanted EBADF", err)
				}
				if err := f.SetAttr(p9.SetAttrMask{}, p9.SetAttr{}); err != syscall.EBADF {
					t.Errorf("setattrk got %v, wanted EBADF", err)
				}
				if err := f.Rename(root, "new-name"); err != syscall.EBADF {
					t.Errorf("rename got %v, wanted EBADF", err)
				}
				if err := f.Close(); err != syscall.EBADF {
					t.Errorf("close got %v, wanted EBADF", err)
				}
				if _, _, _, err := f.Open(p9.ReadOnly); err != syscall.EBADF {
					t.Errorf("open got %v, wanted EBADF", err)
				}
				if _, err := f.ReadAt([]byte("hello"), 0); err != syscall.EBADF {
					t.Errorf("readAt got %v, wanted EBADF", err)
				}
				if _, err := f.WriteAt(make([]byte, 6), 0); err != syscall.EBADF {
					t.Errorf("writeAt got %v, wanted EBADF", err)
				}
				if err := f.FSync(); err != syscall.EBADF {
					t.Errorf("fsync got %v, wanted EBADF", err)
				}
				if _, _, _, _, err := f.Create("new-file", p9.ReadWrite, 0, 0, 0); err != syscall.EBADF {
					t.Errorf("create got %v, wanted EBADF", err)
				}
				if _, err := f.Mkdir("new-directory", 0, 0, 0); err != syscall.EBADF {
					t.Errorf("mkdir got %v, wanted EBADF", err)
				}
				if _, err := f.Symlink("old-name", "new-name", 0, 0); err != syscall.EBADF {
					t.Errorf("symlink got %v, wanted EBADF", err)
				}
				if err := f.Link(root, "new-name"); err != syscall.EBADF {
					t.Errorf("link got %v, wanted EBADF", err)
				}
				if _, err := f.Mknod("new-block-device", 0, 0, 0, 0, 0); err != syscall.EBADF {
					t.Errorf("mknod got %v, wanted EBADF", err)
				}
				if err := f.RenameAt("old-name", root, "new-name"); err != syscall.EBADF {
					t.Errorf("renameAt got %v, wanted EBADF", err)
				}
				if err := f.UnlinkAt("name", 0); err != syscall.EBADF {
					t.Errorf("unlinkAt got %v, wanted EBADF", err)
				}
				if _, err := f.Readdir(0, 1); err != syscall.EBADF {
					t.Errorf("readdir got %v, wanted EBADF", err)
				}
				if _, err := f.Readlink(); err != syscall.EBADF {
					t.Errorf("readlink got %v, wanted EBADF", err)
				}
				if err := f.Flush(); err != syscall.EBADF {
					t.Errorf("flush got %v, wanted EBADF", err)
				}
				if _, _, _, _, err := f.WalkGetAttr(nil); err != syscall.EBADF {
					t.Errorf("walkgetattr got %v, wanted EBADF", err)
				}
				if _, err := f.Connect(p9.ConnectFlags(0)); err != syscall.EBADF {
					t.Errorf("connect got %v, wanted EBADF", err)
				}
			})
		}
	}
}

// onlyWorksOnOpenThings is a helper test method for operations that should
// only work on files that have been explicitly opened.
func onlyWorksOnOpenThings(h *Harness, t *testing.T, name string, root p9.File, mode p9.OpenFlags, expectedErr error, fn func(backend *Mock, f p9.File, shouldSucceed bool) error) {
	// Walk to the file normally.
	_, backend, f := walkHelper(h, name, root)
	defer f.Close()

	// Does it work before opening?
	if err := fn(backend, f, false); err != syscall.EINVAL {
		t.Errorf("operation got %v, wanted EINVAL", err)
	}

	// Is this openable?
	if !p9.CanOpen(backend.Attr.Mode) {
		return // Nothing to do.
	}

	// If this is a directory, we can't handle writing.
	if backend.Attr.Mode.IsDir() && (mode == p9.ReadWrite || mode == p9.WriteOnly) {
		return // Skip.
	}

	// Open the file.
	backend.EXPECT().Open(mode)
	if _, _, _, err := f.Open(mode); err != nil {
		t.Fatalf("open got %v, wanted nil", err)
	}

	// Attempt the operation.
	if err := fn(backend, f, expectedErr == nil); err != expectedErr {
		t.Fatalf("operation got %v, wanted %v", err, expectedErr)
	}
}

func TestRead(t *testing.T) {
	type readTest struct {
		name string
		mode p9.OpenFlags
		err  error
	}

	cases := []readTest{
		{
			name: "read-only",
			mode: p9.ReadOnly,
			err:  nil,
		},
		{
			name: "read-write",
			mode: p9.ReadWrite,
			err:  nil,
		},
		{
			name: "write-only",
			mode: p9.WriteOnly,
			err:  syscall.EPERM,
		},
	}

	for name := range newTypeMap(nil) {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s-%s", tc.name, name), func(t *testing.T) {
				h, c := NewHarness(t)
				defer h.Finish()

				_, root := newRoot(h, c)
				defer root.Close()

				const message = "hello"

				onlyWorksOnOpenThings(h, t, name, root, tc.mode, tc.err, func(backend *Mock, f p9.File, shouldSucceed bool) error {
					if !shouldSucceed {
						_, err := f.ReadAt([]byte(message), 0)
						return err
					}

					// Prepare for the call to readAt in the backend.
					backend.EXPECT().ReadAt(gomock.Any(), uint64(0)).Do(func(p []byte, offset uint64) {
						copy(p, message)
					}).Return(len(message), nil)

					// Make the client call.
					p := make([]byte, 2*len(message)) // Double size.
					n, err := f.ReadAt(p, 0)

					// Sanity check result.
					if err != nil {
						return err
					}
					if n != len(message) {
						t.Fatalf("message length incorrect, got %d, want %d", n, len(message))
					}
					if !bytes.Equal(p[:n], []byte(message)) {
						t.Fatalf("message incorrect, got %v, want %v", p, []byte(message))
					}
					return nil // Success.
				})
			})
		}
	}
}

func TestWrite(t *testing.T) {
	type writeTest struct {
		name string
		mode p9.OpenFlags
		err  error
	}

	cases := []writeTest{
		{
			name: "read-only",
			mode: p9.ReadOnly,
			err:  syscall.EPERM,
		},
		{
			name: "read-write",
			mode: p9.ReadWrite,
			err:  nil,
		},
		{
			name: "write-only",
			mode: p9.WriteOnly,
			err:  nil,
		},
	}

	for name := range newTypeMap(nil) {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s-%s", tc.name, name), func(t *testing.T) {
				h, c := NewHarness(t)
				defer h.Finish()

				_, root := newRoot(h, c)
				defer root.Close()

				const message = "hello"

				onlyWorksOnOpenThings(h, t, name, root, tc.mode, tc.err, func(backend *Mock, f p9.File, shouldSucceed bool) error {
					if !shouldSucceed {
						_, err := f.WriteAt([]byte(message), 0)
						return err
					}

					// Prepare for the call to readAt in the backend.
					var output []byte // Saved by Do below.
					backend.EXPECT().WriteAt(gomock.Any(), uint64(0)).Do(func(p []byte, offset uint64) {
						output = p
					}).Return(len(message), nil)

					// Make the client call.
					n, err := f.WriteAt([]byte(message), 0)

					// Sanity check result.
					if err != nil {
						return err
					}
					if n != len(message) {
						t.Fatalf("message length incorrect, got %d, want %d", n, len(message))
					}
					if !bytes.Equal(output, []byte(message)) {
						t.Fatalf("message incorrect, got %v, want %v", output, []byte(message))
					}
					return nil // Success.
				})
			})
		}
	}
}

func TestFSync(t *testing.T) {
	for name := range newTypeMap(nil) {
		for _, mode := range []p9.OpenFlags{p9.ReadOnly, p9.WriteOnly, p9.ReadWrite} {
			t.Run(fmt.Sprintf("%s-%s", mode, name), func(t *testing.T) {
				h, c := NewHarness(t)
				defer h.Finish()

				_, root := newRoot(h, c)
				defer root.Close()

				onlyWorksOnOpenThings(h, t, name, root, mode, nil, func(backend *Mock, f p9.File, shouldSucceed bool) error {
					if shouldSucceed {
						backend.EXPECT().FSync().Times(1)
					}
					return f.FSync()
				})
			})
		}
	}
}

func TestFlush(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			_, backend, f := walkHelper(h, name, root)
			defer f.Close()

			backend.EXPECT().Flush()
			f.Flush()
		})
	}
}

// onlyWorksOnDirectories is a helper test method for operations that should
// only work on unopened directories, such as create, mkdir and symlink.
func onlyWorksOnDirectories(h *Harness, t *testing.T, name string, root p9.File, fn func(backend *Mock, f p9.File, shouldSucceed bool) error) {
	// Walk to the file normally.
	_, backend, f := walkHelper(h, name, root)
	defer f.Close()

	// Only directories support mknod.
	if !backend.Attr.Mode.IsDir() {
		if err := fn(backend, f, false); err != syscall.EINVAL {
			t.Errorf("operation got %v, wanted EINVAL", err)
		}
		return // Nothing else to do.
	}

	// Should succeed.
	if err := fn(backend, f, true); err != nil {
		t.Fatalf("operation got %v, wanted nil", err)
	}

	// Open the directory.
	backend.EXPECT().Open(p9.ReadOnly).Times(1)
	if _, _, _, err := f.Open(p9.ReadOnly); err != nil {
		t.Fatalf("open got %v, wanted nil", err)
	}

	// Should not work again.
	if err := fn(backend, f, false); err != syscall.EINVAL {
		t.Fatalf("operation got %v, wanted EINVAL", err)
	}
}

func TestCreate(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			onlyWorksOnDirectories(h, t, name, root, func(backend *Mock, f p9.File, shouldSucceed bool) error {
				if !shouldSucceed {
					_, _, _, _, err := f.Create("new-file", p9.ReadWrite, 0, 1, 2)
					return err
				}

				// If the create is going to succeed, then we
				// need to create a new backend file, and we
				// clone to ensure that we don't close the
				// original.
				_, newF, err := f.Walk(nil)
				if err != nil {
					t.Fatalf("clone got %v, wanted nil", err)
				}
				defer newF.Close()
				newBackend := h.Pop(newF)

				// Run a regular FD test to validate that path.
				fdTest(t, func(send *fd.FD) *fd.FD {
					// Return the send FD on success.
					newFile := h.NewFile()(backend) // New file with the parent backend.
					newBackend.EXPECT().Create("new-file", p9.ReadWrite, p9.FileMode(0), p9.UID(1), p9.GID(2)).Return(send, newFile, p9.QID{}, uint32(0), nil)

					// Receive the fd back.
					recv, _, _, _, err := newF.Create("new-file", p9.ReadWrite, 0, 1, 2)
					if err != nil {
						t.Fatalf("create got %v, wanted nil", err)
					}
					return recv
				})

				// The above will fail via normal test flow, so
				// we can assume that it passed.
				return nil
			})
		})
	}
}

func TestCreateInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			if _, _, _, _, err := root.Create(invalidName, p9.ReadWrite, 0, 0, 0); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

func TestMkdir(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			onlyWorksOnDirectories(h, t, name, root, func(backend *Mock, f p9.File, shouldSucceed bool) error {
				if shouldSucceed {
					backend.EXPECT().Mkdir("new-directory", p9.FileMode(0), p9.UID(1), p9.GID(2))
				}
				_, err := f.Mkdir("new-directory", 0, 1, 2)
				return err
			})
		})
	}
}

func TestMkdirInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			if _, err := root.Mkdir(invalidName, 0, 0, 0); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

func TestSymlink(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			onlyWorksOnDirectories(h, t, name, root, func(backend *Mock, f p9.File, shouldSucceed bool) error {
				if shouldSucceed {
					backend.EXPECT().Symlink("old-name", "new-name", p9.UID(1), p9.GID(2))
				}
				_, err := f.Symlink("old-name", "new-name", 1, 2)
				return err
			})
		})
	}
}

func TestSyminkInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			// We need only test for invalid names in the new name,
			// the target can be an arbitrary string and we don't
			// need to sanity check it.
			if _, err := root.Symlink("old-name", invalidName, 0, 0); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

func TestLink(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			onlyWorksOnDirectories(h, t, name, root, func(backend *Mock, f p9.File, shouldSucceed bool) error {
				if shouldSucceed {
					backend.EXPECT().Link(gomock.Any(), "new-link")
				}
				return f.Link(f, "new-link")
			})
		})
	}
}

func TestLinkInvalid(t *testing.T) {
	h, c := NewHarness(t)
	defer h.Finish()

	_, root := newRoot(h, c)
	defer root.Close()

	for name := range newTypeMap(nil) {
		for _, invalidName := range allInvalidNames(name) {
			if err := root.Link(root, invalidName); err != syscall.EINVAL {
				t.Errorf("got %v for name %q, want EINVAL", err, invalidName)
			}
		}
	}
}

func TestMknod(t *testing.T) {
	for name := range newTypeMap(nil) {
		t.Run(name, func(t *testing.T) {
			h, c := NewHarness(t)
			defer h.Finish()

			_, root := newRoot(h, c)
			defer root.Close()

			onlyWorksOnDirectories(h, t, name, root, func(backend *Mock, f p9.File, shouldSucceed bool) error {
				if shouldSucceed {
					backend.EXPECT().Mknod("new-block-device", p9.FileMode(0), uint32(1), uint32(2), p9.UID(3), p9.GID(4)).Times(1)
				}
				_, err := f.Mknod("new-block-device", 0, 1, 2, 3, 4)
				return err
			})
		})
	}
}

// concurrentFn is a specification of a concurrent operation. This is used to
// drive the concurrency tests below.
type concurrentFn struct {
	name  string
	match func(p9.FileMode) bool
	op    func(h *Harness, backend *Mock, f p9.File, callback func())
}

func concurrentTest(t *testing.T, name string, fn1, fn2 concurrentFn, sameDir, expectedOkay bool) {
	var (
		names1 []string
		names2 []string
	)
	if sameDir {
		// Use the same file one directory up.
		names1, names2 = []string{"one", name}, []string{"one", name}
	} else {
		// For different directories, just use siblings.
		names1, names2 = []string{"one", name}, []string{"three", name}
	}

	t.Run(fmt.Sprintf("%s(%v)+%s(%v)", fn1.name, names1, fn2.name, names2), func(t *testing.T) {
		h, c := NewHarness(t)
		defer h.Finish()

		_, root := newRoot(h, c)
		defer root.Close()

		// Walk to both files as given.
		_, f1, err := root.Walk(names1)
		if err != nil {
			t.Fatalf("error walking, got %v, want nil", err)
		}
		defer f1.Close()
		b1 := h.Pop(f1)
		_, f2, err := root.Walk(names2)
		if err != nil {
			t.Fatalf("error walking, got %v, want nil", err)
		}
		defer f2.Close()
		b2 := h.Pop(f2)

		// Are these a good match for the current test case?
		if !fn1.match(b1.Attr.Mode) {
			t.SkipNow()
		}
		if !fn2.match(b2.Attr.Mode) {
			t.SkipNow()
		}

		// Construct our "concurrency creator".
		in1 := make(chan struct{}, 1)
		in2 := make(chan struct{}, 1)
		var top sync.WaitGroup
		var fns sync.WaitGroup
		defer top.Wait()
		top.Add(2) // Accounting for below.
		defer fns.Done()
		fns.Add(1) // See line above; released before top.Wait.
		go func() {
			defer top.Done()
			fn1.op(h, b1, f1, func() {
				in1 <- struct{}{}
				fns.Wait()
			})
		}()
		go func() {
			defer top.Done()
			fn2.op(h, b2, f2, func() {
				in2 <- struct{}{}
				fns.Wait()
			})
		}()

		// Compute a reasonable timeout. If we expect the operation to hang,
		// give it 10 milliseconds before we assert that it's fine. After all,
		// there will be a lot of these tests. If we don't expect it to hang,
		// give it a full minute, since the machine could be slow.
		timeout := 10 * time.Millisecond
		if expectedOkay {
			timeout = 1 * time.Minute
		}

		// Read the first channel.
		var second chan struct{}
		select {
		case <-in1:
			second = in2
		case <-in2:
			second = in1
		}

		// Catch concurrency.
		select {
		case <-second:
			// We finished successful. Is this good? Depends on the
			// expected result.
			if !expectedOkay {
				t.Errorf("%q and %q proceeded concurrently!", fn1.name, fn2.name)
			}
		case <-time.After(timeout):
			// Great, things did not proceed concurrently. Is that what we
			// expected?
			if expectedOkay {
				t.Errorf("%q and %q hung concurrently!", fn1.name, fn2.name)
			}
		}
	})
}

func randomFileName() string {
	return fmt.Sprintf("%x", rand.Int63())
}

func TestConcurrency(t *testing.T) {
	readExclusive := []concurrentFn{
		{
			// N.B. We can't explicitly check WalkGetAttr behavior,
			// but we rely on the fact that the internal code paths
			// are the same.
			name:  "walk",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				// See the documentation of WalkCallback.
				// Because walk is actually implemented by the
				// mock, we need a special place for this
				// callback.
				//
				// Note that a clone actually locks the parent
				// node. So we walk from this node to test
				// concurrent operations appropriately.
				backend.WalkCallback = func() error {
					callback()
					return nil
				}
				f.Walk([]string{randomFileName()}) // Won't exist.
			},
		},
		{
			name:  "fsync",
			match: func(mode p9.FileMode) bool { return p9.CanOpen(mode) },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Open(gomock.Any())
				backend.EXPECT().FSync().Do(func() {
					callback()
				})
				f.Open(p9.ReadOnly) // Required.
				f.FSync()
			},
		},
		{
			name:  "readdir",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Open(gomock.Any())
				backend.EXPECT().Readdir(gomock.Any(), gomock.Any()).Do(func(uint64, uint32) {
					callback()
				})
				f.Open(p9.ReadOnly) // Required.
				f.Readdir(0, 1)
			},
		},
		{
			name:  "readlink",
			match: func(mode p9.FileMode) bool { return mode.IsSymlink() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Readlink().Do(func() {
					callback()
				})
				f.Readlink()
			},
		},
		{
			name:  "connect",
			match: func(mode p9.FileMode) bool { return mode.IsSocket() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Connect(gomock.Any()).Do(func(p9.ConnectFlags) {
					callback()
				})
				f.Connect(0)
			},
		},
		{
			name:  "open",
			match: func(mode p9.FileMode) bool { return p9.CanOpen(mode) },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Open(gomock.Any()).Do(func(p9.OpenFlags) {
					callback()
				})
				f.Open(p9.ReadOnly)
			},
		},
		{
			name:  "flush",
			match: func(mode p9.FileMode) bool { return true },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Flush().Do(func() {
					callback()
				})
				f.Flush()
			},
		},
	}
	writeExclusive := []concurrentFn{
		{
			// N.B. We can't really check getattr. But this is an
			// extremely low-risk function, it seems likely that
			// this check is paranoid anyways.
			name:  "setattr",
			match: func(mode p9.FileMode) bool { return true },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().SetAttr(gomock.Any(), gomock.Any()).Do(func(p9.SetAttrMask, p9.SetAttr) {
					callback()
				})
				f.SetAttr(p9.SetAttrMask{}, p9.SetAttr{})
			},
		},
		{
			name:  "unlinkAt",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().UnlinkAt(gomock.Any(), gomock.Any()).Do(func(string, uint32) {
					callback()
				})
				f.UnlinkAt(randomFileName(), 0)
			},
		},
		{
			name:  "mknod",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Mknod(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(string, p9.FileMode, uint32, uint32, p9.UID, p9.GID) {
					callback()
				})
				f.Mknod(randomFileName(), 0, 0, 0, 0, 0)
			},
		},
		{
			name:  "link",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Link(gomock.Any(), gomock.Any()).Do(func(p9.File, string) {
					callback()
				})
				f.Link(f, randomFileName())
			},
		},
		{
			name:  "symlink",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Symlink(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(string, string, p9.UID, p9.GID) {
					callback()
				})
				f.Symlink(randomFileName(), randomFileName(), 0, 0)
			},
		},
		{
			name:  "mkdir",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().Mkdir(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(string, p9.FileMode, p9.UID, p9.GID) {
					callback()
				})
				f.Mkdir(randomFileName(), 0, 0, 0)
			},
		},
		{
			name:  "create",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				// Return an error for the creation operation, as this is the simplest.
				backend.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil, p9.QID{}, uint32(0), syscall.EINVAL).Do(func(string, p9.OpenFlags, p9.FileMode, p9.UID, p9.GID) {
					callback()
				})
				f.Create(randomFileName(), p9.ReadOnly, 0, 0, 0)
			},
		},
	}
	globalExclusive := []concurrentFn{
		{
			name:  "remove",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				// Remove operates on a locked parent. So we
				// add a child, walk to it and call remove.
				// Note that because this operation can operate
				// concurrently with itself, we need to
				// generate a random file name.
				randomFile := randomFileName()
				backend.AddChild(randomFile, h.NewFile())
				defer backend.RemoveChild(randomFile)
				_, file, err := f.Walk([]string{randomFile})
				if err != nil {
					h.t.Fatalf("walk got %v, want nil", err)
				}

				// Remove is automatically translated to the parent.
				backend.EXPECT().UnlinkAt(gomock.Any(), gomock.Any()).Do(func(string, uint32) {
					callback()
				})

				// Remove is also a close.
				file.(deprecatedRemover).Remove()
			},
		},
		{
			name:  "rename",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				// Similarly to remove, because we need to
				// operate on a child, we allow a walk.
				randomFile := randomFileName()
				backend.AddChild(randomFile, h.NewFile())
				defer backend.RemoveChild(randomFile)
				_, file, err := f.Walk([]string{randomFile})
				if err != nil {
					h.t.Fatalf("walk got %v, want nil", err)
				}
				defer file.Close()
				fileBackend := h.Pop(file)

				// Rename is automatically translated to the parent.
				backend.EXPECT().RenameAt(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(string, p9.File, string) {
					callback()
				})

				// Attempt the rename.
				fileBackend.EXPECT().Renamed(gomock.Any(), gomock.Any())
				file.Rename(f, randomFileName())
			},
		},
		{
			name:  "renameAt",
			match: func(mode p9.FileMode) bool { return mode.IsDir() },
			op: func(h *Harness, backend *Mock, f p9.File, callback func()) {
				backend.EXPECT().RenameAt(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(string, p9.File, string) {
					callback()
				})

				// Attempt the rename. There are no active fids
				// with this name, so we don't need to expect
				// Renamed hooks on anything.
				f.RenameAt(randomFileName(), f, randomFileName())
			},
		},
	}

	for _, fn1 := range readExclusive {
		for _, fn2 := range readExclusive {
			for name := range newTypeMap(nil) {
				// Everything should be able to proceed in parallel.
				concurrentTest(t, name, fn1, fn2, true, true)
				concurrentTest(t, name, fn1, fn2, false, true)
			}
		}
	}

	for _, fn1 := range append(readExclusive, writeExclusive...) {
		for _, fn2 := range writeExclusive {
			for name := range newTypeMap(nil) {
				// Only cross-directory functions should proceed in parallel.
				concurrentTest(t, name, fn1, fn2, true, false)
				concurrentTest(t, name, fn1, fn2, false, true)
			}
		}
	}

	for _, fn1 := range append(append(readExclusive, writeExclusive...), globalExclusive...) {
		for _, fn2 := range globalExclusive {
			for name := range newTypeMap(nil) {
				// Nothing should be able to run in parallel.
				concurrentTest(t, name, fn1, fn2, true, false)
				concurrentTest(t, name, fn1, fn2, false, false)
			}
		}
	}
}
