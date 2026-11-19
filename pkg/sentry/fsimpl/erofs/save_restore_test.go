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

package erofs

import (
	"bytes"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/usermem"
)

// testNode is a file of an image built by newTestTreeImage. Tests place each
// one explicitly, to control what a rebuild of the image moves.
type testNode struct {
	// nid is the slot of the inode in the first block of the image, and
	// block is the address of its data block.
	nid   uint64
	block uint32
	// attr has the mode, owner and mtime of the inode.
	attr erofs.InodeExtended
	// data is the contents of a regular file, and children the entries of a
	// directory. A node that is entered more than once is a hard link.
	data     string
	children testNodes
}

type testNodes = map[string]*testNode

func testFile(nid uint64, block uint32, data string) *testNode {
	return &testNode{nid: nid, block: block, attr: erofs.InodeExtended{Mode: linux.S_IFREG | 0444}, data: data}
}

func testDir(nid uint64, block uint32, children testNodes) *testNode {
	return &testNode{nid: nid, block: block, attr: erofs.InodeExtended{Mode: linux.S_IFDIR | 0555}, children: children}
}

// newTestTreeImage returns an image of the directory tree at root. Images
// have the same superblock if they have the same build number and root nid.
func newTestTreeImage(build uint64, root *testNode) []byte {
	const blocks = 16
	image := make([]byte, blocks*hostarch.PageSize)
	sb := erofs.SuperBlock{Magic: erofs.SuperBlockMagicV1, BlockSizeBits: uint8(hostarch.PageShift), RootNid: uint16(root.nid), BuildTime: build, Blocks: blocks}
	sb.MarshalUnsafe(image[erofs.SuperBlockOffset:])
	root.marshal(image)
	return image
}

// marshal writes n and its descendants into image.
func (n *testNode) marshal(image []byte) {
	data := []byte(n.data)
	if n.children != nil {
		names := slices.Sorted(maps.Keys(n.children))
		data = make([]byte, len(names)*erofs.DirentSize)
		for j, name := range names {
			n.children[name].marshal(image)
			dirent := erofs.Dirent{NidLow: uint32(n.children[name].nid), NameOff: uint16(len(data))}
			dirent.MarshalUnsafe(data[j*erofs.DirentSize:])
			data = append(data, name...)
		}
	}
	inode := n.attr
	inode.Format = erofs.InodeLayoutExtended<<erofs.InodeLayoutBit | erofs.InodeDataLayoutFlatPlain<<erofs.InodeDataLayoutBit
	inode.Nlink, inode.Size, inode.RawBlockAddr = 1, uint64(len(data)), n.block
	inode.MarshalUnsafe(image[n.nid<<erofs.InodeSlotBits:])
	copy(image[uintptr(n.block)*hostarch.PageSize:], data)
}

// openTestPaths mounts image and opens its root directory and the files at
// paths.
func openTestPaths(t *testing.T, ctx context.Context, image []byte, paths ...string) []*vfs.FileDescription {
	t.Helper()
	root := mountTestImage(t, ctx, image)
	fds := []*vfs.FileDescription{openTestPath(t, ctx, root, "/")}
	for _, path := range paths {
		fds = append(fds, openTestPath(t, ctx, root, path))
	}
	return fds
}

// restoreTestFDs checkpoints fds, the first of which represents the root of
// their mount, and restores them with image as the image of the mount. It
// returns the restored root and the other file descriptions, and the result
// of completing the restore.
func restoreTestFDs(t *testing.T, ctx context.Context, fds []*vfs.FileDescription, image []byte) (vfs.VirtualDentry, []*vfs.FileDescription, error) {
	t.Helper()
	if err := fds[0].Mount().Filesystem().VirtualFilesystem().PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &fds); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	ctx = context.WithValue(ctx, vfs.CtxRestoreFilesystemFDMap, map[checkpoint.ResourceID]int{{}: newTestImageFD(t, image)})
	var restored []*vfs.FileDescription
	if _, err := state.Load(ctx, &buf, &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	err := restored[0].Mount().Filesystem().VirtualFilesystem().CompleteRestore(ctx, &vfs.CompleteRestoreOptions{})
	return restored[0].VirtualDentry(), restored[1:], err
}

func statTestPath(ctx context.Context, root vfs.VirtualDentry, path string) (linux.Statx, error) {
	return root.Mount().Filesystem().VirtualFilesystem().StatAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}, &vfs.StatOptions{})
}

// TestRestoreRebuiltImage restores an open file onto a rebuild of its image
// that has the same superblock, but has the file elsewhere.
func TestRestoreRebuiltImage(t *testing.T) {
	ctx := contexttest.Context(t)
	const contents = "contents of a"
	tree := func(a *testNode, others testNodes) *testNode {
		others["dir"], others["c"] = testDir(42, 3, testNodes{"a": a, "b": a}), a
		return testDir(40, 2, others)
	}
	before := newTestTreeImage(1, tree(testFile(44, 4, contents), testNodes{
		"gone": testDir(46, 5, testNodes{"deep": testDir(48, 6, testNodes{"file": testFile(50, 7, "gone")})}),
	}))
	// Another file takes the place of the open one, and the unused one goes
	// along with its directories. Both have names of one length, so that the
	// inode of the open file is the only one in use that differs.
	after := newTestTreeImage(1, tree(testFile(52, 8, contents), testNodes{"more": testFile(44, 4, "more")}))

	fds := openTestPaths(t, ctx, before, "dir/a", "dir/b")
	if _, err := statTestPath(ctx, fds[0].VirtualDentry(), "gone/deep/file"); err != nil {
		t.Fatalf("StatAt: %v", err)
	}
	old, err := fds[1].Stat(ctx, vfs.StatOptions{})
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	root, fds, err := restoreTestFDs(t, ctx, fds, after)
	if err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	buf := make([]byte, len(contents)+1)
	if n, err := fds[0].Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); err != nil && err != io.EOF || string(buf[:n]) != contents {
		t.Errorf("file open across the restore reads %q and gets error %v, want %q", buf[:n], err, contents)
	}
	// The hard links of the file still share its inode.
	if a, c := fds[0].Impl().(*regularFileFD).inode(), openTestPath(t, ctx, root, "c").Impl().(*regularFileFD).inode(); a != c {
		t.Errorf("hard links of the open file have inodes %p and %p, want one", a, c)
	}
	// The added file has the inode number that the open one had. An
	// application that remembers the latter must not take it for that file.
	stat, err := statTestPath(ctx, root, "more")
	if err != nil {
		t.Fatalf("StatAt: %v", err)
	}
	if stat.Ino != old.Ino || stat.DevMinor == old.DevMinor {
		t.Errorf("file that the rebuild added has device and inode numbers %d and %d, want another device than %d and inode number %d", stat.DevMinor, stat.Ino, old.DevMinor, old.Ino)
	}
}

// TestRestoreUnchangedInodes checks that an image is taken for the
// checkpointed one if it has the same superblock and has the inodes in use as
// they were, whatever else in it has changed.
func TestRestoreUnchangedInodes(t *testing.T) {
	ctx := contexttest.Context(t)
	tree := func(unused string) *testNode {
		return testDir(40, 2, testNodes{"file": testFile(42, 3, "contents"), "unused": testFile(44, 4, unused)})
	}
	fds := openTestPaths(t, ctx, newTestTreeImage(1, tree("before")), "file")
	old, err := statTestPath(ctx, fds[0].VirtualDentry(), "unused")
	if err != nil {
		t.Fatalf("StatAt: %v", err)
	}
	root, _, err := restoreTestFDs(t, ctx, fds, newTestTreeImage(1, tree("after it changed")))
	if err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	if stat, err := statTestPath(ctx, root, "file"); err != nil {
		t.Fatalf("StatAt: %v", err)
	} else if stat.DevMinor != old.DevMinor {
		t.Errorf("device number is %d, want %d as before the restore", stat.DevMinor, old.DevMinor)
	}
}

// TestRestoreIncompatibleImage checks that a restore fails if the image no
// longer has a file in use as it was.
func TestRestoreIncompatibleImage(t *testing.T) {
	tree := func() testNodes {
		link := testFile(42, 3, "contents")
		return testNodes{"x": link, "y": link, "z": testFile(44, 4, "contents"), "d": testDir(48, 6, testNodes{})}
	}
	for _, tc := range []struct {
		name   string
		change func(root testNodes)
		want   string
	}{
		{"file removed", func(root testNodes) { delete(root, "z") }, "no such file or directory"},
		{"mode changed", func(root testNodes) { root["z"].attr.Mode ^= 0200 }, "mode or owner changed"},
		{"gid changed", func(root testNodes) { root["z"].attr.GID++ }, "mode or owner changed"},
		{"file type changed", func(root testNodes) { root["z"].attr.Mode = linux.S_IFLNK | 0444 }, "mode or owner changed"},
		{"directory owner changed", func(root testNodes) { root["d"].attr.UID++ }, "mode or owner changed"},
		{"size changed", func(root testNodes) { root["z"].data += "!" }, "size or mtime changed"},
		{"mtime changed", func(root testNodes) { root["z"].attr.Mtime++ }, "size or mtime changed"},
		{"mtime nanoseconds changed", func(root testNodes) { root["z"].attr.MtimeNsec++ }, "size or mtime changed"},
		{"hard links split", func(root testNodes) { root["y"] = testFile(46, 5, "contents") }, "hard links changed"},
		{"hard links merged", func(root testNodes) { root["z"] = root["x"] }, "hard links changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			after := tree()
			tc.change(after)
			_, _, err := restoreTestFDs(t, ctx, openTestPaths(t, ctx, newTestTreeImage(1, testDir(40, 2, tree())), "x", "y", "z", "d"), newTestTreeImage(2, testDir(40, 2, after)))
			if _, ok := err.(vfs.ErrCorruption); !ok || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("CompleteRestore: got %v, want a vfs.ErrCorruption containing %q", err, tc.want)
			}
		})
	}
}
