// Copyright 2018 Google LLC
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

package fsutil_test

import (
	"io"
	"syscall"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	ramfstest "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs/test"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type testInodeOperations struct {
	fs.InodeOperations
	fs.InodeType
	FileSize int64
	writes   uint
	reads    uint
}

func (t *testInodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	return fs.UnstableAttr{Size: t.FileSize}, nil
}

// Check implements InodeOperations.Check.
func (t *testInodeOperations) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

func (t *testInodeOperations) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	t.reads++
	return t.InodeOperations.DeprecatedPreadv(ctx, dst, offset)
}

func (t *testInodeOperations) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	t.writes++
	return t.InodeOperations.DeprecatedPwritev(ctx, src, offset)
}

// testHandle returns a handle for a test node.
//
// The size of the node is fixed at 20 bytes.
func testHandle(t *testing.T, flags fs.FileFlags, nt fs.InodeType) (*fs.File, *testInodeOperations) {
	ctx := contexttest.Context(t)
	m := fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{})
	n := &testInodeOperations{
		InodeOperations: ramfstest.NewFile(ctx, fs.FilePermissions{User: fs.PermMask{Read: true, Write: true}}),
		FileSize:        20,
	}
	d := fs.NewDirent(fs.NewInode(n, m, fs.StableAttr{Type: nt}), "test")
	return fsutil.NewHandle(ctx, d, flags, d.Inode.HandleOps()), n
}

func TestHandleOps(t *testing.T) {
	h, n := testHandle(t, fs.FileFlags{Read: true, Write: true}, fs.RegularFile)
	defer h.DecRef()

	// Make sure a write request works.
	if n, err := h.Writev(contexttest.Context(t), usermem.BytesIOSequence([]byte("a"))); n != 1 || err != nil {
		t.Fatalf("Writev: got (%d, %v), wanted (1, nil)", n, err)
	}
	if n.writes != 1 {
		t.Errorf("found %d writes, expected 1", n.writes)
	}

	// Make sure a read request works.
	dst := make([]byte, 1)
	if n, err := h.Preadv(contexttest.Context(t), usermem.BytesIOSequence(dst), 0); n != 1 || (err != nil && err != io.EOF) {
		t.Errorf("Preadv: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if dst[0] != 'a' {
		t.Errorf("Preadv: read %q, wanted 'a'", dst[0])
	}
	if n.reads != 1 {
		t.Errorf("found %d reads, expected 1", n.reads)
	}
}

type seekTest struct {
	whence fs.SeekWhence
	offset int64
	result int64
	err    error
}

type seekSuite struct {
	nodeType fs.InodeType
	cases    []seekTest
}

// FIXME: This is currently missing fs.SeekEnd tests due to the
// fact that NullInodeOperations returns an error on stat.
func TestHandleSeek(t *testing.T) {
	ts := []seekSuite{
		{
			nodeType: fs.RegularFile,
			cases: []seekTest{
				{fs.SeekSet, 0, 0, nil},
				{fs.SeekSet, 10, 10, nil},
				{fs.SeekSet, -5, 10, syscall.EINVAL},
				{fs.SeekCurrent, -1, 9, nil},
				{fs.SeekCurrent, 2, 11, nil},
				{fs.SeekCurrent, -12, 11, syscall.EINVAL},
				{fs.SeekEnd, -1, 19, nil},
				{fs.SeekEnd, 0, 20, nil},
				{fs.SeekEnd, 2, 22, nil},
			},
		},
		{
			nodeType: fs.Directory,
			cases: []seekTest{
				{fs.SeekSet, 0, 0, nil},
				{fs.SeekSet, 10, 0, syscall.EINVAL},
				{fs.SeekSet, -5, 0, syscall.EINVAL},
				{fs.SeekCurrent, 0, 0, nil},
				{fs.SeekCurrent, 11, 0, syscall.EINVAL},
				{fs.SeekCurrent, -6, 0, syscall.EINVAL},
				{fs.SeekEnd, 0, 0, syscall.EINVAL},
				{fs.SeekEnd, -1, 0, syscall.EINVAL},
				{fs.SeekEnd, 2, 0, syscall.EINVAL},
			},
		},
		{
			nodeType: fs.Symlink,
			cases: []seekTest{
				{fs.SeekSet, 5, 0, syscall.EINVAL},
				{fs.SeekSet, -5, 0, syscall.EINVAL},
				{fs.SeekSet, 0, 0, syscall.EINVAL},
				{fs.SeekCurrent, 5, 0, syscall.EINVAL},
				{fs.SeekCurrent, -5, 0, syscall.EINVAL},
				{fs.SeekCurrent, 0, 0, syscall.EINVAL},
				{fs.SeekEnd, 5, 0, syscall.EINVAL},
				{fs.SeekEnd, -5, 0, syscall.EINVAL},
				{fs.SeekEnd, 0, 0, syscall.EINVAL},
			},
		},
		{
			nodeType: fs.Pipe,
			cases: []seekTest{
				{fs.SeekSet, 5, 0, syscall.ESPIPE},
				{fs.SeekSet, -5, 0, syscall.ESPIPE},
				{fs.SeekSet, 0, 0, syscall.ESPIPE},
				{fs.SeekCurrent, 5, 0, syscall.ESPIPE},
				{fs.SeekCurrent, -5, 0, syscall.ESPIPE},
				{fs.SeekCurrent, 0, 0, syscall.ESPIPE},
				{fs.SeekEnd, 5, 0, syscall.ESPIPE},
				{fs.SeekEnd, -5, 0, syscall.ESPIPE},
				{fs.SeekEnd, 0, 0, syscall.ESPIPE},
			},
		},
		{
			nodeType: fs.Socket,
			cases: []seekTest{
				{fs.SeekSet, 5, 0, syscall.ESPIPE},
				{fs.SeekSet, -5, 0, syscall.ESPIPE},
				{fs.SeekSet, 0, 0, syscall.ESPIPE},
				{fs.SeekCurrent, 5, 0, syscall.ESPIPE},
				{fs.SeekCurrent, -5, 0, syscall.ESPIPE},
				{fs.SeekCurrent, 0, 0, syscall.ESPIPE},
				{fs.SeekEnd, 5, 0, syscall.ESPIPE},
				{fs.SeekEnd, -5, 0, syscall.ESPIPE},
				{fs.SeekEnd, 0, 0, syscall.ESPIPE},
			},
		},
		{
			nodeType: fs.CharacterDevice,
			cases: []seekTest{
				{fs.SeekSet, 5, 0, nil},
				{fs.SeekSet, -5, 0, nil},
				{fs.SeekSet, 0, 0, nil},
				{fs.SeekCurrent, 5, 0, nil},
				{fs.SeekCurrent, -5, 0, nil},
				{fs.SeekCurrent, 0, 0, nil},
				{fs.SeekEnd, 5, 0, nil},
				{fs.SeekEnd, -5, 0, nil},
				{fs.SeekEnd, 0, 0, nil},
			},
		},
		{
			nodeType: fs.BlockDevice,
			cases: []seekTest{
				{fs.SeekSet, 0, 0, nil},
				{fs.SeekSet, 10, 10, nil},
				{fs.SeekSet, -5, 10, syscall.EINVAL},
				{fs.SeekCurrent, -1, 9, nil},
				{fs.SeekCurrent, 2, 11, nil},
				{fs.SeekCurrent, -12, 11, syscall.EINVAL},
				{fs.SeekEnd, -1, 19, nil},
				{fs.SeekEnd, 0, 20, nil},
				{fs.SeekEnd, 2, 22, nil},
			},
		},
	}

	for _, s := range ts {
		h, _ := testHandle(t, fs.FileFlags{Read: true, Write: true}, s.nodeType)
		defer h.DecRef()

		for _, c := range s.cases {
			// Try the given seek.
			offset, err := h.Seek(contexttest.Context(t), c.whence, c.offset)
			if err != c.err {
				t.Errorf("seek(%s, %d) on %s had unexpected error: expected %v, got %v", c.whence, c.offset, s.nodeType, c.err, err)
			}
			if err == nil && offset != c.result {
				t.Errorf("seek(%s, %d) on %s had bad result: expected %v, got %v", c.whence, c.offset, s.nodeType, c.result, offset)
			}
		}
	}
}
