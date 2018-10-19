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

package gofer

import (
	"fmt"
	"io"
	"syscall"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/p9/p9test"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// goodMockFile returns a file that can be Walk'ed to and created.
func goodMockFile(mode p9.FileMode, size uint64) *p9test.FileMock {
	return &p9test.FileMock{
		GetAttrMock: p9test.GetAttrMock{
			Attr:  p9.Attr{Mode: mode, Size: size, RDev: 0},
			Valid: p9.AttrMaskAll(),
		},
	}
}

func newClosedSocket() (*unet.Socket, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	s, err := unet.NewSocket(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return s, s.Close()
}

// root returns a p9 file mock and an fs.InodeOperations created from that file.  Any
// functions performed on fs.InodeOperations will use the p9 file mock.
func root(ctx context.Context, cp cachePolicy, mode p9.FileMode, size uint64) (*p9test.FileMock, *fs.Inode, error) {
	sock, err := newClosedSocket()
	if err != nil {
		return nil, nil, err
	}

	// Construct a dummy session that we can destruct.
	s := &session{
		conn:        sock,
		mounter:     fs.RootOwner,
		cachePolicy: cp,
		client:      &p9.Client{},
	}

	rootFile := goodMockFile(mode, size)
	sattr, rootInodeOperations := newInodeOperations(ctx, s, contextFile{file: rootFile}, p9.QID{}, rootFile.GetAttrMock.Valid, rootFile.GetAttrMock.Attr, false /* socket */)
	m := fs.NewMountSource(s, &filesystem{}, fs.MountSourceFlags{})
	return rootFile, fs.NewInode(rootInodeOperations, m, sattr), nil
}

func TestLookup(t *testing.T) {
	// Test parameters.
	type lookupTest struct {
		// Name of the test.
		name string

		// Function input parameters.
		fileName string

		// Expected return value.
		want error
	}

	tests := []lookupTest{
		{
			name:     "mock Walk passes (function succeeds)",
			fileName: "ppp",
			want:     nil,
		},
		{
			name:     "mock Walk fails (function fails)",
			fileName: "ppp",
			want:     syscall.ENOENT,
		},
	}

	ctx := contexttest.Context(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up mock.
			rootFile, rootInode, err := root(ctx, cacheNone, p9.PermissionsMask, 0)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}

			rootFile.WalkGetAttrMock.QIDs = []p9.QID{{}}
			rootFile.WalkGetAttrMock.Err = test.want
			rootFile.WalkGetAttrMock.File = goodMockFile(p9.PermissionsMask, 0)

			// Call function.
			dirent, err := rootInode.Lookup(ctx, test.fileName)

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

			// Check mock parameters.
			if !rootFile.WalkGetAttrMock.Called {
				t.Errorf("GetAttr not called; error: %v", err)
			} else if rootFile.WalkGetAttrMock.Names[0] != test.fileName {
				t.Errorf("file name not set")
			}
		})
	}
}

func TestRevalidation(t *testing.T) {
	tests := []struct {
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
	}{
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

	ctx := contexttest.Context(t)
	for _, test := range tests {
		name := fmt.Sprintf("cachepolicy=%s", test.cachePolicy)
		t.Run(name, func(t *testing.T) {
			// Set up mock.
			rootFile, rootInode, err := root(ctx, test.cachePolicy, p9.ModeDirectory|p9.PermissionsMask, 0)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}

			rootDir := fs.NewDirent(rootInode, "root")

			// Create a mock file that we will walk to from the root.
			const (
				name = "foo"
				mode = p9.PermissionsMask
			)
			file := goodMockFile(mode, 0)
			file.GetAttrMock.Valid = p9.AttrMaskAll()

			// Tell the root mock how to walk to this file.
			rootFile.WalkGetAttrMock.QIDs = []p9.QID{{}}
			rootFile.WalkGetAttrMock.File = file
			rootFile.WalkGetAttrMock.Attr = file.GetAttrMock.Attr
			rootFile.WalkGetAttrMock.Valid = file.GetAttrMock.Valid

			// Do the walk.
			dirent, err := rootDir.Walk(ctx, rootDir, name)
			if err != nil {
				t.Fatalf("Lookup(%q) failed: %v", name, err)
			}

			// Walk again. Depending on the cache policy, we may get a new
			// dirent.
			newDirent, err := rootDir.Walk(ctx, rootDir, name)
			if err != nil {
				t.Fatalf("Lookup(%q) failed: %v", name, err)
			}
			if test.preModificationWantReload && dirent == newDirent {
				t.Errorf("Lookup(%q) with cachePolicy=%s got old dirent %v, wanted a new dirent", name, test.cachePolicy, dirent)
			}
			if !test.preModificationWantReload && dirent != newDirent {
				t.Errorf("Lookup(%q) with cachePolicy=%s got new dirent %v, wanted old dirent %v", name, test.cachePolicy, newDirent, dirent)
			}

			// Modify the underlying mocked file's modification time.
			nowSeconds := time.Now().Unix()
			rootFile.WalkGetAttrMock.Attr.MTimeSeconds = uint64(nowSeconds)
			file.GetAttrMock.Attr.MTimeSeconds = uint64(nowSeconds)

			// Walk again. Depending on the cache policy, we may get a new
			// dirent.
			newDirent, err = rootDir.Walk(ctx, rootDir, name)
			if err != nil {
				t.Fatalf("Lookup(%q) failed: %v", name, err)
			}
			if test.postModificationWantReload && dirent == newDirent {
				t.Errorf("Lookup(%q) with cachePolicy=%s got old dirent %v, wanted a new dirent", name, test.cachePolicy, dirent)
			}
			if !test.postModificationWantReload && dirent != newDirent {
				t.Errorf("Lookup(%q) with cachePolicy=%s got new dirent %v, wanted old dirent %v", name, test.cachePolicy, newDirent, dirent)
			}
			uattrs, err := newDirent.Inode.UnstableAttr(ctx)
			if err != nil {
				t.Fatalf("Error getting unstable attrs: %v", err)
			}
			gotModTimeSeconds := uattrs.ModificationTime.Seconds()
			if test.postModificationWantUpdatedAttrs && gotModTimeSeconds != nowSeconds {
				t.Fatalf("Lookup(%q) with cachePolicy=%s got new modification time %v, wanted %v", name, test.cachePolicy, gotModTimeSeconds, nowSeconds)
			}

			// Make WalkGetAttr return ENOENT. This simulates
			// removing the file from the remote fs.
			rootFile.WalkGetAttrMock = p9test.WalkGetAttrMock{
				Err: syscall.ENOENT,
			}

			// Walk again. Depending on the cache policy, we may
			// get ENOENT.
			newDirent, err = rootDir.Walk(ctx, rootDir, name)
			if test.postRemovalWantReload && err == nil {
				t.Errorf("Lookup(%q) with cachePolicy=%s got nil error, wanted ENOENT", name, test.cachePolicy)
			}
			if !test.postRemovalWantReload && (err != nil || dirent != newDirent) {
				t.Errorf("Lookup(%q) with cachePolicy=%s got new dirent %v and error %v, wanted old dirent %v and nil error", name, test.cachePolicy, newDirent, err, dirent)
			}
		})
	}
}

func TestSetTimestamps(t *testing.T) {
	// Test parameters.
	type setTimestampsTest struct {
		// Name of the test.
		name string

		// Function input parameters.
		ts fs.TimeSpec
	}

	ctx := contexttest.Context(t)
	now := ktime.NowFromContext(ctx)
	tests := []setTimestampsTest{
		{
			name: "mock SetAttr passes (function succeeds)",
			ts: fs.TimeSpec{
				ATime: now,
				MTime: now,
			},
		},
		{
			name: "mock SetAttr passes, times are 0 (function succeeds)",
			ts:   fs.TimeSpec{},
		},
		{
			name: "mock SetAttr passes, times are 0 and not system time (function succeeds)",
			ts: fs.TimeSpec{
				ATimeSetSystemTime: false,
				MTimeSetSystemTime: false,
			},
		},
		{
			name: "mock SetAttr passes, times are set to system time (function succeeds)",
			ts: fs.TimeSpec{
				ATimeSetSystemTime: true,
				MTimeSetSystemTime: true,
			},
		},
		{
			name: "mock SetAttr passes, times are omitted (function succeeds)",
			ts: fs.TimeSpec{
				ATimeOmit: true,
				MTimeOmit: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up mock.
			rootFile, rootInode, err := root(ctx, cacheNone, p9.PermissionsMask, 0)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}

			// Call function.
			err = rootInode.SetTimestamps(ctx, nil /* Dirent */, test.ts)

			// Check return values.
			if err != nil {
				t.Errorf("SetTimestamps failed: got error %v, want nil", err)
			}

			// Check mock parameters.
			if !(test.ts.ATimeOmit && test.ts.MTimeOmit) && !rootFile.SetAttrMock.Called {
				t.Errorf("TestSetTimestamps failed: SetAttr not called")
				return
			}

			// Check what was passed to the mock function.
			attr := rootFile.SetAttrMock.Attr
			atimeGiven := ktime.FromUnix(int64(attr.ATimeSeconds), int64(attr.ATimeNanoSeconds))
			if test.ts.ATimeOmit {
				if rootFile.SetAttrMock.Valid.ATime {
					t.Errorf("ATime got set true in mask, wanted false")
				}
			} else {
				if got, want := rootFile.SetAttrMock.Valid.ATimeNotSystemTime, !test.ts.ATimeSetSystemTime; got != want {
					t.Errorf("got ATimeNotSystemTime %v, want %v", got, want)
				}
				if !test.ts.ATimeSetSystemTime && !test.ts.ATime.Equal(atimeGiven) {
					t.Errorf("ATime got %v, want %v", atimeGiven, test.ts.ATime)
				}
			}

			mtimeGiven := ktime.FromUnix(int64(attr.MTimeSeconds), int64(attr.MTimeNanoSeconds))
			if test.ts.MTimeOmit {
				if rootFile.SetAttrMock.Valid.MTime {
					t.Errorf("MTime got set true in mask, wanted false")
				}
			} else {
				if got, want := rootFile.SetAttrMock.Valid.MTimeNotSystemTime, !test.ts.MTimeSetSystemTime; got != want {
					t.Errorf("got MTimeNotSystemTime %v, want %v", got, want)
				}
				if !test.ts.MTimeSetSystemTime && !test.ts.MTime.Equal(mtimeGiven) {
					t.Errorf("MTime got %v, want %v", mtimeGiven, test.ts.MTime)
				}
			}
		})
	}
}

func TestSetPermissions(t *testing.T) {
	// Test parameters.
	type setPermissionsTest struct {
		// Name of the test.
		name string

		// SetPermissions input parameters.
		perms fs.FilePermissions

		// Error that SetAttr mock should return.
		setAttrErr error

		// Expected return value.
		want bool
	}

	tests := []setPermissionsTest{
		{
			name:       "SetAttr mock succeeds (function succeeds)",
			perms:      fs.FilePermissions{User: fs.PermMask{Read: true, Write: true, Execute: true}},
			want:       true,
			setAttrErr: nil,
		},
		{
			name:       "SetAttr mock fails (function fails)",
			perms:      fs.FilePermissions{User: fs.PermMask{Read: true, Write: true}},
			want:       false,
			setAttrErr: syscall.ENOENT,
		},
	}

	ctx := contexttest.Context(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up mock.
			rootFile, rootInode, err := root(ctx, cacheNone, 0, 0)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}
			rootFile.SetAttrMock.Err = test.setAttrErr

			ok := rootInode.SetPermissions(ctx, nil /* Dirent */, test.perms)

			// Check return value.
			if ok != test.want {
				t.Errorf("SetPermissions got %v, want %v", ok, test.want)
			}

			// Check mock parameters.
			pattr := rootFile.SetAttrMock.Attr
			if !rootFile.SetAttrMock.Called {
				t.Errorf("SetAttr not called")
				return
			}
			if !rootFile.SetAttrMock.Valid.Permissions {
				t.Errorf("SetAttr did not get right request (got false, expected SetAttrMask.Permissions true)")
			}
			if got := fs.FilePermsFromP9(pattr.Permissions); got != test.perms {
				t.Errorf("SetAttr did not get right permissions -- got %v, want %v", got, test.perms)
			}
		})
	}
}

func TestClose(t *testing.T) {
	ctx := contexttest.Context(t)
	// Set up mock.
	rootFile, rootInode, err := root(ctx, cacheNone, p9.PermissionsMask, 0)
	if err != nil {
		t.Fatalf("error creating root: %v", err)
	}

	// Call function.
	rootInode.InodeOperations.Release(ctx)

	// Check mock parameters.
	if !rootFile.CloseMock.Called {
		t.Errorf("TestClose failed: Close not called")
	}
}

func TestRename(t *testing.T) {
	// Test parameters.
	type renameTest struct {
		// Name of the test.
		name string

		// Input parameters.
		newParent *fs.Inode
		newName   string

		// Rename mock parameters.
		renameErr    error
		renameCalled bool

		// Error want to return given the parameters. (Same as what
		// we expect and tell rename to return.)
		want error
	}
	ctx := contexttest.Context(t)
	rootFile, rootInode, err := root(ctx, cacheNone, p9.PermissionsMask, 0)
	if err != nil {
		t.Fatalf("error creating root: %v", err)
	}

	tests := []renameTest{
		{
			name:         "mock Rename succeeds (function succeeds)",
			newParent:    rootInode,
			newName:      "foo2",
			want:         nil,
			renameErr:    nil,
			renameCalled: true,
		},
		{
			name:         "mock Rename fails (function fails)",
			newParent:    rootInode,
			newName:      "foo2",
			want:         syscall.ENOENT,
			renameErr:    syscall.ENOENT,
			renameCalled: true,
		},
		{
			name:         "newParent is not inodeOperations but should be (function fails)",
			newParent:    fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{Type: fs.Directory}),
			newName:      "foo2",
			want:         syscall.EXDEV,
			renameErr:    nil,
			renameCalled: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockFile := goodMockFile(p9.PermissionsMask, 0)
			rootFile.WalkGetAttrMock.QIDs = []p9.QID{{}}
			rootFile.WalkGetAttrMock.File = mockFile

			dirent, err := rootInode.Lookup(ctx, "foo")
			if err != nil {
				t.Fatalf("root.Walk failed: %v", err)
			}
			mockFile.RenameMock.Err = test.renameErr
			mockFile.RenameMock.Called = false

			// Use a dummy oldParent to acquire write access to that directory.
			oldParent := &inodeOperations{
				readdirCache: fs.NewSortedDentryMap(nil),
			}
			oldInode := fs.NewInode(oldParent, fs.NewMockMountSource(nil), fs.StableAttr{Type: fs.Directory})

			// Call function.
			err = dirent.Inode.InodeOperations.Rename(ctx, oldInode, "", test.newParent, test.newName)

			// Check return value.
			if err != test.want {
				t.Errorf("Rename got %v, want %v", err, test.want)
			}

			// Check mock parameters.
			if got, want := mockFile.RenameMock.Called, test.renameCalled; got != want {
				t.Errorf("renameCalled got %v want %v", got, want)
			}
		})
	}
}

// This file is read from in TestPreadv.
type readAtFileFake struct {
	p9test.FileMock

	// Parameters for faking ReadAt.
	FileLength int
	Err        error
	ChunkSize  int
	Called     bool
	LengthRead int
}

func (r *readAtFileFake) ReadAt(p []byte, offset uint64) (int, error) {
	r.Called = true
	log.Warningf("ReadAt fake: length read so far = %d, len(p) = %d, offset = %d", r.LengthRead, len(p), offset)
	if int(offset) != r.LengthRead {
		return 0, fmt.Errorf("offset got %d; expected %d", offset, r.LengthRead)
	}

	if r.Err != nil {
		return 0, r.Err
	}

	if r.LengthRead >= r.FileLength {
		return 0, io.EOF
	}

	// Read at most ChunkSize and read at most what's left in the file.
	toBeRead := len(p)
	if r.LengthRead+toBeRead >= r.FileLength {
		toBeRead = r.FileLength - int(offset)
	}
	if toBeRead > r.ChunkSize {
		toBeRead = r.ChunkSize
	}

	r.LengthRead += toBeRead
	if r.LengthRead == r.FileLength {
		return toBeRead, io.EOF
	}
	return toBeRead, nil
}

func TestPreadv(t *testing.T) {
	// Test parameters.
	type preadvTest struct {
		// Name of the test.
		name string

		// Mock parameters
		mode p9.FileMode

		// Buffer to read into.
		buffer    [512]byte
		sliceSize int

		// How much readAt returns at a time.
		chunkSize int

		// Whether or not we expect ReadAt to be called.
		readAtCalled bool
		readAtErr    error

		// Expected return values.
		want error
	}

	tests := []preadvTest{
		{
			name:         "fake ReadAt succeeds, 512 bytes requested, 512 byte chunks (function succeeds)",
			want:         nil,
			readAtErr:    nil,
			mode:         p9.PermissionsMask,
			readAtCalled: true,
			sliceSize:    512,
			chunkSize:    512,
		},
		{
			name:         "fake ReadAt succeeds, 512 bytes requested, 200 byte chunks (function succeeds)",
			want:         nil,
			readAtErr:    nil,
			mode:         p9.PermissionsMask,
			readAtCalled: true,
			sliceSize:    512,
			chunkSize:    200,
		},
		{
			name:         "fake ReadAt succeeds, 0 bytes requested (function succeeds)",
			want:         nil,
			readAtErr:    nil,
			mode:         p9.PermissionsMask,
			readAtCalled: false,
			sliceSize:    0,
			chunkSize:    100,
		},
		{
			name:         "fake ReadAt returns 0 bytes and EOF (function fails)",
			want:         io.EOF,
			readAtErr:    io.EOF,
			mode:         p9.PermissionsMask,
			readAtCalled: true,
			sliceSize:    512,
			chunkSize:    512,
		},
	}

	ctx := contexttest.Context(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up mock.
			rootFile, rootInode, err := root(ctx, cacheNone, test.mode, 1024)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}

			// Set up the read buffer.
			dst := usermem.BytesIOSequence(test.buffer[:test.sliceSize])

			// This file will be read from.
			openFile := &readAtFileFake{
				Err:        test.readAtErr,
				FileLength: test.sliceSize,
				ChunkSize:  test.chunkSize,
			}
			rootFile.WalkGetAttrMock.File = openFile
			rootFile.WalkGetAttrMock.Attr.Mode = test.mode
			rootFile.WalkGetAttrMock.Valid.Mode = true

			f := NewFile(
				ctx,
				fs.NewDirent(rootInode, ""),
				"",
				fs.FileFlags{Read: true},
				rootInode.InodeOperations.(*inodeOperations),
				&handles{File: contextFile{file: openFile}},
			)

			// Call function.
			_, err = f.Preadv(ctx, dst, 0)

			// Check return value.
			if err != test.want {
				t.Errorf("Preadv got %v, want %v", err, test.want)
			}

			// Check mock parameters.
			if test.readAtCalled != openFile.Called {
				t.Errorf("ReadAt called: %v, but expected opposite", openFile.Called)
			}
		})
	}
}

func TestReadlink(t *testing.T) {
	// Test parameters.
	type readlinkTest struct {
		// Name of the test.
		name string

		// Mock parameters
		mode p9.FileMode

		// Whether or not we expect ReadAt to be called and what error
		// it shall return.
		readlinkCalled bool
		readlinkErr    error

		// Expected return values.
		want error
	}

	tests := []readlinkTest{
		{
			name:           "file is not symlink (function fails)",
			want:           syscall.ENOLINK,
			mode:           p9.PermissionsMask,
			readlinkCalled: false,
			readlinkErr:    nil,
		},
		{
			name:           "mock Readlink succeeds (function succeeds)",
			want:           nil,
			mode:           p9.PermissionsMask | p9.ModeSymlink,
			readlinkCalled: true,
			readlinkErr:    nil,
		},
		{
			name:           "mock Readlink fails (function fails)",
			want:           syscall.ENOENT,
			mode:           p9.PermissionsMask | p9.ModeSymlink,
			readlinkCalled: true,
			readlinkErr:    syscall.ENOENT,
		},
	}

	ctx := contexttest.Context(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up mock.
			rootFile, rootInode, err := root(ctx, cacheNone, test.mode, 0)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}

			openFile := goodMockFile(test.mode, 0)
			rootFile.WalkMock.File = openFile
			rootFile.ReadlinkMock.Err = test.readlinkErr

			// Call function.
			_, err = rootInode.Readlink(ctx)

			// Check return value.
			if err != test.want {
				t.Errorf("Readlink got %v, want %v", err, test.want)
			}

			// Check mock parameters.
			if test.readlinkCalled && !rootFile.ReadlinkMock.Called {
				t.Errorf("Readlink not called")
			}
		})
	}
}

// This file is write from in TestPwritev.
type writeAtFileFake struct {
	p9test.FileMock

	// Parameters for faking WriteAt.
	Err           error
	ChunkSize     int
	Called        bool
	LengthWritten int
}

func (r *writeAtFileFake) WriteAt(p []byte, offset uint64) (int, error) {
	r.Called = true
	log.Warningf("WriteAt fake: length written so far = %d, len(p) = %d, offset = %d", r.LengthWritten, len(p), offset)
	if int(offset) != r.LengthWritten {
		return 0, fmt.Errorf("offset got %d; want %d", offset, r.LengthWritten)
	}

	if r.Err != nil {
		return 0, r.Err
	}

	// Write at most ChunkSize.
	toBeWritten := len(p)
	if toBeWritten > r.ChunkSize {
		toBeWritten = r.ChunkSize
	}
	r.LengthWritten += toBeWritten
	return toBeWritten, nil
}

func TestPwritev(t *testing.T) {
	// Test parameters.
	type pwritevTest struct {
		// Name of the test.
		name string

		// Mock parameters
		mode p9.FileMode

		allowWrite bool

		// Buffer to write into.
		buffer    [512]byte
		sliceSize int
		chunkSize int

		// Whether or not we expect writeAt to be called.
		writeAtCalled bool
		writeAtErr    error

		// Expected return values.
		want error
	}

	tests := []pwritevTest{
		{
			name:          "fake writeAt succeeds, one chunk (function succeeds)",
			want:          nil,
			writeAtErr:    nil,
			mode:          p9.PermissionsMask,
			allowWrite:    true,
			writeAtCalled: true,
			sliceSize:     512,
			chunkSize:     512,
		},
		{
			name:          "fake writeAt fails, short write (function fails)",
			want:          io.ErrShortWrite,
			writeAtErr:    nil,
			mode:          p9.PermissionsMask,
			allowWrite:    true,
			writeAtCalled: true,
			sliceSize:     512,
			chunkSize:     200,
		},
		{
			name:          "fake writeAt succeeds, len 0 (function succeeds)",
			want:          nil,
			writeAtErr:    nil,
			mode:          p9.PermissionsMask,
			allowWrite:    true,
			writeAtCalled: false,
			sliceSize:     0,
			chunkSize:     0,
		},
		{
			name:          "writeAt can still write despite file permissions read only (function succeeds)",
			want:          nil,
			writeAtErr:    nil,
			mode:          p9.PermissionsMask,
			allowWrite:    false,
			writeAtCalled: true,
			sliceSize:     512,
			chunkSize:     512,
		},
	}

	ctx := contexttest.Context(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up mock.
			_, rootInode, err := root(ctx, cacheNone, test.mode, 0)
			if err != nil {
				t.Fatalf("error creating root: %v", err)
			}

			src := usermem.BytesIOSequence(test.buffer[:test.sliceSize])

			// This is the file that will be used for writing.
			openFile := &writeAtFileFake{
				Err:       test.writeAtErr,
				ChunkSize: test.chunkSize,
			}

			f := NewFile(
				ctx,
				fs.NewDirent(rootInode, ""),
				"",
				fs.FileFlags{Write: true},
				rootInode.InodeOperations.(*inodeOperations),
				&handles{File: contextFile{file: openFile}},
			)

			// Call function.
			_, err = f.Pwritev(ctx, src, 0)

			// Check return value.
			if err != test.want {
				t.Errorf("Pwritev got %v, want %v", err, test.want)
			}

			// Check mock parameters.
			if test.writeAtCalled != openFile.Called {
				t.Errorf("WriteAt called: %v, but expected opposite", openFile.Called)
				return
			}
			if openFile.Called && test.writeAtErr != nil && openFile.LengthWritten != test.sliceSize {
				t.Errorf("wrote %d bytes, expected %d bytes written", openFile.LengthWritten, test.sliceSize)
			}
		})
	}
}
