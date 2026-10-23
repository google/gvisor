// Copyright 2020 The gVisor Authors.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func TestDestroyIdempotent(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := filesystem{
		mf:         pgalloc.MemoryFileFromContext(ctx),
		inoByKey:   make(map[inoKey]uint64),
		inodeByKey: make(map[inoKey]*inode),
		clock:      ktime.RealtimeClockFromContext(ctx),
		// Test relies on no dentry being held in the cache.
		dentryCache: &dentryCache{maxCachedDentries: 0},
		client:      &lisafs.Client{},
	}

	parentInode := lisafs.Inode{
		ControlFD: 1,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE,
			Mode: linux.S_IFDIR | 0666,
		},
	}
	parent, err := fs.newLisafsDentry(ctx, &parentInode)
	if err != nil {
		t.Fatalf("fs.newDentry(): %v", err)
	}

	childInode := lisafs.Inode{
		ControlFD: 2,
		Stat: lisafs.Statx{
			Mask: linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_SIZE,
			Mode: linux.S_IFREG | 0666,
			Size: 0,
		},
	}

	child, err := fs.newLisafsDentry(ctx, &childInode)
	if err != nil {
		t.Fatalf("fs.newDentry(): %v", err)
	}
	parent.opMu.Lock()
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, "child")
	parent.childrenMu.Unlock()
	parent.opMu.Unlock()

	fs.renameMu.Lock()
	defer fs.renameMu.Unlock()
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	if got := child.refs.Load(); got != -1 {
		t.Fatalf("child.refs=%d, want: -1", got)
	}
	// Parent will also be destroyed when child reference is removed.
	if got := parent.refs.Load(); got != -1 {
		t.Fatalf("parent.refs=%d, want: -1", got)
	}
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
}

func TestStringFixedCache(t *testing.T) {
	names := []string{"a", "b", "c"}
	cache := stringFixedCache{}

	cache.init(uint64(len(names)))
	if inited := cache.isInited(); !inited {
		t.Fatalf("cache.isInited(): %v, want: true", inited)
	}
	for _, s := range names {
		victim := cache.add(s)
		if victim != "" {
			t.Fatalf("cache.add(): %v, want: \"\"", victim)
		}
	}
	for _, s := range names {
		victim := cache.add("something")
		if victim != s {
			t.Fatalf("cache.add(): %v, want: %v", victim, s)
		}
	}
}

func TestXattrCacheValues(t *testing.T) {
	ino := &inode{}

	// 1. Initial state
	if _, _, found := ino.xattrCache.get("user.foo"); found {
		t.Errorf("get(user.foo) got found=true, want false")
	}

	// 2. Cache present xattr
	ino.xattrCache.add("user.foo", "bar")
	val, negative, found := ino.xattrCache.get("user.foo")
	if !found || negative || val != "bar" {
		t.Errorf("get(user.foo) = (%q, %v, %v), want (%q, false, true)", val, negative, found, "bar")
	}

	// 3. Cache negative xattr
	ino.xattrCache.addNegative("user.neg")
	val, negative, found = ino.xattrCache.get("user.neg")
	if !found || !negative || val != "" {
		t.Errorf("get(user.neg) = (%q, %v, %v), want (%q, true, true)", val, negative, found, "")
	}

	// Overwrite negative xattr with present xattr
	ino.xattrCache.add("user.neg", "baz")
	val, negative, found = ino.xattrCache.get("user.neg")
	if !found || negative || val != "baz" {
		t.Errorf("get(user.neg) = (%q, %v, %v), want (%q, false, true)", val, negative, found, "baz")
	}

	// 4. Overlay opaque xattr
	ino.xattrCache.addNegative(xattrOverlayOpaque)
	val, negative, found = ino.xattrCache.get(xattrOverlayOpaque)
	if !found || !negative || val != "" {
		t.Errorf("get(xattrOverlayOpaque) = (%q, %v, %v), want (%q, true, true)", val, negative, found, "")
	}

	// Overwrite overlay opaque xattr with present xattr
	ino.xattrCache.add(xattrOverlayOpaque, "y")
	val, negative, found = ino.xattrCache.get(xattrOverlayOpaque)
	if !found || negative || val != "y" {
		t.Errorf("get(xattrOverlayOpaque) = (%q, %v, %v), want (%q, false, true)", val, negative, found, "y")
	}
}

func TestXattrCacheList(t *testing.T) {
	ino := &inode{}

	// 1. Initial state
	if _, found := ino.xattrCache.getList(); found {
		t.Errorf("getList() got found=true, want false")
	}

	// 2. Cache empty list
	ino.xattrCache.setList([]string{})
	list, found := ino.xattrCache.getList()
	if !found || len(list) != 0 {
		t.Errorf("getList() = (%v, %v), want ([], true)", list, found)
	}

	// 3. Cache non-empty list
	initialList := []string{"user.foo", "user.bar"}
	ino.xattrCache.setList(initialList)
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, initialList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, initialList)
	}

	// 4. Cache new xattr updates list
	ino.xattrCache.add("user.baz", "val")
	wantList := []string{"user.foo", "user.bar", "user.baz"}
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, wantList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, wantList)
	}

	// 5. Cache existing xattr does not duplicate in list
	ino.xattrCache.add("user.foo", "val2")
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, wantList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, wantList)
	}

	// 6. Cache negative xattr removes from list
	ino.xattrCache.addNegative("user.bar")
	wantList = []string{"user.foo", "user.baz"}
	list, found = ino.xattrCache.getList()
	if !found || !slices.Equal(list, wantList) {
		t.Errorf("getList() = (%v, %v), want (%v, true)", list, found, wantList)
	}
}

func TestWrapRestoreError(t *testing.T) {
	corruptionErrs := []error{
		unix.ENOENT,
		linuxerr.ENOENT,
		unix.EACCES,
		linuxerr.EACCES,
		unix.ENOTDIR,
		linuxerr.ENOTDIR,
		unix.EISDIR,
		linuxerr.EISDIR,
		unix.ESTALE,
		linuxerr.ESTALE,
	}
	for _, err := range corruptionErrs {
		wrapped := fmt.Errorf("restore failed: %w", err)
		got := wrapRestoreError(err, wrapped)
		var corruption vfs.ErrCorruption
		if !errors.As(got, &corruption) {
			t.Errorf("wrapRestoreError(%v) = %T (%v), want vfs.ErrCorruption", err, got, got)
		}
	}

	nonCorruptionErrs := []error{
		unix.EIO,
		linuxerr.EIO,
		unix.EINVAL,
		linuxerr.EINVAL,
	}
	for _, err := range nonCorruptionErrs {
		wrapped := fmt.Errorf("restore failed: %w", err)
		got := wrapRestoreError(err, wrapped)
		var corruption vfs.ErrCorruption
		if errors.As(got, &corruption) {
			t.Errorf("wrapRestoreError(%v) = %T (%v), did not want vfs.ErrCorruption", err, got, got)
		}
	}
}

func TestSpecialFileFDCompleteRestoreWrapsCorruptionError(t *testing.T) {
	ctx := contexttest.Context(t)
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init(): %v", err)
	}
	fs := &filesystem{
		mf:          pgalloc.MemoryFileFromContext(ctx),
		inoByKey:    make(map[inoKey]uint64),
		inodeByKey:  make(map[inoKey]*inode),
		clock:       ktime.RealtimeClockFromContext(ctx),
		dentryCache: &dentryCache{maxCachedDentries: 0},
	}
	fs.vfsfs.Init(&vfsObj, &FilesystemType{}, fs)

	// Simulate a shared mount under CACHE_MODE_NONE
	// (regularFilesUseSpecialFileFD) where a file was opened O_RDWR before
	// save, then chmod 0444 by an external actor before restore.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0444); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("unix.Open(%q): %v", dir, err)
	}
	defer unix.Close(dirFD)

	parentInode := &directfsInode{
		inode: inode{
			fs:      fs,
			mode:    atomicbitops.FromUint32(linux.S_IFDIR | 0755),
			readFD:  atomicbitops.FromInt32(-1),
			writeFD: atomicbitops.FromInt32(-1),
			mmapFD:  atomicbitops.FromInt32(-1),
		},
		controlFD: dirFD,
	}
	parentInode.inode.init(parentInode)
	parent := &dentry{
		name:  "",
		inode: &parentInode.inode,
	}
	parent.init()

	di := &directfsInode{
		inode: inode{
			fs:      fs,
			mode:    atomicbitops.FromUint32(linux.S_IFREG | 0444),
			readFD:  atomicbitops.FromInt32(-1),
			writeFD: atomicbitops.FromInt32(-1),
			mmapFD:  atomicbitops.FromInt32(-1),
		},
		controlFD: -1,
	}
	di.inode.init(di)
	d := &dentry{
		name:  "locked.txt",
		inode: &di.inode,
	}
	d.init()
	d.parent.Store(parent)

	var fd specialFileFD
	mnt := vfsObj.NewDisconnectedMount(&fs.vfsfs, &parent.vfsd, &vfs.MountOptions{})
	if err := fd.vfsfd.Init(&fd, linux.O_RDWR, auth.CredentialsFromContext(ctx), mnt, &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		t.Fatalf("fd.vfsfd.Init(): %v", err)
	}

	err = fd.completeRestore(ctx)
	var corruption vfs.ErrCorruption
	if !errors.As(err, &corruption) {
		t.Errorf("specialFileFD.completeRestore() = %T (%v), want vfs.ErrCorruption", err, err)
	}
}
