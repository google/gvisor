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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
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

func TestDirectfsOpenHandleDetectsRenameExchange(t *testing.T) {
	ctx := contexttest.Context(t)
	dir := t.TempDir()
	tempPath := filepath.Join(dir, "temp")
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(tempPath, []byte("temp"), 0666); err != nil {
		t.Fatalf("WriteFile(temp): %v", err)
	}
	const wantSecret = "secret-content-must-not-be-truncated"
	if err := os.WriteFile(secretPath, []byte(wantSecret), 0600); err != nil {
		t.Fatalf("WriteFile(secret): %v", err)
	}
	fs := filesystem{
		mf:          pgalloc.MemoryFileFromContext(ctx),
		inoByKey:    make(map[inoKey]uint64),
		inodeByKey:  make(map[inoKey]*inode),
		clock:       ktime.RealtimeClockFromContext(ctx),
		dentryCache: &dentryCache{maxCachedDentries: 0},
		client:      &lisafs.Client{},
	}
	dirFD, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("unix.Open(dir): %v", err)
	}
	parent, err := fs.newDirectfsDentry(dirFD)
	if err != nil {
		t.Fatalf("newDirectfsDentry(dir): %v", err)
	}
	tempFD, err := unix.Open(tempPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("unix.Open(temp): %v", err)
	}
	child, err := fs.newDirectfsDentry(tempFD)
	if err != nil {
		t.Fatalf("newDirectfsDentry(temp): %v", err)
	}
	parent.opMu.Lock()
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, "temp")
	parent.childrenMu.Unlock()
	parent.opMu.Unlock()
	// Simulate the TOCTOU race between permission check and openHandle():
	// swap "temp" and "secret" on the host using RENAME_EXCHANGE.
	if err := unix.Renameat2(unix.AT_FDCWD, tempPath, unix.AT_FDCWD, secretPath, unix.RENAME_EXCHANGE); err != nil {
		t.Fatalf("Renameat2(RENAME_EXCHANGE): %v", err)
	}
	fs.renameMu.RLock()
	h, openErr := child.inode.impl.(*directfsInode).openHandle(ctx, unix.O_RDWR|unix.O_TRUNC, child)
	fs.renameMu.RUnlock()
	if openErr == nil {
		_ = unix.Close(int(h.fd))
		t.Fatalf("openHandle() succeeded on swapped inode; want error")
	}
	// Verify that O_TRUNC did not truncate the swapped secret file (now at tempPath).
	gotSecret, err := os.ReadFile(tempPath)
	if err != nil {
		t.Fatalf("ReadFile(swapped secret): %v", err)
	}
	if string(gotSecret) != wantSecret {
		t.Errorf("secret file content = %q, want %q (file was truncated!)", string(gotSecret), wantSecret)
	}
}
