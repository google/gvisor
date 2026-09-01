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
	"slices"
	"testing"

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

// TestReleaseInoOnDeletion verifies that deleting a file retires its sentry
// inode number, so that a later file the host gives the same inode key mints
// a fresh number — a Landlock rule keyed by the deleted file's identity must
// not match the new file — while a file that still has hard links keeps its
// number.
func TestReleaseInoOnDeletion(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := filesystem{
		mf:          pgalloc.MemoryFileFromContext(ctx),
		inoByKey:    make(map[inoKey]uint64),
		inodeByKey:  make(map[inoKey]*inode),
		clock:       ktime.RealtimeClockFromContext(ctx),
		dentryCache: &dentryCache{maxCachedDentries: 0},
		client:      &lisafs.Client{},
	}

	newFile := func(controlFD lisafs.FDID, hostIno uint64, nlink uint32) *dentry {
		t.Helper()
		d, err := fs.newLisafsDentry(ctx, &lisafs.Inode{
			ControlFD: controlFD,
			Stat: lisafs.Statx{
				Mask:  linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_SIZE | linux.STATX_INO | linux.STATX_NLINK,
				Mode:  linux.S_IFREG | 0666,
				Ino:   hostIno,
				Nlink: nlink,
			},
		})
		if err != nil {
			t.Fatalf("fs.newLisafsDentry(): %v", err)
		}
		return d
	}

	// A singly-linked file: deletion retires its number.
	const hostIno = 42
	key := inoKey{ino: hostIno}
	a := newFile(1, hostIno, 1)
	inoA := a.inode.ino
	if got, ok := fs.inoByKey[key]; !ok || got != inoA {
		t.Fatalf("fs.inoByKey[%+v] = %d, %t; want %d, true", key, got, ok, inoA)
	}
	a.setDeleted()
	a.decLinks()
	a.releaseInoOnDeletion()
	if _, ok := fs.inoByKey[key]; ok {
		t.Errorf("fs.inoByKey still maps %+v after deletion of the last link", key)
	}
	if _, ok := fs.inodeByKey[key]; ok {
		t.Errorf("fs.inodeByKey still maps %+v after deletion of the last link", key)
	}

	// A new file with the recycled host inode number must get a fresh sentry
	// number and a fresh inode.
	b := newFile(2, hostIno, 1)
	if b.inode.ino == inoA {
		t.Errorf("recycled host inode %d inherited retired sentry ino %d", hostIno, inoA)
	}
	if b.inode == a.inode {
		t.Errorf("recycled host inode %d shares the deleted file's inode", hostIno)
	}

	// A file with a surviving hard link keeps its number until the last link
	// is removed.
	const hostIno2 = 43
	key2 := inoKey{ino: hostIno2}
	c := newFile(3, hostIno2, 2)
	inoC := c.inode.ino
	c.setDeleted()
	c.decLinks()
	c.releaseInoOnDeletion()
	if got, ok := fs.inoByKey[key2]; !ok || got != inoC {
		t.Errorf("fs.inoByKey[%+v] = %d, %t after unlink with a surviving link; want %d, true", key2, got, ok, inoC)
	}
	// The last link goes away.
	c.decLinks()
	c.releaseInoOnDeletion()
	if _, ok := fs.inoByKey[key2]; ok {
		t.Errorf("fs.inoByKey still maps %+v after deletion of the last link", key2)
	}
}

// TestPinnedDentrySurvivesEviction verifies that a dentry pinned by
// PinInodeIdentity keeps its reference — and with it its sentry inode
// number — across dentry cache eviction, while an unpinned dentry is
// destroyed, and that re-pinning is idempotent.
func TestPinnedDentrySurvivesEviction(t *testing.T) {
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

	newFile := func(controlFD lisafs.FDID, hostIno uint64) *dentry {
		t.Helper()
		d, err := fs.newLisafsDentry(ctx, &lisafs.Inode{
			ControlFD: controlFD,
			Stat: lisafs.Statx{
				Mask:  linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_SIZE | linux.STATX_INO | linux.STATX_NLINK,
				Mode:  linux.S_IFREG | 0666,
				Ino:   hostIno,
				Nlink: 1,
			},
		})
		if err != nil {
			t.Fatalf("fs.newLisafsDentry(): %v", err)
		}
		return d
	}

	pinned := newFile(1, 42)
	pinned.PinInodeIdentity()
	pinnedIno := pinned.inode.ino
	victim := newFile(2, 43)

	fs.renameMu.Lock()
	pinned.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	victim.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	fs.evictAllCachedDentriesLocked(ctx)
	fs.renameMu.Unlock()

	if got := victim.refs.Load(); got != -1 {
		t.Errorf("unpinned dentry was not destroyed: refs=%d, want -1", got)
	}
	if got := pinned.refs.Load(); got != 1 {
		t.Errorf("pinned dentry did not survive eviction: refs=%d, want 1", got)
	}
	if pinned.inode.ino != pinnedIno {
		t.Errorf("pinned dentry ino changed: got %d, want %d", pinned.inode.ino, pinnedIno)
	}
	if got, ok := fs.inoByKey[inoKey{ino: 42}]; !ok || got != pinnedIno {
		t.Errorf("fs.inoByKey[{ino: 42}] = %d, %t; want %d, true", got, ok, pinnedIno)
	}

	// Pinning is idempotent: re-pinning must not accumulate references.
	pinned.PinInodeIdentity()
	if got := pinned.refs.Load(); got != 1 {
		t.Errorf("re-pinning changed refs: got %d, want 1", got)
	}
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
