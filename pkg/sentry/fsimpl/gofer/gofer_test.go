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
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
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
		// There is no VFS to allocate device numbers from.
		devMinorByHostDev: map[uint64]uint32{0: 1},
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

func TestValidateRestoredFileType(t *testing.T) {
	for _, test := range []struct {
		name         string
		savedMode    uint32
		savedRdev    [2]uint32 // major, minor
		restoredMode uint32
		restoredRdev [2]uint32 // major, minor
		wantErr      bool
	}{
		{
			name:         "RegularFile",
			savedMode:    linux.S_IFREG | 0644,
			restoredMode: linux.S_IFREG | 0600,
		},
		{
			name:         "Directory",
			savedMode:    linux.S_IFDIR | 0755,
			restoredMode: linux.S_IFDIR | 0755,
		},
		{
			name:         "CharDevice",
			savedMode:    linux.S_IFCHR | 0666,
			savedRdev:    [2]uint32{1, 3},
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{1, 3},
		},
		{
			name:         "RegularFileReplacedByDirectory",
			savedMode:    linux.S_IFREG | 0644,
			restoredMode: linux.S_IFDIR | 0755,
			wantErr:      true,
		},
		{
			name:         "DirectoryReplacedBySymlink",
			savedMode:    linux.S_IFDIR | 0755,
			restoredMode: linux.S_IFLNK | 0777,
			wantErr:      true,
		},
		{
			name:         "FIFOReplacedByCharDevice",
			savedMode:    linux.S_IFIFO | 0644,
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{1, 3},
			wantErr:      true,
		},
		{
			name:         "RegularFileReplacedByBlockDevice",
			savedMode:    linux.S_IFREG | 0644,
			restoredMode: linux.S_IFBLK | 0660,
			restoredRdev: [2]uint32{8, 0},
			wantErr:      true,
		},
		{
			name:         "BlockDevice",
			savedMode:    linux.S_IFBLK | 0660,
			savedRdev:    [2]uint32{8, 0},
			restoredMode: linux.S_IFBLK | 0660,
			restoredRdev: [2]uint32{8, 0},
			wantErr:      true,
		},
		{
			name:         "CharDeviceMajorChanged",
			savedMode:    linux.S_IFCHR | 0666,
			savedRdev:    [2]uint32{1, 3},
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{4, 3},
			wantErr:      true,
		},
		{
			name:         "CharDeviceMinorChanged",
			savedMode:    linux.S_IFCHR | 0666,
			savedRdev:    [2]uint32{1, 3},
			restoredMode: linux.S_IFCHR | 0666,
			restoredRdev: [2]uint32{1, 5},
			wantErr:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			i := &inode{
				fs:        &filesystem{},
				mode:      atomicbitops.FromUint32(test.savedMode),
				rdevMajor: test.savedRdev[0],
				rdevMinor: test.savedRdev[1],
			}
			d := &dentry{inode: i}
			err := i.validateRestoredFileType(test.restoredMode, test.restoredRdev[0], test.restoredRdev[1], d)
			if !test.wantErr {
				if err != nil {
					t.Errorf("validateRestoredFileType(%#o, %d, %d) = %v, want nil", test.restoredMode, test.restoredRdev[0], test.restoredRdev[1], err)
				}
				return
			}
			var corruption vfs.ErrCorruption
			if !errors.As(err, &corruption) {
				t.Errorf("validateRestoredFileType(%#o, %d, %d) = %v, want vfs.ErrCorruption", test.restoredMode, test.restoredRdev[0], test.restoredRdev[1], err)
			}
		})
	}
}
