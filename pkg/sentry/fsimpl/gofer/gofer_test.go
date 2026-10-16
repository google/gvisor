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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
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

func newTestFilesystem(ctx context.Context, interop InteropMode) *filesystem {
	return &filesystem{
		opts:          filesystemOptions{interop: interop},
		mf:            pgalloc.MemoryFileFromContext(ctx),
		inoByKey:      make(map[inoKey]uint64),
		inodeByKey:    make(map[inoKey]*inode),
		savedDentryRW: make(map[*dentry]savedDentryRW),
		clock:         ktime.RealtimeClockFromContext(ctx),
		dentryCache:   &dentryCache{maxCachedDentries: 0},
		client:        &lisafs.Client{},
	}
}

func initTestDentry(ino *inode, impl any, fs *filesystem, parent *dentry, name string, mode uint32) *dentry {
	*ino = inode{
		fs:      fs,
		ino:     fs.nextIno(),
		mode:    atomicbitops.FromUint32(mode),
		uid:     atomicbitops.FromUint32(uint32(os.Geteuid())),
		gid:     atomicbitops.FromUint32(uint32(os.Getegid())),
		readFD:  atomicbitops.FromInt32(-1),
		writeFD: atomicbitops.FromInt32(-1),
		mmapFD:  atomicbitops.FromInt32(-1),
	}
	ino.init(impl)
	d := &dentry{name: name, inode: ino}
	d.init()
	d.parent.Store(parent)
	return d
}

func newTestDirectfsDentry(t *testing.T, fs *filesystem, parent *dentry, name string, mode uint32, controlFD int) (*directfsInode, *dentry) {
	t.Helper()
	di := &directfsInode{controlFD: controlFD}
	t.Cleanup(func() {
		if di.controlFD >= 0 {
			_ = unix.Close(di.controlFD)
		}
	})
	return di, initTestDentry(&di.inode, di, fs, parent, name, mode)
}

func openTestFD(t *testing.T, path string, flags int) int {
	t.Helper()
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0644)
	if err != nil {
		t.Fatalf("unix.Open(%q): %v", path, err)
	}
	return fd
}

func newTestDirectfsEnv(ctx context.Context, t *testing.T, interop InteropMode) (string, *filesystem, *dentry) {
	t.Helper()
	dir := t.TempDir()
	fs := newTestFilesystem(ctx, interop)
	_, parent := newTestDirectfsDentry(t, fs, nil, "", linux.S_IFDIR|0755, openTestFD(t, dir, unix.O_RDONLY|unix.O_DIRECTORY))
	return dir, fs, parent
}

func newNotDirEnv(ctx context.Context, t *testing.T, interop InteropMode) (*filesystem, *dentry) {
	t.Helper()
	fs := newTestFilesystem(ctx, interop)
	_, parent := newTestDirectfsDentry(t, fs, nil, "", linux.S_IFDIR|0755, openTestFD(t, filepath.Join(t.TempDir(), "not_a_dir"), unix.O_CREAT|unix.O_RDONLY))
	return fs, parent
}

func requireOuterErrCorruption(t *testing.T, got, wantInner error, wantSubstrs ...string) {
	t.Helper()
	corruption, ok := got.(vfs.ErrCorruption)
	if !ok {
		t.Fatalf("got %T (%v), want outermost vfs.ErrCorruption", got, got)
	}
	if corruption.Err == nil {
		t.Fatalf("got vfs.ErrCorruption with nil inner error")
	}
	// cloud/gvisor/sentry/app/app.go type-switches on concrete vfs.ErrCorruption.
	prepended := vfs.PrependErrMsg("vfs.CompleteRestore() failed", vfs.PrependErrMsg("failed to complete restore", got))
	if _, ok := prepended.(vfs.ErrCorruption); !ok {
		t.Fatalf("vfs.PrependErrMsg(%T) = %T (%v), want outermost vfs.ErrCorruption", got, prepended, prepended)
	}
	if wantInner != nil && !errors.Is(corruption.Err, wantInner) {
		t.Errorf("inner error = %v, want %v", corruption.Err, wantInner)
	}
	for _, sub := range wantSubstrs {
		if !strings.Contains(corruption.Err.Error(), sub) {
			t.Errorf("inner error = %q, want substring %q", corruption.Err.Error(), sub)
		}
	}
}

func TestDirectfsRestoreFileCorruptionErrors(t *testing.T) {
	ctx := contexttest.Context(t)
	t.Run("missing_file", func(t *testing.T) {
		_, fs, parent := newTestDirectfsEnv(ctx, t, InteropModeShared)
		_, d := newTestDirectfsDentry(t, fs, parent, "missing.txt", linux.S_IFREG|0644, -1)
		requireOuterErrCorruption(t, d.restoreFile(ctx, &vfs.CompleteRestoreOptions{}), unix.ENOENT, "failed to walk")
	})
	t.Run("mountpoint_recreate_fails", func(t *testing.T) {
		fs, parent := newNotDirEnv(ctx, t, InteropModeShared)
		_, d := newTestDirectfsDentry(t, fs, parent, "mnt", linux.S_IFDIR|0755, -1)
		d.forMountpoint = true
		requireOuterErrCorruption(t, d.restoreFile(ctx, &vfs.CompleteRestoreOptions{}), unix.ENOTDIR, "create mountpoint directory")
	})
	for _, tc := range []struct {
		name    string
		interop InteropMode
	}{
		{name: "exclusive", interop: InteropModeExclusive},
		{name: "shared", interop: InteropModeShared},
	} {
		t.Run("file_type_mismatch_"+tc.name, func(t *testing.T) {
			dir, fs, parent := newTestDirectfsEnv(ctx, t, tc.interop)
			childFD := openTestFD(t, dir, unix.O_RDONLY|unix.O_DIRECTORY)
			di, d := newTestDirectfsDentry(t, fs, parent, "replaced_by_dir", linux.S_IFREG|0644, -1)
			requireOuterErrCorruption(t, di.restoreFile(ctx, childFD, &vfs.CompleteRestoreOptions{}, d), nil, "file type changed")
			if di.controlFD != -1 {
				t.Errorf("di.controlFD = %d, want -1", di.controlFD)
			}
			if _, fdErr := unix.FcntlInt(uintptr(childFD), unix.F_GETFD, 0); !errors.Is(fdErr, unix.EBADF) {
				_ = unix.Close(childFD)
				t.Errorf("childFD still open after file-type mismatch (fcntl err = %v), want EBADF", fdErr)
			}
			if len(fs.inoByKey) != 0 || len(fs.inodeByKey) != 0 {
				t.Errorf("len(inoByKey)=%d, len(inodeByKey)=%d, want 0, 0", len(fs.inoByKey), len(fs.inodeByKey))
			}
		})
	}
	t.Run("shared_handle_reopen_fails", func(t *testing.T) {
		dir, fs, parent := newTestDirectfsEnv(ctx, t, InteropModeShared)
		if err := os.Mkdir(filepath.Join(dir, "dir"), 0755); err != nil {
			t.Fatalf("os.Mkdir(): %v", err)
		}
		_, d := newTestDirectfsDentry(t, fs, parent, "dir", linux.S_IFDIR|0755, -1)
		// Requesting a writable handle on a directory fails deterministically with EISDIR.
		fs.savedDentryRW[d] = savedDentryRW{read: true, write: true}
		requireOuterErrCorruption(t, d.restoreFile(ctx, &vfs.CompleteRestoreOptions{}), unix.EISDIR, "failed to restore file handles")
	})
}

func TestLisafsRestoreInodeFileTypeValidation(t *testing.T) {
	ctx := contexttest.Context(t)
	for _, tc := range []struct {
		name       string
		interop    InteropMode
		stat       lisafs.Statx
		wantSubstr string
	}{
		{name: "missing_statx_type", interop: InteropModeShared, stat: lisafs.Statx{Mask: linux.STATX_MODE, Mode: linux.S_IFREG | 0644}, wantSubstr: "file type not available"},
		{name: "mismatch_exclusive", interop: InteropModeExclusive, stat: lisafs.Statx{Mask: linux.STATX_TYPE | linux.STATX_MODE, Mode: linux.S_IFDIR | 0755}, wantSubstr: "file type changed"},
		{name: "mismatch_shared", interop: InteropModeShared, stat: lisafs.Statx{Mask: linux.STATX_TYPE | linux.STATX_MODE, Mode: linux.S_IFDIR | 0755}, wantSubstr: "file type changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFilesystem(ctx, tc.interop)
			li := &lisafsInode{}
			d := initTestDentry(&li.inode, li, fs, nil, "file.txt", linux.S_IFREG|0644)
			ino := lisafs.Inode{ControlFD: 1, Stat: tc.stat}
			requireOuterErrCorruption(t, li.restoreInode(ctx, &ino, &vfs.CompleteRestoreOptions{}, d), nil, tc.wantSubstr)
			if li.controlFD.Ok() {
				t.Errorf("li.controlFD.Ok() = true, want false")
			}
			if len(fs.inoByKey) != 0 || len(fs.inodeByKey) != 0 {
				t.Errorf("len(inoByKey)=%d, len(inodeByKey)=%d, want 0, 0", len(fs.inoByKey), len(fs.inodeByKey))
			}
		})
	}
}

func TestRestoreDeletedPreservesOutermostErrCorruption(t *testing.T) {
	ctx := contexttest.Context(t)
	t.Run("recreate_deleted_regular_file_fails", func(t *testing.T) {
		fs, parent := newNotDirEnv(ctx, t, InteropModeExclusive)
		_, d := newTestDirectfsDentry(t, fs, parent, "deleted.txt", linux.S_IFREG|0644, -1)
		d.inode.savedDeletedData = []byte("hello")
		requireOuterErrCorruption(t, d.restoreDeletedRegularFile(ctx, &vfs.CompleteRestoreOptions{}, make(map[*dentry]string)), unix.ENOTDIR, "failed to re-create deleted file")
	})
	t.Run("recreate_deleted_directory_fails", func(t *testing.T) {
		fs, parent := newNotDirEnv(ctx, t, InteropModeExclusive)
		_, d := newTestDirectfsDentry(t, fs, parent, "deleted_dir", linux.S_IFDIR|0755, -1)
		requireOuterErrCorruption(t, d.restoreDeletedDirectory(ctx, &vfs.CompleteRestoreOptions{}, make(map[*dentry]string)), unix.ENOTDIR, "failed to re-create deleted directory")
	})
	t.Run("deleted_regular_file_restoreFile_failure", func(t *testing.T) {
		dir, fs, parent := newTestDirectfsEnv(ctx, t, InteropModeExclusive)
		_, d := newTestDirectfsDentry(t, fs, parent, "deleted.txt", linux.S_IFREG|0644, -1)
		d.inode.size = atomicbitops.FromUint64(100)
		d.inode.savedDeletedData = []byte("short")
		filesToDelete := make(map[*dentry]string)
		requireOuterErrCorruption(t, d.restoreDeletedRegularFile(ctx, &vfs.CompleteRestoreOptions{ValidateFileSizes: true}, filesToDelete), nil, "failed to restore deleted regular file", "file size validation failed")
		if _, err := os.Stat(filepath.Join(dir, "deleted.txt")); !errors.Is(err, os.ErrNotExist) || len(filesToDelete) != 0 {
			t.Errorf("stat err = %v (want ErrNotExist), len(filesToDelete) = %d (want 0)", err, len(filesToDelete))
		}
	})
	t.Run("deleted_directory_restoreFile_failure", func(t *testing.T) {
		dir, fs, parent := newTestDirectfsEnv(ctx, t, InteropModeExclusive)
		_, d := newTestDirectfsDentry(t, fs, parent, "deleted_dir", linux.S_IFDIR|0755, -1)
		fs.savedDentryRW[d] = savedDentryRW{read: true, write: true}
		dirsToDelete := make(map[*dentry]string)
		requireOuterErrCorruption(t, d.restoreDeletedDirectory(ctx, &vfs.CompleteRestoreOptions{}, dirsToDelete), unix.EISDIR, "failed to restore deleted directory")
		if _, err := os.Stat(filepath.Join(dir, "deleted_dir")); !errors.Is(err, os.ErrNotExist) || len(dirsToDelete) != 0 {
			t.Errorf("stat err = %v (want ErrNotExist), len(dirsToDelete) = %d (want 0)", err, len(dirsToDelete))
		}
	})
}

func TestSpecialFileFDCompleteRestoreWrapsCorruptionError(t *testing.T) {
	ctx := contexttest.Context(t)
	dir, fs, parent := newTestDirectfsEnv(ctx, t, InteropModeExclusive)
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init(): %v", err)
	}
	fs.vfsfs.Init(&vfsObj, &FilesystemType{}, fs)
	mnt := vfsObj.NewDisconnectedMount(&fs.vfsfs, &parent.vfsd, &vfs.MountOptions{})
	if err := os.WriteFile(filepath.Join(dir, "locked.txt"), []byte("data"), 0444); err != nil {
		t.Fatalf("os.WriteFile(): %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "replaced_by_dir"), 0755); err != nil {
		t.Fatalf("os.Mkdir(): %v", err)
	}
	for _, tc := range []struct {
		name, fileName string
		wantErr        error
		skipRoot       bool
	}{
		{name: "unlinked", fileName: "missing.txt", wantErr: unix.ENOENT},
		{name: "replaced_by_directory", fileName: "replaced_by_dir", wantErr: unix.EISDIR},
		{name: "read_only_chmod", fileName: "locked.txt", wantErr: unix.EACCES, skipRoot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipRoot && os.Geteuid() == 0 {
				t.Skip("chmod 0444 does not block O_RDWR when running as root")
			}
			_, d := newTestDirectfsDentry(t, fs, parent, tc.fileName, linux.S_IFREG|0644, -1)
			var fd specialFileFD
			if err := fd.vfsfd.Init(&fd, linux.O_RDWR, auth.CredentialsFromContext(ctx), mnt, &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
				t.Fatalf("fd.vfsfd.Init(): %v", err)
			}
			requireOuterErrCorruption(t, fd.completeRestore(ctx), tc.wantErr, "failed to open handle for specialFileFD")
		})
	}
}
