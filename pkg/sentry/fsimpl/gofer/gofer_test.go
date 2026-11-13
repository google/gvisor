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
	"fmt"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
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

type recycledInoConnImpl struct {
	mu         sync.Mutex
	rootStat   lisafs.Statx
	targetStat lisafs.Statx
}

func (s *recycledInoConnImpl) getTargetStat() lisafs.Statx {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.targetStat
}

func (s *recycledInoConnImpl) setTargetStat(st lisafs.Statx) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetStat = st
}

// +checklocksread:c.server.renameMu
// +checklocksexclude:c.fdsMu
func (s *recycledInoConnImpl) Mount(c *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, lisafs.Statx, int, error) {
	mountNode.IncRef()
	fd := &recycledInoControlFD{connImpl: s, isRoot: true, stat: s.rootStat}
	fd.Init(c, mountNode, linux.ModeDirectory, fd)
	return fd.FD(), s.rootStat, -1, nil
}

func (s *recycledInoConnImpl) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

func (s *recycledInoConnImpl) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		lisafs.FStat,
		lisafs.Walk,
		lisafs.WalkStat,
		lisafs.OpenAt,
		lisafs.Close,
		lisafs.Flush,
	}
}

type recycledInoControlFD struct {
	lisafs.ControlFD
	lisafs.ControlFDImpl
	connImpl *recycledInoConnImpl
	isRoot   bool
	stat     lisafs.Statx
}

func (fd *recycledInoControlFD) FD() *lisafs.ControlFD { return &fd.ControlFD }
func (fd *recycledInoControlFD) Close()                {}

func (fd *recycledInoControlFD) Stat() (lisafs.Statx, error) {
	if fd.isRoot {
		return fd.connImpl.rootStat, nil
	}
	return fd.stat, nil
}

// +checklocksread:fd.ControlFD.conn.server.renameMu
// +checklocksexclude:fd.ControlFD.conn.fdsMu
func (fd *recycledInoControlFD) Walk(name string) (*lisafs.ControlFD, lisafs.Statx, error) {
	if !fd.isRoot || (name != "target" && name != "target_link") {
		return nil, lisafs.Statx{}, unix.ENOENT
	}
	st := fd.connImpl.getTargetStat()
	var childNode *lisafs.Node
	fd.Node().WithChildrenMu(func() {
		childNode = fd.Node().LookupChildLocked(name)
		if childNode == nil {
			childNode = &lisafs.Node{}
			childNode.InitLocked(name, fd.Node())
		} else {
			childNode.IncRef()
		}
	})
	child := &recycledInoControlFD{connImpl: fd.connImpl, stat: st}
	// Conn returns fd.ControlFD.conn, whose server rename lock is required
	// on entry; checklocks does not retain that identity across the getter.
	child.Init(fd.Conn(), childNode, linux.FileMode(st.Mode), child) // +checklocksignore
	return child.FD(), st, nil
}

func (fd *recycledInoControlFD) WalkStat(path lisafs.StringArray, recordStat func(lisafs.Statx)) error {
	curIsRoot := fd.isRoot
	for i, comp := range path {
		if i == 0 && comp == "" {
			if curIsRoot {
				recordStat(fd.connImpl.rootStat)
			} else {
				recordStat(fd.stat)
			}
			continue
		}
		if curIsRoot && (comp == "target" || comp == "target_link") {
			recordStat(fd.connImpl.getTargetStat())
			curIsRoot = false
			continue
		}
		break
	}
	return nil
}

func (fd *recycledInoControlFD) Open(flags uint32) (*lisafs.OpenFD, int, error) {
	ofd := &recycledInoOpenFD{stat: fd.stat}
	ofd.Init(fd.FD(), flags, ofd)
	return &ofd.OpenFD, -1, nil
}

type recycledInoOpenFD struct {
	lisafs.OpenFD
	lisafs.OpenFDImpl
	stat lisafs.Statx
}

func (fd *recycledInoOpenFD) FD() *lisafs.OpenFD          { return &fd.OpenFD }
func (fd *recycledInoOpenFD) Close()                      {}
func (fd *recycledInoOpenFD) Stat() (lisafs.Statx, error) { return fd.stat, nil }

func mountTestLisafsFS(t *testing.T, targetStat lisafs.Statx) (context.Context, *auth.Credentials, *recycledInoConnImpl, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	t.Helper()
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	serverSock, clientSock, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("unet.SocketPair: %v", err)
	}

	srv := lisafs.NewServer()
	t.Cleanup(func() { srv.Destroy() })

	connImpl := &recycledInoConnImpl{
		rootStat: lisafs.Statx{
			Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
			Mode:     linux.S_IFDIR | 0755,
			DevMajor: 0,
			DevMinor: 1,
			Ino:      1,
		},
		targetStat: targetStat,
	}
	conn, err := srv.CreateConnection(serverSock, "/", lisafs.ConnectionOpts{WalkStatSupported: true}, connImpl)
	if err != nil {
		clientSock.Close()
		serverSock.Close()
		t.Fatalf("srv.CreateConnection: %v", err)
	}
	srv.StartConnection(conn)
	t.Cleanup(func() { srv.Wait() })

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		clientSock.Close()
		t.Fatalf("vfsObj.Init: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	sockFD, err := clientSock.Release()
	if err != nil {
		t.Fatalf("clientSock.Release: %v", err)
	}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,cache=remote_revalidating", sockFD, sockFD),
		},
	}, nil)
	if err != nil {
		_ = unix.Close(sockFD)
		t.Fatalf("NewMountNamespace: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })

	root := mntns.Root(ctx)
	t.Cleanup(func() { root.DecRef(ctx) })
	return ctx, creds, connImpl, vfsObj, root
}

// TestOpenAtRecycledInoTypeChange reproduces host inode number recycling across
// file types end-to-end through vfs.VirtualFilesystem.OpenAt with zero open FDs
// held by the application.
func TestOpenAtRecycledInoTypeChange(t *testing.T) {
	ctx, creds, connImpl, vfsObj, root := mountTestLisafsFS(t, lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO,
		Mode:     linux.S_IFSOCK | 0777,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
	})

	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("target"),
	}

	// 1. Stat "/target" while it is a Unix domain socket (ino=42). Even
	// with no open FD, dcache retains the dentry and fs.inodeByKey retains
	// the socket inode.
	st, err := vfsObj.StatAt(ctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("StatAt(socket): %v", err)
	}
	if got := st.Mode & linux.S_IFMT; got != linux.S_IFSOCK {
		t.Fatalf("StatAt(socket) mode = %#o, want %#o", got, linux.S_IFSOCK)
	}

	// 2. Host unlinks "/target" and creates a regular file at "/target"
	// that reuses host st_ino=42.
	connImpl.setTargetStat(lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode:     linux.S_IFREG | 0644,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
		Size:     64,
	})

	// 3. OpenAt("/target"): doRevalidationLisafs invalidates the old socket
	// dentry (deferring its destruction in ds until OpenAt returns), and
	// stepLocked -> newLisafsDentry immediately walks the new regular file
	// and hits the still-cached socket inode in fs.inodeByKey.
	fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(regular): %v", err)
	}
	defer fd.DecRef(ctx)

	regStat, err := fd.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("fd.Stat(regular): %v", err)
	}
	if got := regStat.Mode & linux.S_IFMT; got != linux.S_IFREG {
		t.Fatalf("fd.Stat(regular) mode = %#o, want %#o", got, linux.S_IFREG)
	}
	if regStat.Size != 64 {
		t.Fatalf("fd.Stat(regular) size = %d, want 64", regStat.Size)
	}

	// 4. Verify that destroying the superseded socket dentry at the end of
	// OpenAt did not evict the new regular inode from fs.inodeByKey, and
	// that walking a second hard link refreshes the shared inode's size.
	connImpl.setTargetStat(lisafs.Statx{
		Mask:     linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_INO | linux.STATX_SIZE,
		Mode:     linux.S_IFREG | 0644,
		DevMajor: 0,
		DevMinor: 1,
		Ino:      42,
		Size:     256,
	})
	linkPop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("target_link"),
	}
	linkFD, err := vfsObj.OpenAt(ctx, creds, &linkPop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(target_link): %v", err)
	}
	defer linkFD.DecRef(ctx)

	regInode := fd.Dentry().Impl().(*dentry).inode
	linkInode := linkFD.Dentry().Impl().(*dentry).inode
	if linkInode != regInode {
		t.Fatalf("hard link did not share replacement *gofer.inode")
	}
	if got := regInode.size.Load(); got != 256 {
		t.Fatalf("regInode.size = %d, want 256", got)
	}
}
