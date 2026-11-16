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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
	if got := child.refs.Load(); got != -1 {
		t.Fatalf("child.refs=%d, want: -1", got)
	}
	// Parent will also be destroyed when child reference is removed.
	if got := parent.refs.Load(); got != -1 {
		t.Fatalf("parent.refs=%d, want: -1", got)
	}
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
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

// newDirectfsTestFilesystem returns a directfs-backed filesystem whose root is
// the host directory dir, without a VFS. The returned filesystem supports host
// walks, opens and unlinks; it has no memory file or clock.
func newDirectfsTestFilesystem(t *testing.T, dir string) (*filesystem, *dentry) {
	t.Helper()
	fs := &filesystem{
		inoByKey:   make(map[inoKey]uint64),
		inodeByKey: make(map[inoKey]*inode),
		// There is no VFS to allocate device numbers from.
		devMinor:    1,
		dentryCache: &dentryCache{maxCachedDentries: 1000},
		client:      &lisafs.Client{},
	}
	fs.opts.virtualInodeNumbers = true
	fs.opts.directfs.enabled = true
	ensureTestProcSelfFD(t)
	rootFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open(%q): %v", dir, err)
	}
	root, err := fs.newDirectfsDentry(rootFD)
	if err != nil {
		t.Fatalf("newDirectfsDentry(%q): %v", dir, err)
	}
	t.Cleanup(func() { destroyTestTree(fs, root) })
	return fs, root
}

// destroyTestTree destroys root and all of its cached descendants, closing
// their host FDs.
func destroyTestTree(fs *filesystem, root *dentry) {
	// Post-order, so that children are destroyed before their parents.
	var all []*dentry
	var walk func(d *dentry)
	walk = func(d *dentry) {
		d.childrenMu.Lock()
		children := make([]*dentry, 0, len(d.children))
		for _, c := range d.children {
			if c != nil {
				children = append(children, c)
			}
		}
		d.childrenMu.Unlock()
		for _, c := range children {
			walk(c)
		}
		all = append(all, d)
	}
	walk(root)
	// With fs.released set, checkCachingLocked() destroys zero-reference
	// dentries instead of caching them.
	fs.released.Store(1)
	ctx := context.Background()
	fs.renameMu.Lock()
	defer fs.renameMu.Unlock()
	for _, d := range all {
		d.checkCachingLocked(ctx, true /* renameMuWriteLocked */, false /* keepRenameMu */)
	}
}

// openHostFDs returns the set of FDs open in this process.
func openHostFDs(t *testing.T) map[string]string {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd): %v", err)
	}
	fds := make(map[string]string)
	for _, e := range ents {
		target, _ := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		fds[e.Name()] = target
	}
	return fds
}

// ensureTestProcSelfFD sets procSelfFD, which directfs requires, for the rest
// of the test binary's lifetime.
func ensureTestProcSelfFD(t *testing.T) {
	t.Helper()
	if procSelfFD >= 0 {
		return
	}
	fd, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open(/proc/self/fd): %v", err)
	}
	SetProcSelfFD(fd)
}

// checkNoLeakedFDs registers a cleanup, run after all cleanups registered
// later, that fails t if any host FD opened by the test is still open.
func checkNoLeakedFDs(t *testing.T) {
	t.Helper()
	ensureTestProcSelfFD(t)
	// Let the Go runtime create any FDs it keeps (e.g. its epoll FD).
	if f, err := os.Open("/proc/self/fd"); err == nil {
		f.Close()
	}
	before := openHostFDs(t)
	t.Cleanup(func() {
		for fd, target := range openHostFDs(t) {
			if _, ok := before[fd]; !ok && !strings.HasSuffix(target, "/proc/self/fd") {
				t.Errorf("leaked host FD %s -> %q", fd, target)
			}
		}
	})
}

// walkTestChild instantiates and caches the child of parent named name.
func walkTestChild(t *testing.T, parent *dentry, name string) *dentry {
	t.Helper()
	child, err := parent.inode.impl.(*directfsInode).getHostChild(name)
	if err != nil {
		t.Fatalf("getHostChild(%q): %v", name, err)
	}
	parent.opMu.Lock()
	parent.childrenMu.Lock()
	parent.cacheNewChildLocked(child, name)
	parent.childrenMu.Unlock()
	parent.opMu.Unlock()
	return child
}

// hostFDPath returns the host path that fd refers to, as reported by procfs.
// Paths of FDs whose name has been removed end in " (deleted)".
func hostFDPath(t *testing.T, fd int) string {
	t.Helper()
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		t.Fatalf("readlink(fd %d): %v", fd, err)
	}
	return p
}

func countAliases(i *inode) int {
	i.fs.inodeMu.Lock()
	defer i.fs.inodeMu.Unlock()
	n := 0
	for e := i.aliases.Front(); e != nil; e = e.Next() {
		n++
	}
	return n
}

// setupHardLinkTest creates dir/x/t and its hard link dir/y/t on the host, and
// returns cached dentries for x, x/t and y/t. x/t is opened for reading and
// writing first, so the shared inode's host FDs are opened via x/t.
func setupHardLinkTest(t *testing.T, ctx context.Context) (fs *filesystem, dir string, x, xt, yt *dentry) {
	return setupHardLinkTestWithHandle(t, ctx, true /* write */)
}

// setupHardLinkTestWithHandle is setupHardLinkTest, but x/t is opened only for
// reading if write is false.
func setupHardLinkTestWithHandle(t *testing.T, ctx context.Context, write bool) (fs *filesystem, dir string, x, xt, yt *dentry) {
	t.Helper()
	fs, dir, _, x, xt, yt = setupHardLinkTestFull(t, ctx, write)
	return fs, dir, x, xt, yt
}

// setupHardLinkTestRoot is setupHardLinkTest, but returns the root dentry
// instead of x.
func setupHardLinkTestRoot(t *testing.T, ctx context.Context) (fs *filesystem, dir string, root, xt, yt *dentry) {
	t.Helper()
	fs, dir, root, _, xt, yt = setupHardLinkTestFull(t, ctx, true /* write */)
	return fs, dir, root, xt, yt
}

func setupHardLinkTestFull(t *testing.T, ctx context.Context, write bool) (fs *filesystem, dir string, root, x, xt, yt *dentry) {
	t.Helper()
	dir = t.TempDir()
	checkNoLeakedFDs(t)
	for _, sub := range []string{"x", "y"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "x", "t"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "x", "t"), filepath.Join(dir, "y", "t")); err != nil {
		t.Fatal(err)
	}
	fs, root = newDirectfsTestFilesystem(t, dir)
	x = walkTestChild(t, root, "x")
	y := walkTestChild(t, root, "y")
	xt = walkTestChild(t, x, "t")
	yt = walkTestChild(t, y, "t")
	if xt.inode != yt.inode {
		t.Fatalf("hard links x/t and y/t do not share an inode")
	}
	if got := countAliases(xt.inode); got != 2 {
		t.Fatalf("inode has %d aliases, want 2", got)
	}
	fs.renameMu.RLock()
	err := xt.ensureSharedHandle(ctx, true /* read */, write, false /* trunc */)
	fs.renameMu.RUnlock()
	if err != nil {
		t.Fatalf("ensureSharedHandle: %v", err)
	}
	return fs, dir, root, x, xt, yt
}

// TestRebindHostFDsAfterUnlinkingHardLink checks that unlinking one name of a
// hard-linked file moves the inode's host FDs to a surviving name. Holding a
// host FD on a removed name makes NFS clients keep the file as .nfsXXXX in
// the old directory, so that the directory cannot be removed.
func TestRebindHostFDsAfterUnlinkingHardLink(t *testing.T) {
	ctx := context.Background()
	fs, dir, x, xt, _ := setupHardLinkTest(t, ctx)
	i := xt.inode.impl.(*directfsInode)
	readFD, writeFD := int(i.readFD.Load()), int(i.writeFD.Load())
	fds := []int{i.controlFD, readFD, writeFD}
	oldPath, newPath := filepath.Join(dir, "x", "t"), filepath.Join(dir, "y", "t")
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != oldPath {
			t.Fatalf("fd %d refers to %q, want %q", fd, got, oldPath)
		}
	}

	// This is what filesystem.unlinkAt() does on the host.
	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	xt.setDeleted()
	fs.renameMu.RLock()
	xt.inode.rebindHostFDs(ctx, xt)
	fs.renameMu.RUnlock()

	if i.controlFD != fds[0] || int(i.readFD.Load()) != readFD || int(i.writeFD.Load()) != writeFD {
		t.Errorf("host FD numbers changed: got %d/%d/%d, want %v", i.controlFD, i.readFD.Load(), i.writeFD.Load(), fds)
	}
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != newPath {
			t.Errorf("after unlinking %q, fd %d refers to %q, want %q", oldPath, fd, got, newPath)
		}
	}
	// The rebound FDs keep working.
	buf := make([]byte, 4)
	if n, err := unix.Pread(readFD, buf, 0); err != nil || !bytes.Equal(buf[:n], []byte("data")) {
		t.Errorf("pread after rebind = (%q, %v), want (\"data\", nil)", buf[:n], err)
	}
	if _, err := unix.Pwrite(writeFD, []byte("DATA"), 0); err != nil {
		t.Errorf("pwrite after rebind: %v", err)
	}
	if got, err := os.ReadFile(newPath); err != nil || string(got) != "DATA" {
		t.Errorf("ReadFile(%q) = (%q, %v), want (\"DATA\", nil)", newPath, got, err)
	}
}

// TestRebindHostFDsKeepsUnlinkedOpenFile checks that unlinking the last cached
// name of a file leaves its host FDs alone, so that a file that is unlinked
// while open remains usable.
func TestRebindHostFDsKeepsUnlinkedOpenFile(t *testing.T) {
	ctx := context.Background()
	fs, dir, _, xt, yt := setupHardLinkTest(t, ctx)
	i := xt.inode.impl.(*directfsInode)
	readFD := int(i.readFD.Load())

	// Unlink both names, y/t first, so that no surviving name remains when
	// x/t (via which the host FDs were opened) is unlinked.
	for _, d := range []*dentry{yt, xt} {
		parent := d.parent.Load()
		if err := parent.inode.unlink(ctx, d.name, 0 /* flags */); err != nil {
			t.Fatalf("unlink(%q): %v", d.name, err)
		}
		d.setDeleted()
		fs.renameMu.RLock()
		d.inode.rebindHostFDs(ctx, d)
		fs.renameMu.RUnlock()
	}
	if got, want := hostFDPath(t, readFD), filepath.Join(dir, "x", "t")+" (deleted)"; got != want {
		t.Errorf("fd %d refers to %q, want %q", readFD, got, want)
	}
	buf := make([]byte, 4)
	if n, err := unix.Pread(readFD, buf, 0); err != nil || !bytes.Equal(buf[:n], []byte("data")) {
		t.Errorf("pread of unlinked open file = (%q, %v), want (\"data\", nil)", buf[:n], err)
	}
}

// TestRebindHostFDsChecksIdentity checks that host FDs are not moved to a
// surviving name that has been replaced by a different file on the host.
func TestRebindHostFDsChecksIdentity(t *testing.T) {
	ctx := context.Background()
	fs, dir, x, xt, _ := setupHardLinkTest(t, ctx)
	i := xt.inode.impl.(*directfsInode)
	// Replace y/t behind the sandbox's back.
	newPath := filepath.Join(dir, "y", "t")
	if err := os.Remove(newPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("other"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	xt.setDeleted()
	fs.renameMu.RLock()
	xt.inode.rebindHostFDs(ctx, xt)
	fs.renameMu.RUnlock()
	for _, fd := range []int{i.controlFD, int(i.readFD.Load())} {
		if got := hostFDPath(t, fd); !strings.HasSuffix(got, " (deleted)") {
			t.Errorf("fd %d refers to %q, want the original (deleted) file", fd, got)
		}
	}
}

// destroyTestDentry removes d from its parent's children and destroys it, as
// dentry.evictLocked() does when d is evicted from the dentry cache.
func destroyTestDentry(ctx context.Context, d *dentry) {
	parent := d.parent.Load()
	parent.childrenMu.Lock()
	delete(parent.children, d.name)
	parent.childrenMu.Unlock()
	d.inode.fs.renameMu.Lock()
	defer d.inode.fs.renameMu.Unlock()
	d.destroyLocked(ctx, false /* keepRenameMu */)
}

// TestRebindHostFDsWhenOwnerEvicted checks that evicting the dentry via whose
// name the inode's host FDs were opened, while another name stays cached,
// moves the FDs to that name. Otherwise, unlinking the evicted name would
// leave the FDs on the removed name, since fs.unlinkAt() finds no cached
// dentry for it.
func TestRebindHostFDsWhenOwnerEvicted(t *testing.T) {
	ctx := context.Background()
	_, dir, x, xt, yt := setupHardLinkTest(t, ctx)
	i := xt.inode.impl.(*directfsInode)
	readFD, writeFD := int(i.readFD.Load()), int(i.writeFD.Load())
	fds := []int{i.controlFD, readFD, writeFD}
	oldPath, newPath := filepath.Join(dir, "x", "t"), filepath.Join(dir, "y", "t")
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != oldPath {
			t.Fatalf("fd %d refers to %q, want %q", fd, got, oldPath)
		}
	}

	// Evict x/t while y/t stays cached.
	destroyTestDentry(ctx, xt)
	if got := countAliases(yt.inode); got != 1 {
		t.Fatalf("after evicting x/t, inode has %d aliases, want 1", got)
	}
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != newPath {
			t.Errorf("after evicting x/t, fd %d refers to %q, want %q", fd, got, newPath)
		}
	}

	// Unlink the evicted name on the host, as fs.unlinkAt() does when the
	// child is not cached. The host FDs must not refer to the removed name.
	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if i.controlFD != fds[0] || int(i.readFD.Load()) != readFD || int(i.writeFD.Load()) != writeFD {
		t.Errorf("host FD numbers changed: got %d/%d/%d, want %v", i.controlFD, i.readFD.Load(), i.writeFD.Load(), fds)
	}
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != newPath {
			t.Errorf("after unlinking evicted %q, fd %d refers to %q, want %q", oldPath, fd, got, newPath)
		}
	}
	buf := make([]byte, 4)
	if n, err := unix.Pread(readFD, buf, 0); err != nil || !bytes.Equal(buf[:n], []byte("data")) {
		t.Errorf("pread after rebind = (%q, %v), want (\"data\", nil)", buf[:n], err)
	}

	// y/t is now recorded as the name holding the host FDs.
	yt.inode.fs.inodeMu.Lock()
	owner := yt.inode.hostFDsAlias
	yt.inode.fs.inodeMu.Unlock()
	if owner != yt {
		t.Errorf("hostFDsAlias is not y/t after rebinding to it")
	}
}

// TestRebindHostFDsSkipsOtherNames checks that removing a name other than the
// one via which the inode's host FDs were opened does not reopen them.
func TestRebindHostFDsSkipsOtherNames(t *testing.T) {
	ctx := context.Background()
	fs, dir, _, xt, yt := setupHardLinkTest(t, ctx)
	i := xt.inode.impl.(*directfsInode)
	fds := []int{i.controlFD, int(i.readFD.Load()), int(i.writeFD.Load())}
	reopened := 0
	rebindHostFDsTestHook = func(int) { reopened++ }
	defer func() { rebindHostFDsTestHook = nil }()

	y := yt.parent.Load()
	if err := y.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	yt.setDeleted()
	fs.renameMu.RLock()
	yt.inode.rebindHostFDs(ctx, yt)
	fs.renameMu.RUnlock()
	if reopened != 0 {
		t.Errorf("unlinking y/t reopened %d host FDs opened via x/t, want 0", reopened)
	}
	for _, fd := range fds {
		if got, want := hostFDPath(t, fd), filepath.Join(dir, "x", "t"); got != want {
			t.Errorf("fd %d refers to %q, want %q", fd, got, want)
		}
	}
}

// TestHostFDsOwnerSurvivesLookupRace checks that when two concurrent lookups
// of the same name race, and the lookup that created the inode (and so opened
// its host FDs via that name) loses the race to insert its dentry, ownership
// of the host FDs passes to the winning dentry. Otherwise, evicting the
// winner while another hard link stays cached would not rebind the FDs, and
// they would stay on the name after it is unlinked.
func TestHostFDsOwnerSurvivesLookupRace(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	checkNoLeakedFDs(t)
	for _, sub := range []string{"x", "y"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "x", "t"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "x", "t"), filepath.Join(dir, "y", "t")); err != nil {
		t.Fatal(err)
	}
	fs, root := newDirectfsTestFilesystem(t, dir)
	x := walkTestChild(t, root, "x")
	y := walkTestChild(t, root, "y")

	lookup := func() (*dentry, error) {
		var ds *[]*dentry
		fs.renameMu.RLock()
		defer fs.renameMu.RUnlock()
		x.opMu.RLock()
		defer x.opMu.RUnlock()
		return fs.getRemoteChildLocked(ctx, x, "t", true /* checkForRace */, &ds)
	}

	// Pause the first lookup of x/t (A), which creates the inode, before it
	// inserts its dentry.
	paused, resume := make(chan struct{}), make(chan struct{})
	first := true
	getRemoteChildTestHook = func(parent *dentry, name string) {
		if parent != x || name != "t" || !first {
			return
		}
		first = false
		close(paused)
		<-resume
	}
	defer func() { getRemoteChildTestHook = nil }()
	type result struct {
		d   *dentry
		err error
	}
	aDone := make(chan result, 1)
	go func() {
		d, err := lookup()
		aDone <- result{d, err}
	}()
	<-paused

	// A second lookup of x/t (B) adopts A's inode and is inserted first.
	b, err := lookup()
	close(resume)
	a := <-aDone
	if err != nil {
		t.Fatalf("lookup B: %v", err)
	}
	if a.err != nil {
		t.Fatalf("lookup A: %v", a.err)
	}
	if a.d != b {
		t.Fatalf("lookup A returned a different dentry than the cached one")
	}
	b.inode.fs.inodeMu.Lock()
	owner := b.inode.hostFDsAlias
	b.inode.fs.inodeMu.Unlock()
	if owner != b {
		t.Errorf("after A lost the insertion race, hostFDsAlias is not B")
	}

	// Cache another hard link, open the file via B, then evict B.
	yt := walkTestChild(t, y, "t")
	if yt.inode != b.inode {
		t.Fatalf("hard links x/t and y/t do not share an inode")
	}
	fs.renameMu.RLock()
	err = b.ensureSharedHandle(ctx, true /* read */, false /* write */, false /* trunc */)
	fs.renameMu.RUnlock()
	if err != nil {
		t.Fatalf("ensureSharedHandle: %v", err)
	}
	i := b.inode.impl.(*directfsInode)
	fds := []int{i.controlFD, int(i.readFD.Load())}
	oldPath, newPath := filepath.Join(dir, "x", "t"), filepath.Join(dir, "y", "t")
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != oldPath {
			t.Fatalf("fd %d refers to %q, want %q", fd, got, oldPath)
		}
	}
	destroyTestDentry(ctx, b)

	// Unlink the evicted name on the host.
	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != newPath {
			t.Errorf("after evicting and unlinking %q, fd %d refers to %q, want %q", oldPath, fd, got, newPath)
		}
	}
}

// TestHostFDsRebindAfterLookupRaceWithReplacedName checks the lookup race in
// TestHostFDsOwnerSurvivesLookupRace when the name is replaced on the host
// between the two lookups, so that the winning dentry has a different inode.
// The losing dentry's inode stays alive via another hard link, so its host
// FDs, opened via the replaced name, must be moved to that link.
func TestHostFDsRebindAfterLookupRaceWithReplacedName(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	checkNoLeakedFDs(t)
	for _, sub := range []string{"x", "y"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	oldPath, newPath := filepath.Join(dir, "x", "t"), filepath.Join(dir, "y", "t")
	if err := os.WriteFile(oldPath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	fs, root := newDirectfsTestFilesystem(t, dir)
	x := walkTestChild(t, root, "x")
	y := walkTestChild(t, root, "y")

	lookup := func() (*dentry, error) {
		var ds *[]*dentry
		fs.renameMu.RLock()
		defer fs.renameMu.RUnlock()
		x.opMu.RLock()
		defer x.opMu.RUnlock()
		return fs.getRemoteChildLocked(ctx, x, "t", true /* checkForRace */, &ds)
	}
	paused, resume := make(chan struct{}), make(chan struct{})
	first := true
	getRemoteChildTestHook = func(parent *dentry, name string) {
		if parent != x || name != "t" || !first {
			return
		}
		first = false
		close(paused)
		<-resume
	}
	defer func() { getRemoteChildTestHook = nil }()
	aDone := make(chan error, 1)
	go func() {
		_, err := lookup()
		aDone <- err
	}()
	<-paused

	// While A is paused, cache y/t (which adopts A's inode) and replace x/t
	// on the host, so that B creates a new inode.
	yt := walkTestChild(t, y, "t")
	i, ok := yt.inode.impl.(*directfsInode)
	if !ok {
		t.Fatalf("y/t is not a directfs inode")
	}
	controlFD := i.controlFD
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("other"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, oldPath); err != nil {
		t.Fatal(err)
	}
	b, err := lookup()
	close(resume)
	if aErr := <-aDone; aErr != nil {
		t.Fatalf("lookup A: %v", aErr)
	}
	if err != nil {
		t.Fatalf("lookup B: %v", err)
	}
	if b.inode == yt.inode {
		t.Fatalf("x/t was replaced, but its new dentry shares y/t's inode")
	}
	if got := hostFDPath(t, controlFD); got != newPath {
		t.Errorf("after A lost the race to a replaced x/t, control FD refers to %q, want %q", got, newPath)
	}
	yt.inode.fs.inodeMu.Lock()
	owner := yt.inode.hostFDsAlias
	yt.inode.fs.inodeMu.Unlock()
	if owner != yt {
		t.Errorf("hostFDsAlias is not y/t after rebinding to it")
	}
}

// TestHostFDsRebindAfterOwnerInvalidated checks that invalidating the dentry
// that owns its inode's host FDs, after the file was renamed on the host,
// does not stop a later unlink of the file's new name from rebinding them.
func TestHostFDsRebindAfterOwnerInvalidated(t *testing.T) {
	ctx := context.Background()
	fs, dir, root, xt, _ := setupHardLinkTestRoot(t, ctx)
	i := xt.inode.impl.(*directfsInode)
	fds := []int{i.controlFD, int(i.readFD.Load()), int(i.writeFD.Load())}
	// Keep x/t alive after it is invalidated, as an open FD would.
	xt.IncRef()

	// Rename x/t to z/t on the host. The host FDs follow the file.
	if err := os.Mkdir(filepath.Join(dir, "z"), 0755); err != nil {
		t.Fatal(err)
	}
	zPath := filepath.Join(dir, "z", "t")
	if err := os.Rename(filepath.Join(dir, "x", "t"), zPath); err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != zPath {
			t.Fatalf("after host rename, fd %d refers to %q, want %q", fd, got, zPath)
		}
	}
	var vfsObj vfs.VirtualFilesystem
	var ds *[]*dentry
	fs.renameMu.RLock()
	xt.invalidate(ctx, &vfsObj, &ds)
	fs.renameMu.RUnlock()

	// Look up z/t, which adopts the inode, and unlink it.
	z := walkTestChild(t, root, "z")
	zt := walkTestChild(t, z, "t")
	if zt.inode != xt.inode {
		t.Fatalf("z/t does not share x/t's inode")
	}
	if err := z.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	zt.setDeleted()
	fs.renameMu.RLock()
	zt.inode.rebindHostFDs(ctx, zt)
	fs.renameMu.RUnlock()
	for _, fd := range fds {
		if got, want := hostFDPath(t, fd), filepath.Join(dir, "y", "t"); got != want {
			t.Errorf("after unlinking z/t, fd %d refers to %q, want %q", fd, got, want)
		}
	}
	xt.DecRef(ctx)
}

// TestHostFDsRebindTargetInvalidatedConcurrently checks that if the alias
// that host FDs are being rebound to is invalidated concurrently (revalidation
// does not lock handleMu), it is not recorded as the owner, so that a later
// unlink of the file's actual name still rebinds the FDs.
func TestHostFDsRebindTargetInvalidatedConcurrently(t *testing.T) {
	ctx := context.Background()
	fs, dir, root, xt, yt := setupHardLinkTestRoot(t, ctx)
	if err := os.Mkdir(filepath.Join(dir, "w"), 0755); err != nil {
		t.Fatal(err)
	}
	wPath := filepath.Join(dir, "w", "t")
	if err := os.Link(filepath.Join(dir, "y", "t"), wPath); err != nil {
		t.Fatal(err)
	}
	w := walkTestChild(t, root, "w")
	walkTestChild(t, w, "t")
	if err := os.Mkdir(filepath.Join(dir, "z"), 0755); err != nil {
		t.Fatal(err)
	}
	i := xt.inode.impl.(*directfsInode)
	fds := []int{i.controlFD, int(i.readFD.Load()), int(i.writeFD.Load())}
	// Keep y/t alive after it is invalidated, as an open FD would.
	yt.IncRef()

	// Unlink x/t. While its FDs are being rebound to y/t, rename y/t to z/t
	// on the host and invalidate y/t, as revalidation would.
	x := xt.parent.Load()
	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	xt.setDeleted()
	zPath := filepath.Join(dir, "z", "t")
	var vfsObj vfs.VirtualFilesystem
	var ds *[]*dentry
	invalidated := false
	rebindHostFDsTestHook = func(int) {
		if invalidated {
			return
		}
		invalidated = true
		if err := os.Rename(filepath.Join(dir, "y", "t"), zPath); err != nil {
			t.Errorf("Rename: %v", err)
		}
		yt.invalidate(ctx, &vfsObj, &ds)
	}
	defer func() { rebindHostFDsTestHook = nil }()
	fs.renameMu.RLock()
	xt.inode.rebindHostFDs(ctx, xt)
	fs.renameMu.RUnlock()
	rebindHostFDsTestHook = nil
	if !invalidated {
		t.Fatalf("rebind did not reach the test hook")
	}
	xt.inode.fs.inodeMu.Lock()
	owner := xt.inode.hostFDsAlias
	xt.inode.fs.inodeMu.Unlock()
	if owner == yt {
		t.Errorf("invalidated y/t was recorded as the owner of the host FDs")
	}

	// The FDs now refer to z/t. Look it up and unlink it: the FDs must move
	// to w/t.
	z := walkTestChild(t, root, "z")
	zt := walkTestChild(t, z, "t")
	if err := z.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	zt.setDeleted()
	fs.renameMu.RLock()
	zt.inode.rebindHostFDs(ctx, zt)
	fs.renameMu.RUnlock()
	for _, fd := range fds {
		if got := hostFDPath(t, fd); got != wPath {
			t.Errorf("after unlinking z/t, fd %d refers to %q, want %q", fd, got, wPath)
		}
	}
	yt.DecRef(ctx)
}

// TestHostFDsOwnerSetBeforeInodePublished checks that the dentry that creates
// an inode is recorded as the owner of its host FDs before other lookups can
// adopt the inode. Otherwise, a rebind by another lookup while the creating
// lookup is delayed would be overwritten when it resumes.
func TestHostFDsOwnerSetBeforeInodePublished(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	checkNoLeakedFDs(t)
	for _, sub := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	aPath := filepath.Join(dir, "a", "t")
	if err := os.WriteFile(aPath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"b", "c"} {
		if err := os.Link(aPath, filepath.Join(dir, sub, "t")); err != nil {
			t.Fatal(err)
		}
	}
	fs, root := newDirectfsTestFilesystem(t, dir)
	a := walkTestChild(t, root, "a")
	b := walkTestChild(t, root, "b")
	c := walkTestChild(t, root, "c")

	// Pause the lookup of a/t, which creates the inode, after the inode is
	// published but before the dentry is registered as an alias.
	paused, resume := make(chan struct{}), make(chan struct{})
	first := true
	newDirectfsDentryTestHook = func() {
		if !first {
			return
		}
		first = false
		close(paused)
		<-resume
	}
	defer func() { newDirectfsDentryTestHook = nil }()
	type result struct {
		d   *dentry
		err error
	}
	aDone := make(chan result, 1)
	go func() {
		d, err := a.inode.impl.(*directfsInode).getHostChild("t")
		aDone <- result{d, err}
	}()
	<-paused

	// Meanwhile, b/t and c/t adopt the inode, and b/t is unlinked.
	bt := walkTestChild(t, b, "t")
	ct := walkTestChild(t, c, "t")
	if err := b.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	bt.setDeleted()
	fs.renameMu.RLock()
	bt.inode.rebindHostFDs(ctx, bt)
	fs.renameMu.RUnlock()
	close(resume)
	res := <-aDone
	if res.err != nil {
		t.Fatalf("getHostChild(a/t): %v", res.err)
	}
	at := res.d
	a.opMu.Lock()
	a.childrenMu.Lock()
	a.cacheNewChildLocked(at, "t")
	a.childrenMu.Unlock()
	a.opMu.Unlock()
	if at.inode != ct.inode {
		t.Fatalf("a/t and c/t do not share an inode")
	}

	// Unlink c/t. Wherever the host FDs are, they must not refer to a
	// removed name while a/t remains.
	if err := c.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	ct.setDeleted()
	fs.renameMu.RLock()
	ct.inode.rebindHostFDs(ctx, ct)
	fs.renameMu.RUnlock()
	controlFD := at.inode.impl.(*directfsInode).controlFD
	if got := hostFDPath(t, controlFD); got != aPath {
		t.Errorf("after unlinking b/t and c/t, control FD refers to %q, want %q", got, aPath)
	}
}

// TestInodeAliasesTracksDentries checks that inode.aliases tracks the
// dentries that share an inode as they are destroyed.
func TestInodeAliasesTracksDentries(t *testing.T) {
	ctx := context.Background()
	_, _, x, xt, yt := setupHardLinkTest(t, ctx)
	ino := xt.inode
	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	xt.setDeleted()
	destroyTestDentry(ctx, xt)
	if got := countAliases(ino); got != 1 {
		t.Fatalf("after destroying x/t, inode has %d aliases, want 1", got)
	}
	ino.fs.inodeMu.Lock()
	front := ino.aliases.Front()
	ino.fs.inodeMu.Unlock()
	if front == nil || front.d != yt {
		t.Fatalf("remaining alias is not y/t")
	}
}

// TestRebindHostFDsNameSwappedForFIFO checks that rebinding does not block,
// and leaves the host FDs referring to the original file, if the surviving
// name is replaced by a FIFO while the FDs are being reopened.
func TestRebindHostFDsNameSwappedForFIFO(t *testing.T) {
	ctx := context.Background()
	fs, dir, x, xt, _ := setupHardLinkTestWithHandle(t, ctx, false /* write */)
	i := xt.inode.impl.(*directfsInode)
	fds := []int{i.controlFD, int(i.readFD.Load())}
	var want unix.Stat_t
	if err := unix.Fstat(fds[1], &want); err != nil {
		t.Fatal(err)
	}
	if flags, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFL, 0); err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_NONBLOCK != 0 {
		t.Fatalf("readFD flags = %#x, %v; want blocking O_RDONLY", flags, err)
	}
	alias := filepath.Join(dir, "y", "t")
	// Swap the name after the control FD has been reopened, before the
	// blocking read-only FD is.
	rebindHostFDsTestHook = func(fd int) {
		if fd != fds[1] {
			return
		}
		if err := os.Remove(alias); err != nil {
			t.Errorf("Remove(%q): %v", alias, err)
		}
		if err := unix.Mkfifo(alias, 0644); err != nil {
			t.Errorf("Mkfifo(%q): %v", alias, err)
		}
	}
	defer func() { rebindHostFDsTestHook = nil }()

	if err := x.inode.unlink(ctx, "t", 0 /* flags */); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	xt.setDeleted()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fs.renameMu.RLock()
		defer fs.renameMu.RUnlock()
		xt.inode.rebindHostFDs(ctx, xt)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		// Unblock the open of the FIFO so that the test can finish.
		if f, err := os.OpenFile(alias, os.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatalf("rebindHostFDs blocked after the surviving name was replaced by a FIFO")
	}
	for _, fd := range fds {
		var got unix.Stat_t
		if err := unix.Fstat(fd, &got); err != nil {
			t.Fatalf("fstat(%d): %v", fd, err)
		}
		if got.Ino != want.Ino || got.Dev != want.Dev || got.Mode&unix.S_IFMT != unix.S_IFREG {
			t.Errorf("fd %d refers to ino %d mode %#o, want the original regular file (ino %d)", fd, got.Ino, got.Mode, want.Ino)
		}
	}
}

// TestRebindAfterRename checks which renames require rebinding the replaced
// file's host FDs, including a synthetic file (e.g. a bound Unix socket)
// replacing a real one, where the replaced file is unlinked on the host.
func TestRebindAfterRename(t *testing.T) {
	ctx := context.Background()
	_, _, x, xt, yt := setupHardLinkTest(t, ctx)
	synthetic := &dentry{inode: &inode{}}
	synthetic.inode.mode.Store(linux.S_IFSOCK | 0777)
	for _, tc := range []struct {
		name     string
		renamed  *dentry
		replaced *dentry
		exchange bool
		want     *dentry
	}{
		{"no replaced file", xt, nil, false, nil},
		{"real file replaced", x, yt, false, yt},
		{"synthetic file replaces real file", synthetic, yt, false, yt},
		{"exchange", x, yt, true, nil},
		{"directory replaced", xt, x, false, nil},
		{"link of the same file replaced", xt, yt, false, nil},
		{"synthetic file replaced", xt, synthetic, false, nil},
	} {
		if got := rebindAfterRename(tc.renamed, tc.replaced, tc.exchange); got != tc.want {
			t.Errorf("%s: rebindAfterRename() = %p, want %p", tc.name, got, tc.want)
		}
	}
}
