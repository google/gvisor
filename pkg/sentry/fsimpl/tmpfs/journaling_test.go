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

package tmpfs

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const pageSize = uint64(hostarch.PageSize)

func newJournalTestFD(t testing.TB) int {
	t.Helper()
	fd, err := memutil.CreateMemFD("tmpfs-journal-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func dupFile(t testing.TB, fd int, name string) *os.File {
	t.Helper()
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	return os.NewFile(uintptr(dup), name)
}

// journaledTmpfs is a mounted tmpfs backed by a single MemoryFile.
type journaledTmpfs struct {
	ctx    context.Context
	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry
	fs     *filesystem
	mf     *pgalloc.MemoryFile
}

// mountFreshJournaled mounts a brand-new journaled tmpfs in fd.
func mountFreshJournaled(t testing.TB, ctx context.Context, fd int, regionSize uint64) *journaledTmpfs {
	t.Helper()
	mf, err := pgalloc.NewMemoryFile(dupFile(t, fd, "filestore"), pgalloc.MemoryFileOpts{
		DelayedEviction:         pgalloc.DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	j, err := journal.Create(mf, journal.Options{
		BuildID:    "build",
		ImageID:    "image",
		RegionSize: regionSize,
	})
	if err != nil {
		mf.Destroy()
		t.Fatalf("journal.Create: %v", err)
	}
	return mountTmpfsForTest(t, ctx, mf, FilesystemOpts{
		MemoryFile: mf,
		Journal:    j,
	})
}

// mountImported mounts a tmpfs by replaying the journal in fd, with runtime
// journaling either enabled or disabled.
func mountImported(t testing.TB, ctx context.Context, fd int, regionSize uint64, keepJournal bool) *journaledTmpfs {
	t.Helper()
	mf, err := pgalloc.NewMemoryFile(dupFile(t, fd, "filestore"), pgalloc.MemoryFileOpts{
		DelayedEviction:         pgalloc.DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		KeepFileContents:        true,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	j, st, err := journal.Open(mf, journal.Options{
		BuildID:    "build",
		ImageID:    "image",
		RegionSize: regionSize,
	}, keepJournal)
	if err != nil {
		mf.Destroy()
		t.Fatalf("journal.Open: %v", err)
	}
	return mountTmpfsForTest(t, ctx, mf, FilesystemOpts{
		MemoryFile:   mf,
		Journal:      j,
		JournalState: st,
	})
}

func mountTmpfsForTest(t testing.TB, ctx context.Context, mf *pgalloc.MemoryFile, opts FilesystemOpts) *journaledTmpfs {
	t.Helper()
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: opts,
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(ctx)
	return &journaledTmpfs{
		ctx:    auth.ContextWithCredentials(vfs.WithMountNamespace(ctx, mntns), rootCreds()),
		vfsObj: vfsObj,
		root:   root,
		fs:     root.Mount().Filesystem().Impl().(*filesystem),
		mf:     mf,
	}
}

// crash abandons m without releasing it, as if the sentry was killed.
func (m *journaledTmpfs) crash() {
	if j := m.fs.journal.Load(); j != nil {
		j.Close()
	}
	m.mf.Destroy()
}

func (m *journaledTmpfs) pop(path string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: m.root, Start: m.root, Path: fspath.Parse(path)}
}

// fileModel is the state of one file, as compared across a rebuild.
type fileModel struct {
	Ino     uint64
	Mode    uint32
	UID     uint32
	GID     uint32
	Nlink   uint32
	Size    uint64
	Atime   int64
	Mtime   int64
	Ctime   int64
	Btime   int64
	Target  string
	Rdev    [2]uint32
	Xattrs  map[string]string
	ACL     string
	Data    []byte
	Extents [][3]uint64
}

// model returns the state of every file in m, by path.
func (m *journaledTmpfs) model(t *testing.T) map[string]fileModel {
	t.Helper()
	fs := m.fs
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	model := make(map[string]fileModel)
	var walk func(d *dentry, path string)
	walk = func(d *dentry, path string) {
		i := d.inode
		fm := fileModel{
			Ino:   i.ino,
			Mode:  i.mode.Load(),
			UID:   i.uid.Load(),
			GID:   i.gid.Load(),
			Nlink: i.nlink.Load(),
			Atime: i.atime.Load(),
			Mtime: i.mtime.Load(),
			Ctime: i.ctime.Load(),
			Btime: i.btime.Load(),
		}
		if xattrs := i.xattrs.RawXattrs(); len(xattrs) != 0 {
			fm.Xattrs = xattrs
		}
		if acl := i.accessACL.Load(); acl != nil {
			fm.ACL = acl.String()
		}
		switch impl := i.impl.(type) {
		case *regularFile:
			fm.Size = impl.size.Load()
			fm.Data = make([]byte, fm.Size)
			rw := getRegularFileReadWriter(impl, 0, 0)
			if _, err := rw.ReadToBlocks(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(fm.Data))); err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			putRegularFileReadWriter(rw)
			impl.dataMu.RLock()
			for seg := impl.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
				fm.Extents = append(fm.Extents, [3]uint64{seg.Start(), seg.End(), seg.Value()})
			}
			impl.dataMu.RUnlock()
		case *symlink:
			fm.Target = impl.target
		case *deviceFile:
			fm.Rdev = [2]uint32{impl.major, impl.minor}
		case *directory:
			for name, child := range impl.childMap {
				walk(child, path+"/"+name)
			}
		}
		model[path] = fm
	}
	walk(fs.root, "")
	return model
}

func compareModels(t *testing.T, what string, got, want map[string]fileModel) {
	t.Helper()
	var paths []string
	for p := range want {
		paths = append(paths, p)
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		g, gok := got[p]
		w, wok := want[p]
		switch {
		case !gok:
			t.Errorf("%s: %q is missing", what, p)
		case !wok:
			t.Errorf("%s: %q is unexpected", what, p)
		case !reflect.DeepEqual(g, w):
			gd, wd := g.Data, w.Data
			g.Data, w.Data = nil, nil
			t.Errorf("%s: %q differs:\n got %+v\nwant %+v\ndata equal: %t", what, p, g, w, bytes.Equal(gd, wd))
		}
	}
}

type journalScript struct {
	t     *testing.T
	ctx   context.Context
	creds *auth.Credentials
	m     *journaledTmpfs
}

func (s *journalScript) check(err error, what string) {
	s.t.Helper()
	if err != nil {
		s.t.Fatalf("%s: %v", what, err)
	}
}

func (s *journalScript) mkdir(path string, mode linux.FileMode) {
	s.t.Helper()
	s.check(s.m.vfsObj.MkdirAt(s.ctx, s.creds, s.m.pop(path), &vfs.MkdirOptions{Mode: mode}), "mkdir "+path)
}

func (s *journalScript) open(path string, flags uint32) *vfs.FileDescription {
	s.t.Helper()
	fd, err := s.m.vfsObj.OpenAt(s.ctx, s.creds, s.m.pop(path), &vfs.OpenOptions{Flags: flags, Mode: 0644})
	s.check(err, "open "+path)
	return fd
}

func (s *journalScript) write(fd *vfs.FileDescription, data []byte) {
	s.t.Helper()
	n, err := fd.Write(s.ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	s.check(err, "write")
	if n != int64(len(data)) {
		s.t.Fatalf("write wrote %d bytes, want %d", n, len(data))
	}
}

func rootCreds() *auth.Credentials {
	return auth.NewRootCredentials(auth.NewRootUserNamespace())
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

func createFiles(t *testing.T, m *journaledTmpfs, n int) {
	t.Helper()
	s := &journalScript{t: t, ctx: m.ctx, creds: rootCreds(), m: m}
	for i := 0; i < n; i++ {
		for j := m.fs.journal.Load(); j != nil && j.CompactionPending(); {
			runtime.Gosched()
		}
		if i%50 == 0 {
			s.mkdir(fmt.Sprintf("/d%d", i/50), 0755)
		}
		fd := s.open(fmt.Sprintf("/d%d/file-with-a-long-name-%d", i/50, i), linux.O_RDWR|linux.O_CREAT)
		s.write(fd, pattern(100+i%300, byte(i)))
		fd.DecRef(m.ctx)
	}
}

func TestJournalLargeSnapshot(t *testing.T) {
	ctx := contexttest.Context(t)
	fd := newJournalTestFD(t)
	const regionSize = 4 * pageSize
	m1 := mountFreshJournaled(t, ctx, fd, regionSize)
	createFiles(t, m1, 600)
	if err := m1.fs.compactJournal(); err != nil {
		t.Fatalf("compactJournal: %v", err)
	}
	if m1.fs.journal.Load().Broken() {
		t.Fatalf("journal broken")
	}
	want := m1.model(t)
	m1.crash()
	m2 := mountImported(t, ctx, fd, regionSize, true /* keepJournal */)
	compareModels(t, "after compaction and crash", m2.model(t), want)
	m2.crash()
	m3 := mountImported(t, ctx, fd, regionSize, true /* keepJournal */)
	compareModels(t, "after rebuild and crash", m3.model(t), want)
}
