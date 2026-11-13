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
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs/journal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/usage"
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
	_, st, err := journal.Open(mf, journal.Options{
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

func (m *journaledTmpfs) pop(path string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: m.root, Start: m.root, Path: fspath.Parse(path)}
}

func rootCreds() *auth.Credentials {
	return auth.NewRootCredentials(auth.NewRootUserNamespace())
}

func TestRebuildFromJournal(t *testing.T) {
	ctx := contexttest.Context(t)
	fd := newJournalTestFD(t)
	mf, err := pgalloc.NewMemoryFile(dupFile(t, fd, "filestore"), pgalloc.MemoryFileOpts{
		DelayedEviction:         pgalloc.DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	j, err := journal.Create(mf, journal.Options{BuildID: "build", ImageID: "image"})
	if err != nil {
		mf.Destroy()
		t.Fatalf("journal.Create: %v", err)
	}
	fr, err := mf.Allocate(pageSize, pgalloc.AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	s, err := j.BeginSnapshot(1, 3, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(&journal.InodeRecord{Ino: 1, Mode: linux.S_IFDIR | 0755})
	s.Inode(&journal.InodeRecord{Ino: 2, Mode: linux.S_IFREG | 0640, UID: 7, Size: pageSize})
	s.ExtentSet(2, 0, pageSize, fr.Start)
	s.DirentAdd(1, "file", 2)
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	j.Close()
	mf.Destroy()

	m := mountImported(t, ctx, fd, 0, false)
	defer func() {
		m.fs.Release(m.ctx)
		m.mf.Destroy()
	}()
	st, err := m.vfsObj.StatAt(m.ctx, rootCreds(), m.pop("/file"), &vfs.StatOptions{Mask: linux.STATX_UID | linux.STATX_SIZE})
	if err != nil || st.UID != 7 || st.Size != pageSize {
		t.Fatalf("StatAt(/file) = %+v, %v", st, err)
	}
}
