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
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// TestSourceTarLongSymlinkRelease is a regression test for a bug where
// symlinkFromTar did not call fs.accountPages(1) for symlinks whose target
// length is >= shortSymlinkLen, while (*inode).decRef unconditionally calls
// fs.unaccountPages(1) on teardown for such symlinks. The asymmetry
// underflowed fs.pagesUsed and panicked filesystem.unaccountPages on
// mount-namespace teardown.
func TestSourceTarLongSymlinkRelease(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	// Symlink target of length shortSymlinkLen (128) triggers the long-symlink
	// accounting path.
	longTarget := strings.Repeat("a", shortSymlinkLen)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./longlink",
		Typeflag: tar.TypeSymlink,
		Linkname: longTarget,
		Mode:     0777,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(symlink): %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Writer.Close: %v", err)
	}

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOpts{
				SourceTar: io.NopCloser(&buf),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}

	// Drop the only reference to trigger filesystem teardown. Without the fix,
	// releaseChildrenLocked -> inode.decRef -> fs.unaccountPages(1) underflows
	// fs.pagesUsed and panics here.
	mntns.DecRef(ctx)
}

type mockMappingSpace struct {
	invalidated atomicbitops.Uint32
}

func (m *mockMappingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
	m.invalidated.Store(1)
}

// TestTarRestore verifies that tarRestore invalidates existing memory mappings,
// empties and unlinks existing files to size 0, wipes directory hierarchy, and
// repopulates files and directories from a mock tar stream.
func TestTarRestore(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		t.Fatalf("newTmpfsRoot failed: %v", err)
	}
	defer cleanup()

	oldPop := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("oldfile"),
	}
	oldFD, err := vfsObj.OpenAt(ctx, creds, oldPop, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("OpenAt(oldfile) failed: %v", err)
	}
	defer oldFD.DecRef(ctx)

	oldData := []byte("old_file_data_before_restore")
	src := usermem.BytesIOSequence(oldData)
	if n, err := oldFD.Write(ctx, src, vfs.WriteOptions{}); err != nil || n != int64(len(oldData)) {
		t.Fatalf("oldFD.Write failed: got (%d, %v), want (%d, nil)", n, err, len(oldData))
	}

	rf := oldFD.Dentry().Impl().(*dentry).inode.impl.(*regularFile)
	var ms mockMappingSpace
	rf.mapsMu.Lock()
	rf.mappings.AddMapping(&ms, hostarch.AddrRange{Start: 0x1000, End: 0x2000}, 0, false)
	rf.mapsMu.Unlock()

	statBefore, err := oldFD.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_SIZE})
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if statBefore.Size != uint64(len(oldData)) {
		t.Fatalf("oldfile size before restore: got %d, want %d", statBefore.Size, len(oldData))
	}

	const newFileContent = "new_file_restored_from_tar"
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./newfile",
		Typeflag: tar.TypeReg,
		Size:     int64(len(newFileContent)),
		Mode:     0644,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(newfile): %v", err)
	}
	if _, err := tw.Write([]byte(newFileContent)); err != nil {
		t.Fatalf("tar.Write(newfile): %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}

	fs := root.Mount().Filesystem().Impl().(*filesystem)
	cb := &tarDefaultReaderCallbacks{
		headerToContent: make(map[*tar.Header]*bytes.Buffer),
	}
	if err := fs.tarRestore(ctx, &tarBuf, cb); err != nil {
		t.Fatalf("tarRestore failed: %v", err)
	}

	// Verify that existing mappings were invalidated.
	if ms.invalidated.Load() != 1 {
		t.Fatalf("Expected mock mapping to be invalidated by tarRestore")
	}

	// Verify that oldFD remains bound to the unlinked regularFile, emptied to size 0.
	statAfter, err := oldFD.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_SIZE})
	if err != nil {
		t.Fatalf("Stat after restore failed: %v", err)
	}
	if statAfter.Size != 0 {
		t.Fatalf("Expected oldfile size 0 after restore, got %d", statAfter.Size)
	}
	readBuf := make([]byte, 100)
	dst := usermem.BytesIOSequence(readBuf)
	n, err := oldFD.Read(ctx, dst, vfs.ReadOptions{})
	if n != 0 || (err != nil && err != io.EOF) {
		t.Fatalf("oldFD.Read after restore: got (%d, %v), want (0, nil)", n, err)
	}

	// Verify that /oldfile is gone from root directory lookup.
	lookupOldPop := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("oldfile"),
	}
	_, err = vfsObj.OpenAt(ctx, creds, lookupOldPop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("OpenAt(oldfile) after restore: got err %v, want ENOENT", err)
	}

	// Verify that /newfile exists and contains the restored contents.
	newPop := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("newfile"),
	}
	newFD, err := vfsObj.OpenAt(ctx, creds, newPop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(newfile) after restore failed: %v", err)
	}
	defer newFD.DecRef(ctx)

	newDst := usermem.BytesIOSequence(readBuf)
	n, err = newFD.Read(ctx, newDst, vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("newFD.Read failed: %v", err)
	}
	if got := string(readBuf[:n]); got != newFileContent {
		t.Fatalf("newfile content: got %q, want %q", got, newFileContent)
	}
}
