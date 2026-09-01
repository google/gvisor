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
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
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
	lastRange   hostarch.AddrRange
}

func (m *mockMappingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
	m.invalidated.Store(1)
	m.lastRange = ar
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

type mockFSTarProvider struct {
	getFSTarFunc func(id checkpoint.ResourceID) (io.ReadCloser, error)
}

func (m *mockFSTarProvider) GetFSTar(id checkpoint.ResourceID) (io.ReadCloser, error) {
	return m.getFSTarFunc(id)
}

func TestCompleteRestoreResourceIDNormalization(t *testing.T) {
	ctx := contexttest.Context(t)

	_, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		t.Fatalf("newTmpfsRoot failed: %v", err)
	}
	defer cleanup()

	tf, err := os.CreateTemp(t.TempDir(), "memfile")
	if err != nil {
		t.Fatalf("os.CreateTemp failed: %v", err)
	}
	defer os.Remove(tf.Name())

	uncleanedID := checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp/"}
	cleanedID := uncleanedID.Clean()

	mf, err := pgalloc.NewMemoryFile(tf, pgalloc.MemoryFileOpts{
		DelayedEviction:         pgalloc.DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DiskBackedFile:          true,
		ResourceID:              uncleanedID,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile failed: %v", err)
	}
	defer mf.Destroy()

	fs := root.Mount().Filesystem().Impl().(*filesystem)
	fs.mf = mf

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}
	tarBytes := tarBuf.Bytes()

	var requestedID checkpoint.ResourceID
	tarProvider := &mockFSTarProvider{
		getFSTarFunc: func(id checkpoint.ResourceID) (io.ReadCloser, error) {
			requestedID = id
			return io.NopCloser(bytes.NewReader(tarBytes)), nil
		},
	}

	// Context with cleaned ID in CtxFSCheckpointedMemoryFiles, but uncleaned ID on fs.mf.
	restoreCtx := context.WithValue(ctx, vfs.CtxFSTarProvider, tarProvider)
	restoreCtx = context.WithValue(restoreCtx, pgalloc.CtxFSCheckpointedMemoryFiles, map[checkpoint.ResourceID]struct{}{
		cleanedID: {},
	})

	if err := fs.CompleteRestore(restoreCtx, vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore failed with unnormalized ResourceID: %v", err)
	}

	if requestedID != cleanedID {
		t.Errorf("tarProvider.GetFSTar got ID %+v, want cleaned %+v", requestedID, cleanedID)
	}
}

// TestTarRestoreInvalidatesZeroByteAndBeyondEOFMappings verifies that tarRestore
// invalidates mappings on 0-byte files as well as mappings extending beyond EOF.
func TestTarRestoreInvalidatesZeroByteAndBeyondEOFMappings(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		t.Fatalf("newTmpfsRoot failed: %v", err)
	}
	defer cleanup()

	// 1. Create a 0-byte file and establish a mapping.
	zeroFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("zerofile"),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("OpenAt(zerofile) failed: %v", err)
	}
	defer zeroFD.DecRef(ctx)

	rfZero := zeroFD.Dentry().Impl().(*dentry).inode.impl.(*regularFile)
	var msZero mockMappingSpace
	rfZero.mapsMu.Lock()
	rfZero.mappings.AddMapping(&msZero, hostarch.AddrRange{Start: 0x1000, End: 0x2000}, 0, false)
	rfZero.mapsMu.Unlock()

	// 2. Create a 1-page (4096 byte) file and establish a 2-page (8192 byte) mapping extending past EOF.
	beyondFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("beyondfile"),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("OpenAt(beyondfile) failed: %v", err)
	}
	defer beyondFD.DecRef(ctx)

	pageData := make([]byte, hostarch.PageSize)
	if n, err := beyondFD.Write(ctx, usermem.BytesIOSequence(pageData), vfs.WriteOptions{}); err != nil || n != int64(len(pageData)) {
		t.Fatalf("beyondFD.Write failed: got (%d, %v), want (%d, nil)", n, err, len(pageData))
	}

	rfBeyond := beyondFD.Dentry().Impl().(*dentry).inode.impl.(*regularFile)
	var msBeyond mockMappingSpace
	beyondRange := hostarch.AddrRange{Start: 0x3000, End: 0x5000} // 2 pages, file is 1 page
	rfBeyond.mapsMu.Lock()
	rfBeyond.mappings.AddMapping(&msBeyond, beyondRange, 0, false)
	rfBeyond.mapsMu.Unlock()

	// 3. Run tarRestore.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
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

	// 4. Verify that the 0-byte file's mapping was invalidated.
	if msZero.invalidated.Load() != 1 {
		t.Errorf("Expected 0-byte file mapping to be invalidated, got count %d", msZero.invalidated.Load())
	}

	// 5. Verify that the mapping extending beyond EOF was invalidated for its entire range.
	if msBeyond.invalidated.Load() != 1 {
		t.Errorf("Expected beyond-EOF mapping to be invalidated, got count %d", msBeyond.invalidated.Load())
	}
	if msBeyond.lastRange != beyondRange {
		t.Errorf("Expected beyond-EOF mapping invalidated range %v, got %v", beyondRange, msBeyond.lastRange)
	}
}

// TestTarRestoreWithMountedChildDirectory verifies that tarRestore correctly
// handles child dentries that have active submounts (logging a warning and
// wiping without panicking).
func TestTarRestoreWithMountedChildDirectory(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		t.Fatalf("newTmpfsRoot failed: %v", err)
	}
	defer cleanup()

	// Create a subdirectory that will act as a mount point.
	pop := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("mountpoint"),
	}
	if err := vfsObj.MkdirAt(ctx, creds, pop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt failed: %v", err)
	}

	// Mount a submount onto the directory.
	subMnt, err := vfsObj.MountAt(ctx, creds, "", pop, "tmpfs", &vfs.MountOptions{})
	if err != nil {
		t.Fatalf("MountAt failed: %v", err)
	}
	defer subMnt.DecRef(ctx)

	// Verify child dentry reports IsMounted() == true.
	fs := root.Mount().Filesystem().Impl().(*filesystem)
	fs.mu.Lock()
	dir := root.Dentry().Impl().(*dentry).inode.impl.(*directory)
	childDentry := dir.childMap["mountpoint"]
	if childDentry == nil {
		fs.mu.Unlock()
		t.Fatalf("child dentry 'mountpoint' not found")
	}
	if !childDentry.vfsd.IsMounted() {
		fs.mu.Unlock()
		t.Errorf("childDentry.vfsd.IsMounted() = false, want true")
	}
	fs.mu.Unlock()

	// Execute tarRestore.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}

	cb := &tarDefaultReaderCallbacks{
		headerToContent: make(map[*tar.Header]*bytes.Buffer),
	}
	if err := fs.tarRestore(ctx, &tarBuf, cb); err != nil {
		t.Fatalf("tarRestore failed: %v", err)
	}
}
