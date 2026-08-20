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
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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

// TestTarUpperLayerLargeFile checks that a file larger than the buffer it is
// copied through is written to the archive intact.
func TestTarUpperLayerLargeFile(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	// Not a multiple of the copy buffer, so a truncated final copy is caught.
	const fileSize = 4<<20 + 1234
	want := make([]byte, fileSize)
	for i := range want {
		want[i] = byte(i % 251)
	}

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
		Name:     "./big",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     fileSize,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(file): %v", err)
	}
	if _, err := tw.Write(want); err != nil {
		t.Fatalf("tar.Writer.Write: %v", err)
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
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	fs, ok := root.Mount().Filesystem().Impl().(*filesystem)
	if !ok {
		t.Fatalf("root filesystem is %T, want *tmpfs.filesystem", root.Mount().Filesystem().Impl())
	}

	var out bytes.Buffer
	if err := fs.tarWrite(ctx, &out, tarDefaultWriterCallbacks{}); err != nil {
		t.Fatalf("tarWrite: %v", err)
	}

	tr := tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatal("tarWrite output has no entry for ./big")
		}
		if err != nil {
			t.Fatalf("tar.Reader.Next: %v", err)
		}
		if hdr.Name != "./big" {
			continue
		}
		if hdr.Size != fileSize {
			t.Fatalf("./big header size = %d, want %d", hdr.Size, fileSize)
		}
		got, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading ./big from archive: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("./big content differs from what was written (got %d bytes, want %d)", len(got), len(want))
		}
		return
	}
}

// TestTarUpperLayerLargeFileAllocation checks that archiving a file does not
// allocate in proportion to its size, which for a large file could exhaust the
// memory available to the sentry.
func TestTarUpperLayerLargeFileAllocation(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	const fileSize = 32 << 20
	content := make([]byte, fileSize)
	for i := range content {
		content[i] = byte(i % 251)
	}

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
		Name:     "./big",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     fileSize,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(file): %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar.Writer.Write: %v", err)
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
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	fs, ok := root.Mount().Filesystem().Impl().(*filesystem)
	if !ok {
		t.Fatalf("root filesystem is %T, want *tmpfs.filesystem", root.Mount().Filesystem().Impl())
	}

	// Discard the archive so that only what archiving allocates is measured.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := fs.tarWrite(ctx, io.Discard, tarDefaultWriterCallbacks{}); err != nil {
		t.Fatalf("tarWrite: %v", err)
	}
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("archiving a %d byte file allocated %d bytes", fileSize, allocated)
	if allocated > fileSize/2 {
		t.Errorf("archiving a %d byte file allocated %d bytes, want at most %d", fileSize, allocated, fileSize/2)
	}
}
