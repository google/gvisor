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

// TestTarRestoreWipeChildrenState verifies that wipeChildrenLocked properly resets
// dir.childList, dir.numChildren, and directory stat size without leaking old dentries
// or phantom child counts after tarRestore.
func TestTarRestoreWipeChildrenState(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	// Build initial tar archive with directory and children.
	var buf1 bytes.Buffer
	tw1 := tar.NewWriter(&buf1)
	if err := tw1.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	if err := tw1.WriteHeader(&tar.Header{
		Name:     "./file1",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     0,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(file1): %v", err)
	}
	if err := tw1.WriteHeader(&tar.Header{
		Name:     "./file2",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     0,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(file2): %v", err)
	}
	if err := tw1.WriteHeader(&tar.Header{
		Name:     "./subdir/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(subdir): %v", err)
	}
	if err := tw1.WriteHeader(&tar.Header{
		Name:     "./subdir/subfile",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     0,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(subfile): %v", err)
	}
	if err := tw1.Close(); err != nil {
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
				SourceTar: io.NopCloser(&buf1),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	// Verify root directory size before wipe: direntSize * (2 + 3 children: file1, file2, subdir).
	stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
	}, &vfs.StatOptions{})
	if err != nil {
		t.Fatalf("StatAt failed: %v", err)
	}
	wantInitialSize := uint64(direntSize * 5)
	if stat.Size != wantInitialSize {
		t.Errorf("initial root size = %d, want %d", stat.Size, wantInitialSize)
	}

	// Build a second mount with the desired restored state: only ./ and ./newfile.
	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	if err := tw2.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	if err := tw2.WriteHeader(&tar.Header{
		Name:     "./newfile",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     0,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(newfile): %v", err)
	}
	if err := tw2.Close(); err != nil {
		t.Fatalf("tar.Writer.Close: %v", err)
	}

	mntns2, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOpts{
				SourceTar: io.NopCloser(&buf2),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace(mntns2): %v", err)
	}
	defer mntns2.DecRef(ctx)
	root2 := mntns2.Root(ctx)
	defer root2.DecRef(ctx)

	var fsCkptBuf bytes.Buffer
	if err := FSCheckpointWrite(ctx, root2.Mount().Filesystem(), &fsCkptBuf); err != nil {
		t.Fatalf("FSCheckpointWrite failed: %v", err)
	}

	fs := root.Mount().Filesystem().Impl().(*filesystem)
	if err := fs.tarRestore(ctx, &fsCkptBuf); err != nil {
		t.Fatalf("fs.tarRestore failed: %v", err)
	}

	// Verify root directory size after wipe & restore: direntSize * (2 + 1 child: newfile).
	statAfter, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
	}, &vfs.StatOptions{})
	if err != nil {
		t.Fatalf("StatAt after restore failed: %v", err)
	}
	wantAfterSize := uint64(direntSize * 3)
	if statAfter.Size != wantAfterSize {
		t.Errorf("root size after restore = %d, want %d", statAfter.Size, wantAfterSize)
	}

	// Enumerate directory entries with IterDirents.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		t.Fatalf("OpenAt root failed: %v", err)
	}
	defer fd.DecRef(ctx)

	var names []string
	err = fd.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
		names = append(names, dirent.Name)
		return nil
	}))
	if err != nil {
		t.Fatalf("IterDirents failed: %v", err)
	}

	wantNames := []string{".", "..", "newfile"}
	if len(names) != len(wantNames) {
		t.Fatalf("IterDirents returned %v, want %v", names, wantNames)
	}
	for i, name := range names {
		if name != wantNames[i] {
			t.Errorf("IterDirents entry %d = %q, want %q", i, name, wantNames[i])
		}
	}
}
