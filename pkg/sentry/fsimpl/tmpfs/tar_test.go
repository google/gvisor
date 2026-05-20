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
