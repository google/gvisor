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
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// tarWithEntries returns a tar archive with a root directory and the given
// entries.
func tarWithEntries(t *testing.T, hdrs []*tar.Header, contents [][]byte) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "./",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}); err != nil {
		t.Fatalf("tar.WriteHeader(dir): %v", err)
	}
	for i, hdr := range hdrs {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar.WriteHeader(%s): %v", hdr.Name, err)
		}
		if _, err := tw.Write(contents[i]); err != nil {
			t.Fatalf("tar.Writer.Write(%s): %v", hdr.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Writer.Close: %v", err)
	}
	return &buf
}

// tarWithFile returns a tar archive with a root directory and one regular file.
func tarWithFile(t *testing.T, name string, content []byte) *bytes.Buffer {
	t.Helper()
	return tarWithEntries(t, []*tar.Header{{
		Name:     name,
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(content)),
	}}, [][]byte{content})
}

// mountFromTarTestOnly mounts a tmpfs from the tar archive in src. The mount
// is released when the test ends.
func mountFromTarTestOnly(t *testing.T, ctx context.Context, src io.Reader) *filesystem {
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
			InternalData: FilesystemOpts{
				SourceTar: io.NopCloser(src),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	fs, ok := root.Mount().Filesystem().Impl().(*filesystem)
	if !ok {
		t.Fatalf("root filesystem is %T, want *tmpfs.filesystem", root.Mount().Filesystem().Impl())
	}
	return fs
}

// readFileFromTar returns the content of the named regular file in src.
func readFileFromTar(t *testing.T, src io.Reader, name string) []byte {
	t.Helper()
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("tar archive has no entry for %s", name)
		}
		if err != nil {
			t.Fatalf("tar.Reader.Next: %v", err)
		}
		if hdr.Name != name {
			continue
		}
		got, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s from archive: %v", name, err)
		}
		if int64(len(got)) != hdr.Size {
			t.Fatalf("%s header size = %d, but read %d bytes", name, hdr.Size, len(got))
		}
		return got
	}
}

// randomBytes returns size bytes that differ between calls.
func randomBytes(size int) []byte {
	b := make([]byte, size)
	var seed [32]byte
	binary.LittleEndian.PutUint64(seed[:8], rand.Uint64())
	rand.NewChaCha8(seed).Read(b)
	return b
}

// TestSourceTarLongSymlinkRelease is a regression test for a pagesUsed
// underflow on teardown. symlinkFromTar did not account the page that decRef
// unaccounts for long symlink targets.
func TestSourceTarLongSymlinkRelease(t *testing.T) {
	ctx := contexttest.Context(t)

	// A target of length shortSymlinkLen takes the long-symlink path.
	src := tarWithEntries(t, []*tar.Header{{
		Name:     "./longlink",
		Typeflag: tar.TypeSymlink,
		Linkname: strings.Repeat("a", shortSymlinkLen),
		Mode:     0777,
	}}, [][]byte{nil})

	// Without the fix, the release on cleanup underflows fs.pagesUsed and panics.
	mountFromTarTestOnly(t, ctx, src)
}

// TestTarRegularFileRoundTrip checks that file contents survive a restore and
// archive. Sizes straddle the 32 KiB io.Copy buffer.
func TestTarRegularFileRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 32<<10 - 1, 32 << 10, 32<<10 + 1, 4<<20 + 1234} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			ctx := contexttest.Context(t)
			want := randomBytes(size)
			fs := mountFromTarTestOnly(t, ctx, tarWithFile(t, "./file", want))

			var out bytes.Buffer
			if err := fs.tarWrite(ctx, &out, tarDefaultWriterCallbacks{}); err != nil {
				t.Fatalf("tarWrite: %v", err)
			}
			if got := readFileFromTar(t, &out, "./file"); !bytes.Equal(got, want) {
				t.Fatalf("./file content differs after round trip (got %d bytes, want %d)", len(got), len(want))
			}
		})
	}
}

// TestTarRegularFileAllocation checks that restore and archive memory use does
// not scale with file size.
func TestTarRegularFileAllocation(t *testing.T) {
	const (
		fileSize = 4 << 20
		maxAlloc = 1 << 20
	)
	ctx := contexttest.Context(t)
	src := tarWithFile(t, "./file", randomBytes(fileSize))

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fs := mountFromTarTestOnly(t, ctx, src)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("restoring a %d byte file allocated %d bytes", fileSize, allocated)
	if allocated > maxAlloc {
		t.Errorf("restoring a %d byte file allocated %d bytes, want at most %d", fileSize, allocated, maxAlloc)
	}

	// Discard the archive so that only archiving is measured.
	runtime.ReadMemStats(&before)
	if err := fs.tarWrite(ctx, io.Discard, tarDefaultWriterCallbacks{}); err != nil {
		t.Fatalf("tarWrite: %v", err)
	}
	runtime.ReadMemStats(&after)
	allocated = after.TotalAlloc - before.TotalAlloc
	t.Logf("archiving a %d byte file allocated %d bytes", fileSize, allocated)
	if allocated > maxAlloc {
		t.Errorf("archiving a %d byte file allocated %d bytes, want at most %d", fileSize, allocated, maxAlloc)
	}
}
