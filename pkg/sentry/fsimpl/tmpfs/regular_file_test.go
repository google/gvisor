// Copyright 2019 The gVisor Authors.
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
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// newFileFD creates a new file in a new tmpfs mount, and returns the FD. If
// the returned err is not nil, then cleanup should be called when the FD is no
// longer needed.
func newFileFD(ctx context.Context, filename string) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := vfs.New()
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.GetFilesystemOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create tmpfs root mount: %v", err)
	}
	root := mntns.Root()

	// Create the file that will be write/read.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(filename),
		FollowFinalSymlink: true,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		root.DecRef()
		mntns.DecRef(vfsObj)
		return nil, nil, fmt.Errorf("failed to create file %q: %v", filename, err)
	}

	return fd, func() {
		root.DecRef()
		mntns.DecRef(vfsObj)
	}, nil
}

// Test that we can write some data to a file and read it back.`
func TestSimpleWriteRead(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, "simpleReadWrite")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Write.
	data := []byte("foobarbaz")
	n, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Write got short write length %d, want %d", n, len(data))
	}
	if got, want := fd.Impl().(*regularFileFD).off, int64(len(data)); got != want {
		t.Errorf("fd.Write left offset at %d, want %d", got, want)
	}

	// Seek back to beginning.
	if _, err := fd.Seek(ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatalf("fd.Seek failed: %v", err)
	}
	if got, want := fd.Impl().(*regularFileFD).off, int64(0); got != want {
		t.Errorf("fd.Seek(0) left offset at %d, want %d", got, want)
	}

	// Read.
	buf := make([]byte, len(data))
	n, err = fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("fd.Read failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Read got short read length %d, want %d", n, len(data))
	}
	if got, want := string(buf), string(data); got != want {
		t.Errorf("Read got %q want %s", got, want)
	}
	if got, want := fd.Impl().(*regularFileFD).off, int64(len(data)); got != want {
		t.Errorf("fd.Write left offset at %d, want %d", got, want)
	}
}

func TestPWrite(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, "PRead")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Fill file with 1k 'a's.
	data := bytes.Repeat([]byte{'a'}, 1000)
	n, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Write got short write length %d, want %d", n, len(data))
	}

	// Write "gVisor is awesome" at various offsets.
	buf := []byte("gVisor is awesome")
	offsets := []int{0, 1, 2, 10, 20, 50, 100, len(data) - 100, len(data) - 1, len(data), len(data) + 1}
	for _, offset := range offsets {
		name := fmt.Sprintf("PWrite offset=%d", offset)
		t.Run(name, func(t *testing.T) {
			n, err := fd.PWrite(ctx, usermem.BytesIOSequence(buf), int64(offset), vfs.WriteOptions{})
			if err != nil {
				t.Errorf("fd.PWrite got err %v want nil", err)
			}
			if n != int64(len(buf)) {
				t.Errorf("fd.PWrite got %d bytes want %d", n, len(buf))
			}

			// Update data to reflect expected file contents.
			if len(data) < offset+len(buf) {
				data = append(data, make([]byte, (offset+len(buf))-len(data))...)
			}
			copy(data[offset:], buf)

			// Read the whole file and compare with data.
			readBuf := make([]byte, len(data))
			n, err = fd.PRead(ctx, usermem.BytesIOSequence(readBuf), 0, vfs.ReadOptions{})
			if err != nil {
				t.Fatalf("fd.PRead failed: %v", err)
			}
			if n != int64(len(data)) {
				t.Errorf("fd.PRead got short read length %d, want %d", n, len(data))
			}
			if got, want := string(readBuf), string(data); got != want {
				t.Errorf("PRead got %q want %s", got, want)
			}

		})
	}
}

func TestPRead(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, "PRead")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Write 100 sequences of 'gVisor is awesome'.
	data := bytes.Repeat([]byte("gVisor is awsome"), 100)
	n, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Write got short write length %d, want %d", n, len(data))
	}

	// Read various sizes from various offsets.
	sizes := []int{0, 1, 2, 10, 20, 50, 100, 1000}
	offsets := []int{0, 1, 2, 10, 20, 50, 100, 1000, len(data) - 100, len(data) - 1, len(data), len(data) + 1}

	for _, size := range sizes {
		for _, offset := range offsets {
			name := fmt.Sprintf("PRead offset=%d size=%d", offset, size)
			t.Run(name, func(t *testing.T) {
				var (
					wantRead []byte
					wantErr  error
				)
				if offset < len(data) {
					wantRead = data[offset:]
				} else if size > 0 {
					wantErr = io.EOF
				}
				if offset+size < len(data) {
					wantRead = wantRead[:size]
				}
				buf := make([]byte, size)
				n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), int64(offset), vfs.ReadOptions{})
				if err != wantErr {
					t.Errorf("fd.PRead got err %v want %v", err, wantErr)
				}
				if n != int64(len(wantRead)) {
					t.Errorf("fd.PRead got %d bytes want %d", n, len(wantRead))
				}
				if got := string(buf[:n]); got != string(wantRead) {
					t.Errorf("fd.PRead got %q want %q", got, string(wantRead))
				}
			})
		}
	}
}
