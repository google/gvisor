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

package control

import (
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

type mockFDImpl struct {
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	data       []byte
	isSeekable bool
	readOffset int64
}

func (m *mockFDImpl) Release(context.Context) {}

func (m *mockFDImpl) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	if m.readOffset >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, m.data[m.readOffset:])
	m.readOffset += int64(n)
	return int64(n), err
}

func (m *mockFDImpl) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, _ vfs.ReadOptions) (int64, error) {
	if !m.isSeekable {
		return 0, linuxerr.ESPIPE
	}
	if offset >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, m.data[offset:])
	return int64(n), err
}

func setupMockFD(ctx context.Context, t *testing.T, data []byte, isSeekable bool) (*vfs.FileDescription, func()) {
	t.Helper()
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init failed: %v", err)
	}
	vd := vfsObj.NewAnonVirtualDentry("mock")
	defer vd.DecRef(ctx)

	fd := &vfs.FileDescription{}
	impl := &mockFDImpl{
		data:       data,
		isSeekable: isSeekable,
	}

	creds := auth.CredentialsFromContext(ctx)
	if err := fd.Init(impl, linux.O_RDONLY, creds, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		t.Fatalf("fd.Init failed: %v", err)
	}

	return fd, func() {
		fd.DecRef(ctx)
	}
}

func TestFdReader_Seekable(t *testing.T) {
	ctx := contexttest.Context(t)
	data := []byte("hello world")
	const seekable = true
	fd, cleanup := setupMockFD(ctx, t, data, seekable)
	defer cleanup()

	// Read from offset 0.
	reader0 := &fdReader{ctx: ctx, fd: fd, offset: 0}
	buf0 := make([]byte, 5)
	n, err := reader0.Read(buf0)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 5 || string(buf0) != "hello" {
		t.Fatalf("got %d bytes %q, want 5 bytes %q", n, string(buf0), "hello")
	}

	// Read from offset 6 with a buffer larger than remaining data.
	reader6 := &fdReader{ctx: ctx, fd: fd, offset: 6}
	buf6 := make([]byte, 100)
	n, err = reader6.Read(buf6)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 5 || string(buf6[:n]) != "world" {
		t.Fatalf("got %d bytes %q, want 5 bytes %q", n, string(buf6[:n]), "world")
	}

	// Ensure offset advanced correctly.
	if reader6.offset != 11 {
		t.Fatalf("got %d, want reader offset 11", reader6.offset)
	}

	// Read at or past EOF.
	readerEOF := &fdReader{ctx: ctx, fd: fd, offset: 11}
	bufEOF := make([]byte, 5)
	n, err = readerEOF.Read(bufEOF)
	if err != io.EOF {
		t.Fatalf("got %v, want io.EOF", err)
	}
	if n != 0 {
		t.Fatalf("got %d, want 0 bytes", n)
	}
}

func TestFdReader_NonSeekable(t *testing.T) {
	ctx := contexttest.Context(t)
	data := []byte("hello world")
	const seekable = false
	fd, cleanup := setupMockFD(ctx, t, data, seekable)
	defer cleanup()

	// Read from offset 0, should use Read (which works for non-seekable like pipes).
	// Let's read with a larger buffer than available data.
	reader0 := &fdReader{ctx: ctx, fd: fd, offset: 0}
	buf0 := make([]byte, 100)
	n, err := reader0.Read(buf0)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 11 || string(buf0[:n]) != "hello world" {
		t.Fatalf("got %d bytes %q, want 11 bytes %q", n, string(buf0[:n]), "hello world")
	}

	// Read at or past EOF.
	bufEOF := make([]byte, 5)
	n, err = reader0.Read(bufEOF)
	if err != io.EOF {
		t.Fatalf("got %v, want io.EOF", err)
	}
	if n != 0 {
		t.Fatalf("got %d, want 0 bytes", n)
	}

	// Read from offset 6, should use PRead, which fails with ESPIPE.
	reader6 := &fdReader{ctx: ctx, fd: fd, offset: 6}
	buf6 := make([]byte, 5)
	_, err = reader6.Read(buf6)
	if !linuxerr.Equals(linuxerr.ESPIPE, err) {
		t.Fatalf("got %v, want ESPIPE", err)
	}
}
