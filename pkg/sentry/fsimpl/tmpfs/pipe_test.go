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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const fileName = "mypipe"

func TestSeparateFDs(t *testing.T) {
	ctx, creds, vfsObj, root := setup(t)
	defer root.DecRef(ctx)

	// Open the read side. This is done in a concurrently because opening
	// One end the pipe blocks until the other end is opened.
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(fileName),
		FollowFinalSymlink: true,
	}
	rfdchan := make(chan *vfs.FileDescription)
	go func() {
		openOpts := vfs.OpenOptions{Flags: linux.O_RDONLY}
		rfd, _ := vfsObj.OpenAt(ctx, creds, &pop, &openOpts)
		rfdchan <- rfd
	}()

	// Open the write side.
	openOpts := vfs.OpenOptions{Flags: linux.O_WRONLY}
	wfd, err := vfsObj.OpenAt(ctx, creds, &pop, &openOpts)
	if err != nil {
		t.Fatalf("failed to open pipe for writing %q: %v", fileName, err)
	}
	defer wfd.DecRef(ctx)

	rfd, ok := <-rfdchan
	if !ok {
		t.Fatalf("failed to open pipe for reading %q", fileName)
	}
	defer rfd.DecRef(ctx)

	const msg = "vamos azul"
	checkEmpty(ctx, t, rfd)
	checkWrite(ctx, t, wfd, msg)
	checkRead(ctx, t, rfd, msg)
}

func TestNonblockingRead(t *testing.T) {
	ctx, creds, vfsObj, root := setup(t)
	defer root.DecRef(ctx)

	// Open the read side as nonblocking.
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(fileName),
		FollowFinalSymlink: true,
	}
	openOpts := vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_NONBLOCK}
	rfd, err := vfsObj.OpenAt(ctx, creds, &pop, &openOpts)
	if err != nil {
		t.Fatalf("failed to open pipe for reading %q: %v", fileName, err)
	}
	defer rfd.DecRef(ctx)

	// Open the write side.
	openOpts = vfs.OpenOptions{Flags: linux.O_WRONLY}
	wfd, err := vfsObj.OpenAt(ctx, creds, &pop, &openOpts)
	if err != nil {
		t.Fatalf("failed to open pipe for writing %q: %v", fileName, err)
	}
	defer wfd.DecRef(ctx)

	const msg = "geh blau"
	checkEmpty(ctx, t, rfd)
	checkWrite(ctx, t, wfd, msg)
	checkRead(ctx, t, rfd, msg)
}

func TestNonblockingWriteError(t *testing.T) {
	ctx, creds, vfsObj, root := setup(t)
	defer root.DecRef(ctx)

	// Open the write side as nonblocking, which should return ENXIO.
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(fileName),
		FollowFinalSymlink: true,
	}
	openOpts := vfs.OpenOptions{Flags: linux.O_WRONLY | linux.O_NONBLOCK}
	_, err := vfsObj.OpenAt(ctx, creds, &pop, &openOpts)
	if !linuxerr.Equals(linuxerr.ENXIO, err) {
		t.Fatalf("expected ENXIO, but got error: %v", err)
	}
}

func TestSingleFD(t *testing.T) {
	ctx, creds, vfsObj, root := setup(t)
	defer root.DecRef(ctx)

	// Open the pipe as readable and writable.
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(fileName),
		FollowFinalSymlink: true,
	}
	openOpts := vfs.OpenOptions{Flags: linux.O_RDWR}
	fd, err := vfsObj.OpenAt(ctx, creds, &pop, &openOpts)
	if err != nil {
		t.Fatalf("failed to open pipe for writing %q: %v", fileName, err)
	}
	defer fd.DecRef(ctx)

	const msg = "forza blu"
	checkEmpty(ctx, t, fd)
	checkWrite(ctx, t, fd, msg)
	checkRead(ctx, t, fd, msg)
}

// setup creates a VFS with a pipe in the root directory at path fileName. The
// returned VirtualDentry must be DecRef()'d be the caller. It calls t.Fatal
// upon failure.
func setup(t *testing.T) (context.Context, *auth.Credentials, *vfs.VirtualFilesystem, vfs.VirtualDentry) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	// Create VFS.
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{})
	if err != nil {
		t.Fatalf("failed to create tmpfs root mount: %v", err)
	}

	// Create the pipe.
	root := mntns.Root()
	root.IncRef()
	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(fileName),
	}
	mknodOpts := vfs.MknodOptions{Mode: linux.ModeNamedPipe | 0644}
	if err := vfsObj.MknodAt(ctx, creds, &pop, &mknodOpts); err != nil {
		t.Fatalf("failed to create file %q: %v", fileName, err)
	}

	// Sanity check: the file pipe exists and has the correct mode.
	stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(fileName),
		FollowFinalSymlink: true,
	}, &vfs.StatOptions{})
	if err != nil {
		t.Fatalf("stat(%q) failed: %v", fileName, err)
	}
	if stat.Mode&^linux.S_IFMT != 0644 {
		t.Errorf("got wrong permissions (%0o)", stat.Mode)
	}
	if stat.Mode&linux.S_IFMT != linux.ModeNamedPipe {
		t.Errorf("got wrong file type (%0o)", stat.Mode)
	}

	return ctx, creds, vfsObj, root
}

// checkEmpty calls t.Fatal if the pipe in fd is not empty.
func checkEmpty(ctx context.Context, t *testing.T, fd *vfs.FileDescription) {
	readData := make([]byte, 1)
	dst := usermem.BytesIOSequence(readData)
	bytesRead, err := fd.Read(ctx, dst, vfs.ReadOptions{})
	if err != linuxerr.ErrWouldBlock {
		t.Fatalf("expected ErrWouldBlock reading from empty pipe %q, but got: %v", fileName, err)
	}
	if bytesRead != 0 {
		t.Fatalf("expected to read 0 bytes, but got %d", bytesRead)
	}
}

// checkWrite calls t.Fatal if it fails to write all of msg to fd.
func checkWrite(ctx context.Context, t *testing.T, fd *vfs.FileDescription, msg string) {
	writeData := []byte(msg)
	src := usermem.BytesIOSequence(writeData)
	bytesWritten, err := fd.Write(ctx, src, vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("error writing to pipe %q: %v", fileName, err)
	}
	if bytesWritten != int64(len(writeData)) {
		t.Fatalf("expected to write %d bytes, but wrote %d", len(writeData), bytesWritten)
	}
}

// checkRead calls t.Fatal if it fails to read msg from fd.
func checkRead(ctx context.Context, t *testing.T, fd *vfs.FileDescription, msg string) {
	readData := make([]byte, len(msg))
	dst := usermem.BytesIOSequence(readData)
	bytesRead, err := fd.Read(ctx, dst, vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("error reading from pipe %q: %v", fileName, err)
	}
	if bytesRead != int64(len(msg)) {
		t.Fatalf("expected to read %d bytes, but got %d", len(msg), bytesRead)
	}
	if !bytes.Equal(readData, []byte(msg)) {
		t.Fatalf("expected to read %q from pipe, but got %q", msg, string(readData))
	}
}
