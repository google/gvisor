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

package vfs

import (
	"bytes"
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// genCountFD is a read-only FileDescriptionImpl representing a regular file
// that contains the number of times its DynamicBytesSource.Generate()
// implementation has been called.
type genCountFD struct {
	vfsfd FileDescription
	DynamicBytesFileDescriptionImpl

	count uint64 // accessed using atomic memory ops
}

func newGenCountFD(mnt *Mount, vfsd *Dentry) *FileDescription {
	var fd genCountFD
	fd.vfsfd.Init(&fd, mnt, vfsd)
	fd.DynamicBytesFileDescriptionImpl.SetDataSource(&fd)
	return &fd.vfsfd
}

// Release implements FileDescriptionImpl.Release.
func (fd *genCountFD) Release() {
}

// StatusFlags implements FileDescriptionImpl.StatusFlags.
func (fd *genCountFD) StatusFlags(ctx context.Context) (uint32, error) {
	return 0, nil
}

// SetStatusFlags implements FileDescriptionImpl.SetStatusFlags.
func (fd *genCountFD) SetStatusFlags(ctx context.Context, flags uint32) error {
	return syserror.EPERM
}

// Stat implements FileDescriptionImpl.Stat.
func (fd *genCountFD) Stat(ctx context.Context, opts StatOptions) (linux.Statx, error) {
	// Note that Statx.Mask == 0 in the return value.
	return linux.Statx{}, nil
}

// SetStat implements FileDescriptionImpl.SetStat.
func (fd *genCountFD) SetStat(ctx context.Context, opts SetStatOptions) error {
	return syserror.EPERM
}

// Generate implements DynamicBytesSource.Generate.
func (fd *genCountFD) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d", atomic.AddUint64(&fd.count, 1))
	return nil
}

func TestGenCountFD(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := New() // vfs.New()
	vfsObj.MustRegisterFilesystemType("testfs", FDTestFilesystemType{})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "testfs", &NewFilesystemOptions{})
	if err != nil {
		t.Fatalf("failed to create testfs root mount: %v", err)
	}
	vd := mntns.Root()
	defer vd.DecRef()

	fd := newGenCountFD(vd.Mount(), vd.Dentry())
	defer fd.DecRef()

	// The first read causes Generate to be called to fill the FD's buffer.
	buf := make([]byte, 2)
	ioseq := usermem.BytesIOSequence(buf)
	n, err := fd.Impl().Read(ctx, ioseq, ReadOptions{})
	if n != 1 || (err != nil && err != io.EOF) {
		t.Fatalf("first Read: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if want := byte('1'); buf[0] != want {
		t.Errorf("first Read: got byte %c, wanted %c", buf[0], want)
	}

	// A second read without seeking is still at EOF.
	n, err = fd.Impl().Read(ctx, ioseq, ReadOptions{})
	if n != 0 || err != io.EOF {
		t.Fatalf("second Read: got (%d, %v), wanted (0, EOF)", n, err)
	}

	// Seeking to the beginning of the file causes it to be regenerated.
	n, err = fd.Impl().Seek(ctx, 0, linux.SEEK_SET)
	if n != 0 || err != nil {
		t.Fatalf("Seek: got (%d, %v), wanted (0, nil)", n, err)
	}
	n, err = fd.Impl().Read(ctx, ioseq, ReadOptions{})
	if n != 1 || (err != nil && err != io.EOF) {
		t.Fatalf("Read after Seek: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if want := byte('2'); buf[0] != want {
		t.Errorf("Read after Seek: got byte %c, wanted %c", buf[0], want)
	}

	// PRead at the beginning of the file also causes it to be regenerated.
	n, err = fd.Impl().PRead(ctx, ioseq, 0, ReadOptions{})
	if n != 1 || (err != nil && err != io.EOF) {
		t.Fatalf("PRead: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if want := byte('3'); buf[0] != want {
		t.Errorf("PRead: got byte %c, wanted %c", buf[0], want)
	}
}
