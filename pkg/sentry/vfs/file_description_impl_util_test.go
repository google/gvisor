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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// fileDescription is the common fd struct which a filesystem implementation
// embeds in all of its file description implementations as required.
type fileDescription struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	NoLockFD
}

// genCount contains the number of times its DynamicBytesSource.Generate()
// implementation has been called.
type genCount struct {
	count uint64 // accessed using atomic memory ops
}

// Generate implements DynamicBytesSource.Generate.
func (g *genCount) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d", atomic.AddUint64(&g.count, 1))
	return nil
}

type storeData struct {
	data string
}

var _ WritableDynamicBytesSource = (*storeData)(nil)

// Generate implements DynamicBytesSource.
func (d *storeData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString(d.data)
	return nil
}

// Generate implements WritableDynamicBytesSource.
func (d *storeData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}

	d.data = string(buf[:n])
	return 0, nil
}

// testFD is a read-only FileDescriptionImpl representing a regular file.
type testFD struct {
	fileDescription
	DynamicBytesFileDescriptionImpl

	data DynamicBytesSource
}

func newTestFD(ctx context.Context, vfsObj *VirtualFilesystem, statusFlags uint32, data DynamicBytesSource) *FileDescription {
	vd := vfsObj.NewAnonVirtualDentry("genCountFD")
	defer vd.DecRef(ctx)
	var fd testFD
	fd.vfsfd.Init(&fd, statusFlags, vd.Mount(), vd.Dentry(), &FileDescriptionOptions{})
	fd.DynamicBytesFileDescriptionImpl.SetDataSource(data)
	return &fd.vfsfd
}

// Release implements FileDescriptionImpl.Release.
func (fd *testFD) Release(context.Context) {
}

// SetStatusFlags implements FileDescriptionImpl.SetStatusFlags.
// Stat implements FileDescriptionImpl.Stat.
func (fd *testFD) Stat(ctx context.Context, opts StatOptions) (linux.Statx, error) {
	// Note that Statx.Mask == 0 in the return value.
	return linux.Statx{}, nil
}

// SetStat implements FileDescriptionImpl.SetStat.
func (fd *testFD) SetStat(ctx context.Context, opts SetStatOptions) error {
	return syserror.EPERM
}

func TestGenCountFD(t *testing.T) {
	ctx := contexttest.Context(t)

	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	fd := newTestFD(ctx, vfsObj, linux.O_RDWR, &genCount{})
	defer fd.DecRef(ctx)

	// The first read causes Generate to be called to fill the FD's buffer.
	buf := make([]byte, 2)
	ioseq := usermem.BytesIOSequence(buf)
	n, err := fd.Read(ctx, ioseq, ReadOptions{})
	if n != 1 || (err != nil && err != io.EOF) {
		t.Fatalf("first Read: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if want := byte('1'); buf[0] != want {
		t.Errorf("first Read: got byte %c, wanted %c", buf[0], want)
	}

	// A second read without seeking is still at EOF.
	n, err = fd.Read(ctx, ioseq, ReadOptions{})
	if n != 0 || err != io.EOF {
		t.Fatalf("second Read: got (%d, %v), wanted (0, EOF)", n, err)
	}

	// Seeking to the beginning of the file causes it to be regenerated.
	n, err = fd.Seek(ctx, 0, linux.SEEK_SET)
	if n != 0 || err != nil {
		t.Fatalf("Seek: got (%d, %v), wanted (0, nil)", n, err)
	}
	n, err = fd.Read(ctx, ioseq, ReadOptions{})
	if n != 1 || (err != nil && err != io.EOF) {
		t.Fatalf("Read after Seek: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if want := byte('2'); buf[0] != want {
		t.Errorf("Read after Seek: got byte %c, wanted %c", buf[0], want)
	}

	// PRead at the beginning of the file also causes it to be regenerated.
	n, err = fd.PRead(ctx, ioseq, 0, ReadOptions{})
	if n != 1 || (err != nil && err != io.EOF) {
		t.Fatalf("PRead: got (%d, %v), wanted (1, nil or EOF)", n, err)
	}
	if want := byte('3'); buf[0] != want {
		t.Errorf("PRead: got byte %c, wanted %c", buf[0], want)
	}

	// Write and PWrite fails.
	if _, err := fd.Write(ctx, ioseq, WriteOptions{}); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("Write: got err %v, wanted %v", err, syserror.EIO)
	}
	if _, err := fd.PWrite(ctx, ioseq, 0, WriteOptions{}); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("Write: got err %v, wanted %v", err, syserror.EIO)
	}
}

func TestWritable(t *testing.T) {
	ctx := contexttest.Context(t)

	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	fd := newTestFD(ctx, vfsObj, linux.O_RDWR, &storeData{data: "init"})
	defer fd.DecRef(ctx)

	buf := make([]byte, 10)
	ioseq := usermem.BytesIOSequence(buf)
	if n, err := fd.Read(ctx, ioseq, ReadOptions{}); n != 4 && err != io.EOF {
		t.Fatalf("Read: got (%v, %v), wanted (4, EOF)", n, err)
	}
	if want := "init"; want == string(buf) {
		t.Fatalf("Read: got %v, wanted %v", string(buf), want)
	}

	// Test PWrite.
	want := "write"
	writeIOSeq := usermem.BytesIOSequence([]byte(want))
	if n, err := fd.PWrite(ctx, writeIOSeq, 0, WriteOptions{}); int(n) != len(want) && err != nil {
		t.Errorf("PWrite: got err (%v, %v), wanted (%v, nil)", n, err, len(want))
	}
	if n, err := fd.PRead(ctx, ioseq, 0, ReadOptions{}); int(n) != len(want) && err != io.EOF {
		t.Fatalf("PRead: got (%v, %v), wanted (%v, EOF)", n, err, len(want))
	}
	if want == string(buf) {
		t.Fatalf("PRead: got %v, wanted %v", string(buf), want)
	}

	// Test Seek to 0 followed by Write.
	want = "write2"
	writeIOSeq = usermem.BytesIOSequence([]byte(want))
	if n, err := fd.Seek(ctx, 0, linux.SEEK_SET); n != 0 && err != nil {
		t.Errorf("Seek: got err (%v, %v), wanted (0, nil)", n, err)
	}
	if n, err := fd.Write(ctx, writeIOSeq, WriteOptions{}); int(n) != len(want) && err != nil {
		t.Errorf("Write: got err (%v, %v), wanted (%v, nil)", n, err, len(want))
	}
	if n, err := fd.PRead(ctx, ioseq, 0, ReadOptions{}); int(n) != len(want) && err != io.EOF {
		t.Fatalf("PRead: got (%v, %v), wanted (%v, EOF)", n, err, len(want))
	}
	if want == string(buf) {
		t.Fatalf("PRead: got %v, wanted %v", string(buf), want)
	}

	// Test failure if offset != 0.
	if n, err := fd.Seek(ctx, 1, linux.SEEK_SET); n != 0 && err != nil {
		t.Errorf("Seek: got err (%v, %v), wanted (0, nil)", n, err)
	}
	if n, err := fd.Write(ctx, writeIOSeq, WriteOptions{}); n != 0 && !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("Write: got err (%v, %v), wanted (0, EINVAL)", n, err)
	}
	if n, err := fd.PWrite(ctx, writeIOSeq, 2, WriteOptions{}); n != 0 && !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("PWrite: got err (%v, %v), wanted (0, EINVAL)", n, err)
	}
}
