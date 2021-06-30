// Copyright 2018 The gVisor Authors.
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

package linux

import (
	"bytes"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// LINT.IfChange

// Getdents implements linux syscall getdents(2) for 64bit systems.
func Getdents(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := int(args[2].Uint())

	minSize := int(smallestDirent(t.Arch()))
	if size < minSize {
		// size is smaller than smallest possible dirent.
		return 0, nil, linuxerr.EINVAL
	}

	n, err := getdents(t, fd, addr, size, (*dirent).Serialize)
	return n, nil, err
}

// Getdents64 implements linux syscall getdents64(2).
func Getdents64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := int(args[2].Uint())

	minSize := int(smallestDirent64(t.Arch()))
	if size < minSize {
		// size is smaller than smallest possible dirent.
		return 0, nil, linuxerr.EINVAL
	}

	n, err := getdents(t, fd, addr, size, (*dirent).Serialize64)
	return n, nil, err
}

// getdents implements the core of getdents(2)/getdents64(2).
// f is the syscall implementation dirent serialization function.
func getdents(t *kernel.Task, fd int32, addr hostarch.Addr, size int, f func(*dirent, io.Writer) (int, error)) (uintptr, error) {
	dir := t.GetFile(fd)
	if dir == nil {
		return 0, linuxerr.EBADF
	}
	defer dir.DecRef(t)

	w := &usermem.IOReadWriter{
		Ctx:  t,
		IO:   t.MemoryManager(),
		Addr: addr,
		Opts: usermem.IOOpts{
			AddressSpaceActive: true,
		},
	}

	ds := newDirentSerializer(f, w, t.Arch(), size)
	rerr := dir.Readdir(t, ds)

	switch err := handleIOError(t, ds.Written() > 0, rerr, syserror.ERESTARTSYS, "getdents", dir); err {
	case nil:
		dir.Dirent.InotifyEvent(linux.IN_ACCESS, 0)
		return uintptr(ds.Written()), nil
	case io.EOF:
		return 0, nil
	default:
		return 0, err
	}
}

// oldDirentHdr is a fixed sized header matching the fixed size fields found in
// the old linux dirent struct.
//
// +marshal
type oldDirentHdr struct {
	Ino    uint64
	Off    uint64
	Reclen uint16 `marshal:"unaligned"` // Struct ends mid-word.
}

// direntHdr is a fixed sized header matching the fixed size fields found in the
// new linux dirent struct.
//
// +marshal
type direntHdr struct {
	OldHdr oldDirentHdr
	Typ    uint8 `marshal:"unaligned"` // Struct ends mid-word.
}

// dirent contains the data pointed to by a new linux dirent struct.
type dirent struct {
	Hdr  direntHdr
	Name []byte
}

// newDirent returns a dirent from an fs.InodeOperationsInfo.
func newDirent(width uint, name string, attr fs.DentAttr, offset uint64) *dirent {
	d := &dirent{
		Hdr: direntHdr{
			OldHdr: oldDirentHdr{
				Ino: attr.InodeID,
				Off: offset,
			},
			Typ: fs.ToDirentType(attr.Type),
		},
		Name: []byte(name),
	}
	d.Hdr.OldHdr.Reclen = d.padRec(int(width))
	return d
}

// smallestDirent returns the size of the smallest possible dirent using
// the old linux dirent format.
func smallestDirent(a arch.Context) uint {
	d := dirent{}
	return uint(d.Hdr.OldHdr.SizeBytes()) + a.Width() + 1
}

// smallestDirent64 returns the size of the smallest possible dirent using
// the new linux dirent format.
func smallestDirent64(a arch.Context) uint {
	d := dirent{}
	return uint(d.Hdr.SizeBytes()) + a.Width()
}

// padRec pads the name field until the rec length is a multiple of the width,
// which must be a power of 2. It returns the padded rec length.
func (d *dirent) padRec(width int) uint16 {
	a := d.Hdr.SizeBytes() + len(d.Name)
	r := (a + width) &^ (width - 1)
	padding := r - a
	d.Name = append(d.Name, make([]byte, padding)...)
	return uint16(r)
}

// Serialize64 serializes a Dirent struct to a byte slice, keeping the new
// linux dirent format. Returns the number of bytes serialized or an error.
func (d *dirent) Serialize64(w io.Writer) (int, error) {
	n1, err := d.Hdr.WriteTo(w)
	if err != nil {
		return 0, err
	}
	n2, err := w.Write(d.Name)
	if err != nil {
		return 0, err
	}
	return int(n1) + n2, nil
}

// Serialize serializes a Dirent struct to a byte slice, using the old linux
// dirent format.
// Returns the number of bytes serialized or an error.
func (d *dirent) Serialize(w io.Writer) (int, error) {
	n1, err := d.Hdr.OldHdr.WriteTo(w)
	if err != nil {
		return 0, err
	}
	n2, err := w.Write(d.Name)
	if err != nil {
		return 0, err
	}
	n3, err := w.Write([]byte{d.Hdr.Typ})
	if err != nil {
		return 0, err
	}
	return int(n1) + n2 + n3, nil
}

// direntSerializer implements fs.InodeOperationsInfoSerializer, serializing dirents to an
// io.Writer.
type direntSerializer struct {
	serialize func(*dirent, io.Writer) (int, error)
	w         io.Writer
	// width is the arch native value width.
	width uint
	// offset is the current dirent offset.
	offset uint64
	// written is the total bytes serialized.
	written int
	// size is the size of the buffer to serialize into.
	size int
}

func newDirentSerializer(f func(d *dirent, w io.Writer) (int, error), w io.Writer, ac arch.Context, size int) *direntSerializer {
	return &direntSerializer{
		serialize: f,
		w:         w,
		width:     ac.Width(),
		size:      size,
	}
}

// CopyOut implements fs.InodeOperationsInfoSerializer.CopyOut.
// It serializes and writes the fs.DentAttr to the direntSerializer io.Writer.
func (ds *direntSerializer) CopyOut(name string, attr fs.DentAttr) error {
	ds.offset++

	d := newDirent(ds.width, name, attr, ds.offset)

	// Serialize dirent into a temp buffer.
	var b bytes.Buffer
	n, err := ds.serialize(d, &b)
	if err != nil {
		ds.offset--
		return err
	}

	// Check that we have enough room remaining to write the dirent.
	if n > (ds.size - ds.written) {
		ds.offset--
		return io.EOF
	}

	// Write out the temp buffer.
	if _, err := b.WriteTo(ds.w); err != nil {
		ds.offset--
		return err
	}

	ds.written += n
	return nil
}

// Written returns the total number of bytes written.
func (ds *direntSerializer) Written() int {
	return ds.written
}

// LINT.ThenChange(vfs2/getdents.go)
