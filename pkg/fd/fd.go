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

// Package fd provides types for working with file descriptors.
package fd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
)

// ReadWriter implements io.ReadWriter, io.ReaderAt, and io.WriterAt for fd. It
// does not take ownership of fd.
type ReadWriter struct {
	// fd is accessed atomically so FD.Close/Release can swap it.
	fd int64
}

var _ io.ReadWriter = (*ReadWriter)(nil)
var _ io.ReaderAt = (*ReadWriter)(nil)
var _ io.WriterAt = (*ReadWriter)(nil)

// NewReadWriter creates a ReadWriter for fd.
func NewReadWriter(fd int) *ReadWriter {
	return &ReadWriter{int64(fd)}
}

func fixCount(n int, err error) (int, error) {
	if n < 0 {
		n = 0
	}
	return n, err
}

// Read implements io.Reader.
func (r *ReadWriter) Read(b []byte) (int, error) {
	c, err := fixCount(syscall.Read(int(atomic.LoadInt64(&r.fd)), b))
	if c == 0 && len(b) > 0 && err == nil {
		return 0, io.EOF
	}
	return c, err
}

// ReadAt implements io.ReaderAt.
//
// ReadAt always returns a non-nil error when c < len(b).
func (r *ReadWriter) ReadAt(b []byte, off int64) (c int, err error) {
	for len(b) > 0 {
		var m int
		m, err = fixCount(syscall.Pread(int(atomic.LoadInt64(&r.fd)), b, off))
		if m == 0 && err == nil {
			return c, io.EOF
		}
		if err != nil {
			return c, err
		}
		c += m
		b = b[m:]
		off += int64(m)
	}
	return
}

// Write implements io.Writer.
func (r *ReadWriter) Write(b []byte) (int, error) {
	var err error
	var n, remaining int
	for remaining = len(b); remaining > 0; {
		woff := len(b) - remaining
		n, err = syscall.Write(int(atomic.LoadInt64(&r.fd)), b[woff:])

		if n > 0 {
			// syscall.Write wrote some bytes. This is the common case.
			remaining -= n
		} else {
			if err == nil {
				// syscall.Write did not write anything nor did it return an error.
				//
				// There is no way to guarantee that a subsequent syscall.Write will
				// make forward progress so just panic.
				panic(fmt.Sprintf("syscall.Write returned %d with no error", n))
			}

			if err != syscall.EINTR {
				// If the write failed for anything other than a signal, bail out.
				break
			}
		}
	}

	return len(b) - remaining, err
}

// WriteAt implements io.WriterAt.
func (r *ReadWriter) WriteAt(b []byte, off int64) (c int, err error) {
	for len(b) > 0 {
		var m int
		m, err = fixCount(syscall.Pwrite(int(atomic.LoadInt64(&r.fd)), b, off))
		if err != nil {
			break
		}
		c += m
		b = b[m:]
		off += int64(m)
	}
	return
}

// FD owns a host file descriptor.
//
// It is similar to os.File, with a few important distinctions:
//
// FD provies a Release() method which relinquishes ownership. Like os.File,
// FD adds a finalizer to close the backing FD. However, the finalizer cannot
// be removed from os.File, forever pinning the lifetime of an FD to its
// os.File.
//
// FD supports both blocking and non-blocking operation. os.File only
// supports blocking operation.
type FD struct {
	ReadWriter
}

// New creates a new FD.
//
// New takes ownership of fd.
func New(fd int) *FD {
	if fd < 0 {
		return &FD{ReadWriter{-1}}
	}
	f := &FD{ReadWriter{int64(fd)}}
	runtime.SetFinalizer(f, (*FD).Close)
	return f
}

// NewFromFile creates a new FD from an os.File.
//
// NewFromFile does not transfer ownership of the file descriptor (it will be
// duplicated, so both the os.File and FD will eventually need to be closed
// and some (but not all) changes made to the FD will be applied to the
// os.File as well).
//
// The returned FD is always blocking (Go 1.9+).
func NewFromFile(file *os.File) (*FD, error) {
	fd, err := syscall.Dup(int(file.Fd()))
	// Technically, the runtime may call the finalizer on file as soon as
	// Fd() returns.
	runtime.KeepAlive(file)
	if err != nil {
		return &FD{ReadWriter{-1}}, err
	}
	return New(fd), nil
}

// Open is equivallent to open(2).
func Open(path string, openmode int, perm uint32) (*FD, error) {
	f, err := syscall.Open(path, openmode|syscall.O_LARGEFILE, perm)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

// OpenAt is equivallent to openat(2).
func OpenAt(dir *FD, path string, flags int, mode uint32) (*FD, error) {
	f, err := syscall.Openat(dir.FD(), path, flags, mode)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

// Close closes the file descriptor contained in the FD.
//
// Close is safe to call multiple times, but will return an error after the
// first call.
//
// Concurrently calling Close and any other method is undefined.
func (f *FD) Close() error {
	runtime.SetFinalizer(f, nil)
	return syscall.Close(int(atomic.SwapInt64(&f.fd, -1)))
}

// Release relinquishes ownership of the contained file descriptor.
//
// Concurrently calling Release and any other method is undefined.
func (f *FD) Release() int {
	runtime.SetFinalizer(f, nil)
	return int(atomic.SwapInt64(&f.fd, -1))
}

// FD returns the file descriptor owned by FD. FD retains ownership.
func (f *FD) FD() int {
	return int(atomic.LoadInt64(&f.fd))
}

// File converts the FD to an os.File.
//
// FD does not transfer ownership of the file descriptor (it will be
// duplicated, so both the FD and os.File will eventually need to be closed
// and some (but not all) changes made to the os.File will be applied to the
// FD as well).
//
// This operation is somewhat expensive, so care should be taken to minimize
// its use.
func (f *FD) File() (*os.File, error) {
	fd, err := syscall.Dup(int(atomic.LoadInt64(&f.fd)))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), ""), nil
}

// ReleaseToFile returns an os.File that takes ownership of the FD.
//
// name is passed to os.NewFile.
func (f *FD) ReleaseToFile(name string) *os.File {
	return os.NewFile(uintptr(f.Release()), name)
}
