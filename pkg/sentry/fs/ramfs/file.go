// Copyright 2018 Google Inc.
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

package ramfs

import (
	"io"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/secio"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// File represents a unique file.  It uses a simple byte slice as storage, and
// thus should only be used for small files.
//
// A File is not mappable.
type File struct {
	Entry

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// data tracks backing data for the file.
	data []byte
}

// InitFile initializes a file.
func (f *File) InitFile(ctx context.Context, owner fs.FileOwner, perms fs.FilePermissions) {
	f.InitEntry(ctx, owner, perms)
}

// UnstableAttr returns unstable attributes of this ramfs file.
func (f *File) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	uattr, _ := f.Entry.UnstableAttr(ctx, inode)
	uattr.Size = int64(len(f.data))
	uattr.Usage = f.usageLocked()

	return uattr, nil
}

// usageLocked returns the disk usage. Caller must hold f.mu.
func (f *File) usageLocked() int64 {
	return int64(len(f.data))
}

// Append appends the given data. This is for internal use.
func (f *File) Append(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = append(f.data, data...)
}

// Truncate truncates this node.
func (f *File) Truncate(ctx context.Context, inode *fs.Inode, l int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l < int64(len(f.data)) {
		// Remove excess bytes.
		f.data = f.data[:l]
		return nil
	} else if l > int64(len(f.data)) {
		// Create a new slice with size l, and copy f.data into it.
		d := make([]byte, l)
		copy(d, f.data)
		f.data = d
	}
	f.Entry.NotifyModification(ctx)
	return nil
}

// ReadAt implements io.ReaderAt.
func (f *File) ReadAt(data []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, ErrInvalidOp
	}
	if offset >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(data, f.data[offset:])
	// Did we read past the end?
	if offset+int64(len(data)) >= int64(len(f.data)) {
		return n, io.EOF
	}
	return n, nil
}

// DeprecatedPreadv reads into a collection of slices from a given offset.
func (f *File) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if offset >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, f.data[offset:])
	if n > 0 {
		f.Entry.NotifyAccess(ctx)
	}
	return int64(n), err
}

// WriteAt implements io.WriterAt.
func (f *File) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, ErrInvalidOp
	}
	newLen := offset + int64(len(data))
	if newLen < 0 {
		// Overflow.
		return 0, syserror.EINVAL
	}
	if newLen > int64(len(f.data)) {
		// Copy f.data into new slice with expanded length.
		d := make([]byte, newLen)
		copy(d, f.data)
		f.data = d
	}
	return copy(f.data[offset:], data), nil
}

// DeprecatedPwritev writes from a collection of slices at a given offset.
func (f *File) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := src.CopyInTo(ctx, safemem.FromIOWriter{secio.NewOffsetWriter(f, offset)})
	if n > 0 {
		f.Entry.NotifyModification(ctx)
	}
	return n, err
}
