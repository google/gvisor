// Copyright 2020 The gVisor Authors.
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

package memdev

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	randomDevMinor  = 8
	urandomDevMinor = 9
)

// randomDevice implements vfs.Device for /dev/random and /dev/urandom.
//
// +stateify savable
type randomDevice struct{}

// Open implements vfs.Device.Open.
func (randomDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &randomFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// randomFD implements vfs.FileDescriptionImpl for /dev/random.
//
// +stateify savable
type randomFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	vfs.SpliceInFD

	// off is the "file offset". off is accessed using atomic memory
	// operations.
	off int64
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *randomFD) Release(context.Context) {
	// noop
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *randomFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return dst.CopyOutFrom(ctx, safemem.FromIOReader{rand.Reader})
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *randomFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	n, err := dst.CopyOutFrom(ctx, safemem.FromIOReader{rand.Reader})
	atomic.AddInt64(&fd.off, n)
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *randomFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	// In Linux, this mixes the written bytes into the entropy pool; we just
	// throw them away.
	return src.NumBytes(), nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *randomFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	atomic.AddInt64(&fd.off, src.NumBytes())
	return src.NumBytes(), nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *randomFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Linux: drivers/char/random.c:random_fops.llseek == urandom_fops.llseek
	// == noop_llseek
	return atomic.LoadInt64(&fd.off), nil
}
