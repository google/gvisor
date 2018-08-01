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

package dev

import (
	"io"
	"math"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// +stateify savable
type nullDevice struct {
	ramfs.Entry
}

func newNullDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *nullDevice {
	n := &nullDevice{}
	n.InitEntry(ctx, owner, fs.FilePermsFromMode(mode))
	return n
}

// DeprecatedPreadv reads data from the device.
func (n *nullDevice) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	return 0, io.EOF
}

// DeprecatedPwritev discards writes.
func (n *nullDevice) DeprecatedPwritev(_ context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	return src.NumBytes(), nil
}

// Truncate should be simply ignored for character devices on linux.
func (n *nullDevice) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// +stateify savable
type zeroDevice struct {
	nullDevice
}

func newZeroDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *zeroDevice {
	zd := &zeroDevice{}
	zd.InitEntry(ctx, owner, fs.FilePermsFromMode(mode))
	return zd
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (zd *zeroDevice) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	return dst.ZeroOut(ctx, math.MaxInt64)
}

// GetFile overrides ramfs.Entry.GetFile and returns a zeroFile instead.
func (zd *zeroDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	// Allow pread(2) and pwrite(2) on this file.
	flags.Pread = true
	flags.Pwrite = true

	return fs.NewFile(ctx, dirent, flags, &zeroFileOperations{
		FileOperations: &fsutil.Handle{HandleOperations: dirent.Inode.HandleOps()},
	}), nil
}

// +stateify savable
type zeroFileOperations struct {
	fs.FileOperations
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (*zeroFileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	m, err := mm.NewSharedAnonMappable(opts.Length, platform.FromContext(ctx))
	if err != nil {
		return err
	}
	opts.MappingIdentity = m
	opts.Mappable = m
	return nil
}
