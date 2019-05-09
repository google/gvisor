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

package dev

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/pgalloc"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// +stateify savable
type nullDevice struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopAllocate         `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
}

var _ fs.InodeOperations = (*nullDevice)(nil)

func newNullDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *nullDevice {
	n := &nullDevice{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
	}
	return n
}

// GetFile implements fs.FileOperations.GetFile.
func (n *nullDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	flags.Pwrite = true

	return fs.NewFile(ctx, dirent, flags, &nullFileOperations{}), nil
}

// +stateify savable
type nullFileOperations struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRead             `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoopWrite            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`
}

var _ fs.FileOperations = (*nullFileOperations)(nil)

// +stateify savable
type zeroDevice struct {
	nullDevice
}

var _ fs.InodeOperations = (*zeroDevice)(nil)

func newZeroDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *zeroDevice {
	zd := &zeroDevice{
		nullDevice: nullDevice{
			InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
		},
	}
	return zd
}

// GetFile implements fs.FileOperations.GetFile.
func (zd *zeroDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	flags.Pwrite = true

	return fs.NewFile(ctx, dirent, flags, &zeroFileOperations{}), nil
}

// +stateify savable
type zeroFileOperations struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoopWrite            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	readZeros                       `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`
}

var _ fs.FileOperations = (*zeroFileOperations)(nil)

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (*zeroFileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	m, err := mm.NewSharedAnonMappable(opts.Length, pgalloc.MemoryFileProviderFromContext(ctx))
	if err != nil {
		return err
	}
	opts.MappingIdentity = m
	opts.Mappable = m
	return nil
}
