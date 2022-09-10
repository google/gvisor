// Copyright 2022 The gVisor Authors.
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

// Package iouringfs provides a filesystem implementation for IO_URING basing
// it on anonfs.
package iouringfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// IoUring  implements io_uring struct. See io_uring/io_uring.c.
type IoUring struct {
	head uint32
	tail uint32
}

// IoUringCqe implements IO completion data structure (Completion Queue Entry)
// io_uring_cqe struct. See include/uapi/linux/io_uring.h.
type IoUringCqe struct {
	userData uint64
	res      int16
	flags    uint32
	bigCqe   *uint64
}

// FileDescription implements vfs.FileDescriptionImpl for file-based IO_URING.
// It is based on io_rings struct. See io_uring/io_uring.c.
//
// +stateify savable
type FileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

var _ vfs.FileDescriptionImpl = (*FileDescription)(nil)

// New creates a new iouring fd.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, entries uint32, params *linux.IoUringParams, paramsUser hostarch.Addr) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[io_uring]")
	defer vd.DecRef(ctx)

	iouringfd := &FileDescription{}

	// iouringfd is always set up with read/write mode.
	// See io_uring/io_uring.c:io_uring_install_fd().
	if err := iouringfd.vfsfd.Init(iouringfd, uint32(linux.O_RDWR), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
		DenySpliceIn:      true,
	}); err != nil {
		return nil, err
	}

	return &iouringfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (iouringfd *FileDescription) Release(context.Context) {
}
