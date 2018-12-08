// Copyright 2018 Google LLC
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

package fsutil

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Handle implements FileOperations.
//
// FIXME: Remove Handle entirely in favor of individual fs.File
// implementations using simple generic utilities.
//
// +stateify savable
type Handle struct {
	NoopRelease      `state:"nosave"`
	NoIoctl          `state:"nosave"`
	NoSplice         `state:"nosave"`
	HandleOperations fs.HandleOperations

	// dirCursor is the directory cursor.
	dirCursor string
}

// NewHandle returns a File backed by the Dirent and FileFlags.
func NewHandle(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags, hops fs.HandleOperations) *fs.File {
	if !fs.IsPipe(dirent.Inode.StableAttr) && !fs.IsSocket(dirent.Inode.StableAttr) {
		// Allow reading/writing at an arbitrary offset for non-pipes
		// and non-sockets.
		flags.Pread = true
		flags.Pwrite = true
	}

	return fs.NewFile(ctx, dirent, flags, &Handle{HandleOperations: hops})
}

// Readiness implements waiter.Waitable.Readiness.
func (h *Handle) Readiness(mask waiter.EventMask) waiter.EventMask {
	return h.HandleOperations.Readiness(mask)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (h *Handle) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	h.HandleOperations.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (h *Handle) EventUnregister(e *waiter.Entry) {
	h.HandleOperations.EventUnregister(e)
}

// Readdir implements FileOperations.Readdir.
func (h *Handle) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	root := fs.RootFromContext(ctx)
	defer root.DecRef()
	dirCtx := &fs.DirCtx{
		Serializer: serializer,
		DirCursor:  &h.dirCursor,
	}
	n, err := fs.DirentReaddir(ctx, file.Dirent, h, root, dirCtx, file.Offset())
	return n, err
}

// Seek implements FileOperations.Seek.
func (h *Handle) Seek(ctx context.Context, file *fs.File, whence fs.SeekWhence, offset int64) (int64, error) {
	return SeekWithDirCursor(ctx, file, whence, offset, &h.dirCursor)
}

// IterateDir implements DirIterator.IterateDir.
func (h *Handle) IterateDir(ctx context.Context, dirCtx *fs.DirCtx, offset int) (int, error) {
	return h.HandleOperations.DeprecatedReaddir(ctx, dirCtx, offset)
}

// Read implements FileOperations.Read.
func (h *Handle) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	return h.HandleOperations.DeprecatedPreadv(ctx, dst, offset)
}

// Write implements FileOperations.Write.
func (h *Handle) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	return h.HandleOperations.DeprecatedPwritev(ctx, src, offset)
}

// Fsync implements FileOperations.Fsync.
func (h *Handle) Fsync(ctx context.Context, file *fs.File, start int64, end int64, syncType fs.SyncType) error {
	switch syncType {
	case fs.SyncAll, fs.SyncData:
		// Write out metadata.
		if err := file.Dirent.Inode.WriteOut(ctx); err != nil {
			return err
		}
		fallthrough
	case fs.SyncBackingStorage:
		// Use DeprecatedFsync to sync disks.
		return h.HandleOperations.DeprecatedFsync()
	}
	panic("invalid sync type")
}

// Flush implements FileOperations.Flush.
func (h *Handle) Flush(context.Context, *fs.File) error {
	return h.HandleOperations.DeprecatedFlush()
}

// ConfigureMMap implements FileOperations.ConfigureMMap.
func (h *Handle) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	mappable := file.Dirent.Inode.Mappable()
	if mappable == nil {
		return syserror.ENODEV
	}
	return GenericConfigureMMap(file, mappable, opts)
}
