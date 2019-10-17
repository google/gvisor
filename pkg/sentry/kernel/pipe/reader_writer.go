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

package pipe

import (
	"io"

	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// ReaderWriter satisfies the FileOperations interface and services both
// read and write requests. This should only be used directly for named pipes.
// pipe(2) and pipe2(2) only support unidirectional pipes and should use
// either pipe.Reader or pipe.Writer.
//
// +stateify savable
type ReaderWriter struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	*Pipe
}

// Read implements fs.FileOperations.Read.
func (rw *ReaderWriter) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	return rw.Pipe.Read(ctx, dst)
}

// WriteTo implements fs.FileOperations.WriteTo.
func (rw *ReaderWriter) WriteTo(ctx context.Context, _ *fs.File, w io.Writer, count int64, dup bool) (int64, error) {
	return rw.Pipe.WriteTo(ctx, w, count, dup)
}

// Write implements fs.FileOperations.Write.
func (rw *ReaderWriter) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	return rw.Pipe.Write(ctx, src)
}

// ReadFrom implements fs.FileOperations.WriteTo.
func (rw *ReaderWriter) ReadFrom(ctx context.Context, _ *fs.File, r io.Reader, count int64) (int64, error) {
	return rw.Pipe.ReadFrom(ctx, r, count)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (rw *ReaderWriter) Ioctl(ctx context.Context, _ *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return rw.Pipe.Ioctl(ctx, io, args)
}
