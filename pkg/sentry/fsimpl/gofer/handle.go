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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
)

// handle represents a remote "open file descriptor", consisting of an opened
// fid (p9.File) and optionally a host file descriptor.
//
// These are explicitly not savable.
type handle struct {
	file p9file
	fd   int32 // -1 if unavailable
}

// Preconditions: read || write.
func openHandle(ctx context.Context, file p9file, read, write, trunc bool) (handle, error) {
	_, newfile, err := file.walk(ctx, nil)
	if err != nil {
		return handle{fd: -1}, err
	}
	var flags p9.OpenFlags
	switch {
	case read && !write:
		flags = p9.ReadOnly
	case !read && write:
		flags = p9.WriteOnly
	case read && write:
		flags = p9.ReadWrite
	}
	if trunc {
		flags |= p9.OpenTruncate
	}
	fdobj, _, _, err := newfile.open(ctx, flags)
	if err != nil {
		newfile.close(ctx)
		return handle{fd: -1}, err
	}
	fd := int32(-1)
	if fdobj != nil {
		fd = int32(fdobj.Release())
	}
	return handle{
		file: newfile,
		fd:   fd,
	}, nil
}

func (h *handle) isOpen() bool {
	return !h.file.isNil()
}

func (h *handle) close(ctx context.Context) {
	h.file.close(ctx)
	h.file = p9file{}
	if h.fd >= 0 {
		unix.Close(int(h.fd))
		h.fd = -1
	}
}

func (h *handle) readToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}
	if h.fd >= 0 {
		ctx.UninterruptibleSleepStart(false)
		n, err := hostfd.Preadv2(h.fd, dsts, int64(offset), 0 /* flags */)
		ctx.UninterruptibleSleepFinish(false)
		return n, err
	}
	if dsts.NumBlocks() == 1 && !dsts.Head().NeedSafecopy() {
		n, err := h.file.readAt(ctx, dsts.Head().ToSlice(), offset)
		return uint64(n), err
	}
	// Buffer the read since p9.File.ReadAt() takes []byte.
	buf := make([]byte, dsts.NumBytes())
	n, err := h.file.readAt(ctx, buf, offset)
	if n == 0 {
		return 0, err
	}
	if cp, cperr := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:n]))); cperr != nil {
		return cp, cperr
	}
	return uint64(n), err
}

func (h *handle) writeFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}
	if h.fd >= 0 {
		ctx.UninterruptibleSleepStart(false)
		n, err := hostfd.Pwritev2(h.fd, srcs, int64(offset), 0 /* flags */)
		ctx.UninterruptibleSleepFinish(false)
		return n, err
	}
	if srcs.NumBlocks() == 1 && !srcs.Head().NeedSafecopy() {
		n, err := h.file.writeAt(ctx, srcs.Head().ToSlice(), offset)
		return uint64(n), err
	}
	// Buffer the write since p9.File.WriteAt() takes []byte.
	buf := make([]byte, srcs.NumBytes())
	cp, cperr := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), srcs)
	if cp == 0 {
		return 0, cperr
	}
	n, err := h.file.writeAt(ctx, buf[:cp], offset)
	if err != nil {
		return uint64(n), err
	}
	return cp, cperr
}
