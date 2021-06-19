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
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
)

// handle represents a remote "open file descriptor", consisting of an opened
// fid (p9.File) and optionally a host file descriptor.
//
// If lisafs is being used, fileLisa points to an open file on the server.
//
// These are explicitly not savable.
type handle struct {
	fs       *filesystem // This is only used when lisafs is enabled.
	fileLisa lisafs.FDID
	file     p9file
	fd       int32 // -1 if unavailable
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

// Preconditions: read || write.
func (fs *filesystem) openHandleLisa(ctx context.Context, fd lisafs.FDID, read, write, trunc bool) (handle, error) {
	var flags uint32
	switch {
	case read && write:
		flags = unix.O_RDWR
	case read:
		flags = unix.O_RDONLY
	case write:
		flags = unix.O_WRONLY
	default:
		panic("tried to open unreadable and unwritable handle")
	}
	if trunc {
		flags |= unix.O_TRUNC
	}
	openFD, hostFD, err := fs.openAtLisa(ctx, fd, flags)
	if err != nil {
		return handle{fd: -1}, err
	}
	return handle{
		fs:       fs,
		fileLisa: openFD,
		fd:       int32(hostFD),
	}, nil
}

func (h *handle) isOpen() bool {
	if h.fs != nil && h.fs.opts.lisaEnabled {
		return h.fileLisa.Ok()
	}
	return !h.file.isNil()
}

func (h *handle) close(ctx context.Context) {
	if h.fs != nil && h.fs.opts.lisaEnabled {
		h.fs.closeFDLisa(ctx, h.fileLisa)
		h.fileLisa = lisafs.InvalidFDID
	} else {
		h.file.close(ctx)
		h.file = p9file{}
	}
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
		if h.fs != nil && h.fs.opts.lisaEnabled {
			return h.fs.readLisa(ctx, h.fileLisa, dsts.Head().ToSlice(), offset)
		}
		return h.file.readAt(ctx, dsts.Head().ToSlice(), offset)
	}
	// Buffer the read since p9.File.ReadAt() takes []byte.
	buf := make([]byte, dsts.NumBytes())
	var n uint64
	var err error
	if h.fs != nil && h.fs.opts.lisaEnabled {
		n, err = h.fs.readLisa(ctx, h.fileLisa, buf, offset)
	} else {
		n, err = h.file.readAt(ctx, buf, offset)
	}
	if n == 0 {
		return 0, err
	}
	if cp, cperr := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:n]))); cperr != nil {
		return cp, cperr
	}
	return n, err
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
		if h.fs != nil && h.fs.opts.lisaEnabled {
			return h.fs.writeLisa(ctx, h.fileLisa, srcs.Head().ToSlice(), offset)
		}
		return h.file.writeAt(ctx, srcs.Head().ToSlice(), offset)
	}
	// Buffer the write since p9.File.WriteAt() takes []byte.
	buf := make([]byte, srcs.NumBytes())
	cp, cperr := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf)), srcs)
	if cp == 0 {
		return 0, cperr
	}
	var n uint64
	var err error
	if h.fs != nil && h.fs.opts.lisaEnabled {
		n, err = h.fs.writeLisa(ctx, h.fileLisa, buf[:cp], offset)
	} else {
		n, err = h.file.writeAt(ctx, buf[:cp], offset)
	}
	// err takes precedence over cperr.
	if err != nil {
		return n, err
	}
	return n, cperr
}
