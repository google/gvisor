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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sync"
)

// handle represents a remote "open file descriptor", consisting of an opened
// fid (p9.File) and optionally a host file descriptor.
//
// If lisafs is being used, fdLisa points to an open file on the server.
//
// These are explicitly not savable.
type handle struct {
	fdLisa lisafs.ClientFD
	file   p9file
	fd     int32 // -1 if unavailable
}

// Preconditions: read || write.
func openHandle(ctx context.Context, file p9file, read, write, trunc bool) (handle, error) {
	_, newfile, err := file.walk(ctx, nil)
	if err != nil {
		return handle{fd: -1}, err
	}
	flags := p9.ReadOnly
	switch {
	case read && !write:
		flags = p9.ReadOnly
	case !read && write:
		flags = p9.WriteOnly
	case read && write:
		flags = p9.ReadWrite
	default:
		log.Debugf("openHandle called with read = write = false. Falling back to read only FD.")
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
func openHandleLisa(ctx context.Context, fdLisa lisafs.ClientFD, read, write, trunc bool) (handle, error) {
	flags := uint32(unix.O_RDONLY)
	switch {
	case read && write:
		flags = unix.O_RDWR
	case read:
		flags = unix.O_RDONLY
	case write:
		flags = unix.O_WRONLY
	default:
		log.Debugf("openHandleLisa called with read = write = false. Falling back to read only FD.")
	}
	if trunc {
		flags |= unix.O_TRUNC
	}
	openFD, hostFD, err := fdLisa.OpenAt(ctx, flags)
	if err != nil {
		return handle{fd: -1}, err
	}
	h := handle{
		fdLisa: fdLisa.Client().NewFD(openFD),
		fd:     int32(hostFD),
	}
	return h, nil
}

func (h *handle) isOpen() bool {
	if h.fdLisa.Client() != nil {
		return h.fdLisa.Ok()
	}
	return !h.file.isNil()
}

func (h *handle) close(ctx context.Context) {
	if h.fdLisa.Client() != nil {
		h.fdLisa.Close(ctx)
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
	log.Infof("FOO readToBlocksAt, fd: %d", h.fd)
	if dsts.IsEmpty() {
		log.Infof("FOO readToBlocksAt done (empty)! fd: %d", h.fd)
		return 0, nil
	}
	if h.fd >= 0 {
		ctx.UninterruptibleSleepStart(false)
		n, err := hostfd.Preadv2(h.fd, dsts, int64(offset), 0 /* flags */)
		ctx.UninterruptibleSleepFinish(false)
		log.Infof("FOO readToBlocksAt done (1)! fd: %d, read: %d, err: %v", h.fd, n, err)
		return n, err
	}
	if dsts.NumBlocks() == 1 && !dsts.Head().NeedSafecopy() {
		if h.fdLisa.Client() != nil {
			return h.fdLisa.Read(ctx, dsts.Head().ToSlice(), offset)
		}
		n, err := h.file.readAt(ctx, dsts.Head().ToSlice(), offset)
		log.Infof("FOO readToBlocksAt done (2)! fd: %d, read: %d, err: %v", h.fd, n, err)
		return n, err
	}
	// Buffer the read since p9.File.ReadAt() takes []byte.
	buf := make([]byte, dsts.NumBytes())
	var n uint64
	var err error
	if h.fdLisa.Client() != nil {
		n, err = h.fdLisa.Read(ctx, buf, offset)
	} else {
		n, err = h.file.readAt(ctx, buf, offset)
	}
	if n == 0 {
		log.Infof("FOO readToBlocksAt done (3)! fd: %d, read: %d, err: %v", h.fd, 0, err)
		return 0, err
	}
	if cp, cperr := safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:n]))); cperr != nil {
		log.Infof("FOO readToBlocksAt done (4)! fd: %d, read: %d, err: %v", h.fd, cp, err)
		return cp, cperr
	}
	log.Infof("FOO readToBlocksAt done (5)! fd: %d, read: %d, err: %v", h.fd, n, err)
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
		if h.fdLisa.Client() != nil {
			return h.fdLisa.Write(ctx, srcs.Head().ToSlice(), offset)
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
	if h.fdLisa.Client() != nil {
		n, err = h.fdLisa.Write(ctx, buf[:cp], offset)
	} else {
		n, err = h.file.writeAt(ctx, buf[:cp], offset)
	}
	// err takes precedence over cperr.
	if err != nil {
		return n, err
	}
	return n, cperr
}

type handleReadWriter struct {
	ctx context.Context
	h   *handle
	off uint64
}

var handleReadWriterPool = sync.Pool{
	New: func() interface{} {
		return &handleReadWriter{}
	},
}

func getHandleReadWriter(ctx context.Context, h *handle, offset int64) *handleReadWriter {
	rw := handleReadWriterPool.Get().(*handleReadWriter)
	rw.ctx = ctx
	rw.h = h
	rw.off = uint64(offset)
	return rw
}

func putHandleReadWriter(rw *handleReadWriter) {
	rw.ctx = nil
	rw.h = nil
	handleReadWriterPool.Put(rw)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *handleReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	n, err := rw.h.readToBlocksAt(rw.ctx, dsts, rw.off)
	rw.off += n
	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *handleReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	n, err := rw.h.writeFromBlocksAt(rw.ctx, srcs, rw.off)
	rw.off += n
	return n, err
}
